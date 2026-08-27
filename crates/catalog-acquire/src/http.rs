#![cfg_attr(test, allow(dead_code))]

use std::{
    collections::{BTreeSet, HashSet},
    ffi::{CStr, CString},
    fmt, fs,
    io::{self, Read, Seek, SeekFrom},
    num::NonZeroU64,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::Path,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    time::Duration,
};

use base64::Engine as _;
use reqwest::{Client, StatusCode, Url, header, redirect::Policy};
use sha2::{Digest, Sha256, Sha512};
use tokio::{
    io::AsyncWriteExt,
    sync::Notify,
    task::spawn_blocking,
    time::{Instant, sleep_until},
};

const WHOLE_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REDIRECTS: usize = 5;
const MAX_QUERY_BYTES: usize = 8 * 1024;
const MAX_URL_BYTES: usize = 16 * 1024;
const STREAM_BUFFER_BYTES: usize = 64 * 1024;
const GITHUB_HOST: &str = "github.com";
const GITHUB_ASSET_HOST: &str = "release-assets.githubusercontent.com";

#[cfg(test)]
use std::path::PathBuf;

/// A query-free HTTPS URL admitted by `catalog-core`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HttpsUrl(String);

impl HttpsUrl {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&catalog_core::HttpsArtifactUrl> for HttpsUrl {
    fn from(value: &catalog_core::HttpsArtifactUrl) -> Self {
        Self(value.as_str().to_owned())
    }
}

/// An exact HTTPS origin admitted by `catalog-core`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HttpsOrigin(String);

impl HttpsOrigin {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&catalog_core::AllowedOrigin> for HttpsOrigin {
    fn from(value: &catalog_core::AllowedOrigin) -> Self {
        Self(value.as_str().to_owned())
    }
}

/// A lowercase SHA-256 value admitted by `catalog-core`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sha256Hex(String);

impl Sha256Hex {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&catalog_core::Sha256Digest> for Sha256Hex {
    fn from(value: &catalog_core::Sha256Digest) -> Self {
        Self(value.as_str().to_owned())
    }
}

impl From<&catalog_core::Sha256Hex> for Sha256Hex {
    fn from(value: &catalog_core::Sha256Hex) -> Self {
        Self(value.as_str().to_owned())
    }
}

/// Canonical npm SHA-512 SRI admitted by `catalog-core`.
#[derive(Clone, PartialEq, Eq)]
pub struct NpmSri(String);

impl NpmSri {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&catalog_core::RegistryIntegrity> for NpmSri {
    fn from(value: &catalog_core::RegistryIntegrity) -> Self {
        Self(value.as_str().to_owned())
    }
}

/// Exact content and transport authority for one public object.
#[derive(Clone)]
pub struct FetchRequest {
    pub url: HttpsUrl,
    pub allowed_origins: BTreeSet<HttpsOrigin>,
    pub expected_size: Option<u64>,
    pub maximum_size: NonZeroU64,
    pub sha256: Sha256Hex,
    pub sri: Option<NpmSri>,
}

impl FetchRequest {
    /// Builds a request only from values already admitted by `catalog-core`.
    #[must_use]
    pub fn from_catalog_values(
        url: &catalog_core::HttpsArtifactUrl,
        allowed_origins: &[catalog_core::AllowedOrigin],
        expected_size: Option<u64>,
        maximum_size: NonZeroU64,
        sha256: &catalog_core::Sha256Digest,
        sri: Option<&catalog_core::RegistryIntegrity>,
    ) -> Self {
        Self {
            url: url.into(),
            allowed_origins: allowed_origins.iter().map(HttpsOrigin::from).collect(),
            expected_size,
            maximum_size,
            sha256: sha256.into(),
            sri: sri.map(NpmSri::from),
        }
    }

    /// Builds the bounded public-object request used by the fixed CLI mode.
    pub fn for_public_object(url: &str, size: u64, sha256: &str) -> Result<Self, AcquireError> {
        if size == 0 || size > 8 * 1024 * 1024 * 1024 || !is_lower_sha256(sha256) {
            return Err(AcquireError::InvalidPolicy);
        }
        let parsed = Url::parse(url).map_err(|_| AcquireError::InvalidPolicy)?;
        validate_common_url(&parsed, TransportMode::Production, true)?;
        if parsed.query().is_some() {
            return Err(AcquireError::InvalidPolicy);
        }
        let origin = parsed.origin().ascii_serialization();
        Ok(Self {
            url: HttpsUrl(url.to_owned()),
            allowed_origins: BTreeSet::from([HttpsOrigin(origin)]),
            expected_size: Some(size),
            maximum_size: NonZeroU64::new(size).ok_or(AcquireError::InvalidPolicy)?,
            sha256: Sha256Hex(sha256.to_owned()),
            sri: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        url: &str,
        allowed_origins: &[String],
        expected_size: Option<u64>,
        maximum_size: NonZeroU64,
        sha256: &str,
        sri: Option<&str>,
    ) -> Result<Self, AcquireError> {
        if !is_lower_sha256(sha256)
            || sri.is_some_and(|value| !is_canonical_test_sri(value))
            || allowed_origins.is_empty()
        {
            return Err(AcquireError::InvalidPolicy);
        }
        Ok(Self {
            url: HttpsUrl(url.to_owned()),
            allowed_origins: allowed_origins.iter().cloned().map(HttpsOrigin).collect(),
            expected_size,
            maximum_size,
            sha256: Sha256Hex(sha256.to_owned()),
            sri: sri.map(|value| NpmSri(value.to_owned())),
        })
    }
}

/// Closed redirect behavior. Neither profile accepts a query on its initial URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectProfile {
    Default,
    GitHubReleaseAsset,
}

/// Cooperative cancellation shared by every acquisition phase.
#[derive(Clone, Default)]
pub struct AcquisitionCancellation {
    inner: Arc<CancellationInner>,
}

#[derive(Default)]
struct CancellationInner {
    cancelled: AtomicBool,
    notify: Notify,
}

impl AcquisitionCancellation {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        if !self.inner.cancelled.swap(true, Ordering::AcqRel) {
            self.inner.notify.notify_waiters();
        }
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire)
    }

    pub(crate) async fn cancelled(&self) {
        loop {
            let notified = self.inner.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

/// Stable, non-echoing acquisition failure categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquireError {
    InvalidPolicy,
    RedirectDenied,
    TooManyRedirects,
    UnexpectedStatus,
    Transport,
    Timeout,
    Cancelled,
    SizeLimitExceeded,
    SizeMismatch,
    DigestMismatch,
    SriMismatch,
    TemporaryFile,
    CacheInvalid,
    Publication,
    Archive,
    Graph,
    Bundle,
    Input,
}

impl fmt::Display for AcquireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPolicy => "invalid acquisition policy",
            Self::RedirectDenied => "redirect denied",
            Self::TooManyRedirects => "too many redirects",
            Self::UnexpectedStatus => "unexpected response status",
            Self::Transport => "acquisition transport failed",
            Self::Timeout => "acquisition timed out",
            Self::Cancelled => "acquisition cancelled",
            Self::SizeLimitExceeded => "acquisition size limit exceeded",
            Self::SizeMismatch => "acquisition size mismatch",
            Self::DigestMismatch => "acquisition digest mismatch",
            Self::SriMismatch => "acquisition integrity mismatch",
            Self::TemporaryFile => "acquisition temporary file rejected",
            Self::CacheInvalid => "acquisition cache object rejected",
            Self::Publication => "acquisition publication failed",
            Self::Archive => "acquisition archive rejected",
            Self::Graph => "acquisition graph rejected",
            Self::Bundle => "acquisition bundle rejected",
            Self::Input => "acquisition input rejected",
        })
    }
}

impl std::error::Error for AcquireError {}

/// Non-cloneable authority over one fully rehashed digest-addressed cache winner.
pub struct FetchedObject {
    file: fs::File,
    size: u64,
    sha256: Sha256Hex,
}

impl fmt::Debug for FetchedObject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FetchedObject")
            .field("size", &self.size)
            .field("sha256", &self.sha256)
            .finish_non_exhaustive()
    }
}

impl FetchedObject {
    /// Borrows the verified descriptor without reopening a pathname.
    #[must_use]
    pub fn file(&self) -> &fs::File {
        &self.file
    }

    /// Transfers the verified descriptor for bounded streaming by the next phase.
    #[must_use]
    pub fn into_file(self) -> fs::File {
        self.file
    }

    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    #[must_use]
    pub fn sha256(&self) -> &Sha256Hex {
        &self.sha256
    }
}

/// Reqwest/Rustls transport with no redirect, proxy, cookie, or caller-header authority.
#[derive(Clone)]
pub struct CredentialFreeFetcher {
    inner: Arc<FetcherInner>,
}

struct FetcherInner {
    client: Client,
    cache: CacheRoot,
    profile: RedirectProfile,
    timeout: Duration,
    mode: TransportMode,
    #[cfg(test)]
    hook: Option<TestHook>,
    #[cfg(test)]
    blocking_hook: Option<BlockingTestHook>,
}

#[derive(Clone, Copy)]
enum TransportMode {
    Production,
    #[cfg(test)]
    Loopback(std::net::SocketAddr),
}

impl CredentialFreeFetcher {
    /// Creates the default, query-denying production fetcher.
    pub fn new(cache_root: impl AsRef<Path>) -> Result<Self, AcquireError> {
        Self::production(cache_root.as_ref(), RedirectProfile::Default)
    }

    /// Creates the closed GitHub release-asset production fetcher.
    pub fn for_github_release_assets(cache_root: impl AsRef<Path>) -> Result<Self, AcquireError> {
        Self::production(cache_root.as_ref(), RedirectProfile::GitHubReleaseAsset)
    }

    fn production(cache_root: &Path, profile: RedirectProfile) -> Result<Self, AcquireError> {
        let client = credential_free_client(true, WHOLE_REQUEST_TIMEOUT, None)?;
        Ok(Self {
            inner: Arc::new(FetcherInner {
                client,
                cache: CacheRoot::open(cache_root)?,
                profile,
                timeout: WHOLE_REQUEST_TIMEOUT,
                mode: TransportMode::Production,
                #[cfg(test)]
                hook: None,
                #[cfg(test)]
                blocking_hook: None,
            }),
        })
    }

    pub async fn fetch_exact(
        &self,
        request: FetchRequest,
        cancellation: &AcquisitionCancellation,
    ) -> Result<FetchedObject, AcquireError> {
        if cancellation.is_cancelled() {
            return Err(AcquireError::Cancelled);
        }
        let deadline = Instant::now() + self.inner.timeout;
        self.inner.fetch(request, cancellation, deadline).await
    }

    #[cfg(test)]
    pub(crate) fn for_loopback_test(
        cache_root: impl AsRef<Path>,
        profile: RedirectProfile,
        address: std::net::SocketAddr,
        timeout: Duration,
    ) -> Result<Self, AcquireError> {
        if !address.ip().is_loopback() || address.port() == 0 || timeout.is_zero() {
            return Err(AcquireError::InvalidPolicy);
        }
        let client = credential_free_client(false, timeout, Some(address))?;
        Ok(Self {
            inner: Arc::new(FetcherInner {
                client,
                cache: CacheRoot::open(cache_root.as_ref())?,
                profile,
                timeout,
                mode: TransportMode::Loopback(address),
                hook: None,
                blocking_hook: None,
            }),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_test_hook(&self, hook: TestHook) -> Self {
        Self {
            inner: Arc::new(FetcherInner {
                client: self.inner.client.clone(),
                cache: self.inner.cache.clone(),
                profile: self.inner.profile,
                timeout: self.inner.timeout,
                mode: self.inner.mode,
                hook: Some(hook),
                blocking_hook: self.inner.blocking_hook.clone(),
            }),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_blocking_test_hook(&self, hook: BlockingTestHook) -> Self {
        Self {
            inner: Arc::new(FetcherInner {
                client: self.inner.client.clone(),
                cache: self.inner.cache.clone(),
                profile: self.inner.profile,
                timeout: self.inner.timeout,
                mode: self.inner.mode,
                hook: self.inner.hook.clone(),
                blocking_hook: Some(hook),
            }),
        }
    }

    #[cfg(test)]
    pub(crate) fn cache_path_for_test(&self, request: &FetchRequest) -> PathBuf {
        self.inner.cache.object_path(&request.sha256)
    }
}

fn credential_free_client(
    https_only: bool,
    timeout: Duration,
    #[cfg_attr(not(test), allow(unused_variables))] loopback: Option<std::net::SocketAddr>,
) -> Result<Client, AcquireError> {
    let mut builder = Client::builder()
        .redirect(Policy::none())
        .referer(false)
        .no_proxy()
        .timeout(timeout)
        .use_rustls_tls();
    if https_only {
        builder = builder.https_only(true);
    }
    #[cfg(test)]
    if let Some(address) = loopback {
        builder = builder
            .resolve(GITHUB_HOST, address)
            .resolve(GITHUB_ASSET_HOST, address);
    }
    builder.build().map_err(|_| AcquireError::Transport)
}

impl FetcherInner {
    async fn fetch(
        &self,
        request: FetchRequest,
        cancellation: &AcquisitionCancellation,
        deadline: Instant,
    ) -> Result<FetchedObject, AcquireError> {
        validate_request(&request, self.profile, self.mode)?;
        check_ready(cancellation, deadline)?;
        if let Some(verified) = self
            .cache
            .open_verified(
                &request,
                cancellation,
                deadline,
                AcquireError::CacheInvalid,
                self.blocking_hook(BlockingTestHookPoint::CacheReopen),
            )
            .await?
        {
            return Ok(fetched_object(verified, request.sha256));
        }

        let mut current =
            Url::parse(request.url.as_str()).map_err(|_| AcquireError::InvalidPolicy)?;
        let mut visited = HashSet::from([current.as_str().to_owned()]);
        let mut redirects = 0_usize;
        loop {
            check_ready(cancellation, deadline)?;
            validate_hop(&current, self.profile, self.mode)?;
            let response = await_phase(
                cancellation,
                deadline,
                self.client.get(current.clone()).send(),
            )
            .await?
            .map_err(|_| AcquireError::Transport)?;
            if response.status().is_redirection() {
                validate_redirect_source(&current, self.profile)?;
                if redirects == MAX_REDIRECTS {
                    return Err(AcquireError::TooManyRedirects);
                }
                let location = single_location(response.headers())?;
                let next = redirect_target(&current, location)?;
                validate_redirect_target(&next, &request.allowed_origins, self.profile, self.mode)?;
                if !visited.insert(next.as_str().to_owned()) {
                    return Err(AcquireError::RedirectDenied);
                }
                redirects += 1;
                current = next;
                continue;
            }
            if response.status() != StatusCode::OK {
                return Err(AcquireError::UnexpectedStatus);
            }
            return self
                .receive_and_publish(response, request, cancellation, deadline)
                .await;
        }
    }

    async fn receive_and_publish(
        &self,
        mut response: reqwest::Response,
        request: FetchRequest,
        cancellation: &AcquisitionCancellation,
        deadline: Instant,
    ) -> Result<FetchedObject, AcquireError> {
        validate_content_length(response.headers(), &request)?;
        #[cfg(test)]
        self.pause_at(TestHookPoint::BeforeTemporaryCreate, cancellation, deadline)
            .await?;
        let temporary = self
            .cache
            .create_temporary(
                cancellation,
                deadline,
                self.blocking_hook(BlockingTestHookPoint::TemporaryCreate),
            )
            .await?;
        let mut output = tokio::fs::File::from_std(temporary);
        #[cfg(test)]
        self.pause_at(TestHookPoint::TemporaryCreated, cancellation, deadline)
            .await?;

        let mut size = 0_u64;
        let mut sha256 = Sha256::new();
        let mut sha512 = Sha512::new();
        loop {
            let chunk = await_phase(cancellation, deadline, response.chunk())
                .await?
                .map_err(|_| AcquireError::Transport)?;
            let Some(chunk) = chunk else { break };
            let chunk_size =
                u64::try_from(chunk.len()).map_err(|_| AcquireError::SizeLimitExceeded)?;
            size = size
                .checked_add(chunk_size)
                .ok_or(AcquireError::SizeLimitExceeded)?;
            if size > request.maximum_size.get() {
                return Err(AcquireError::SizeLimitExceeded);
            }
            if request
                .expected_size
                .is_some_and(|expected| size > expected)
            {
                return Err(AcquireError::SizeMismatch);
            }
            await_phase(cancellation, deadline, output.write_all(&chunk))
                .await?
                .map_err(|_| AcquireError::TemporaryFile)?;
            sha256.update(&chunk);
            sha512.update(&chunk);
            #[cfg(test)]
            self.pause_at(TestHookPoint::BodyChunkWritten, cancellation, deadline)
                .await?;
        }
        if request
            .expected_size
            .is_some_and(|expected| size != expected)
        {
            return Err(AcquireError::SizeMismatch);
        }
        require_digests(
            &request,
            sha256.finalize().as_slice(),
            sha512.finalize().as_slice(),
        )?;
        await_phase(cancellation, deadline, output.flush())
            .await?
            .map_err(|_| AcquireError::TemporaryFile)?;
        let temporary = await_phase(cancellation, deadline, output.into_std()).await?;
        let temporary = self
            .cache
            .settle_temporary(
                temporary,
                &request,
                cancellation,
                deadline,
                self.blocking_hook(BlockingTestHookPoint::TemporarySettlement),
            )
            .await?;

        #[cfg(test)]
        self.pause_at(TestHookPoint::BeforePublication, cancellation, deadline)
            .await?;
        let verified = self
            .cache
            .publish(
                temporary,
                &request,
                cancellation,
                deadline,
                self.publication_blocking_hook(),
            )
            .await?;
        Ok(fetched_object(verified, request.sha256))
    }

    fn blocking_hook(&self, point: BlockingTestHookPoint) -> Option<BlockingTestHook> {
        #[cfg(test)]
        let hook = self
            .blocking_hook
            .as_ref()
            .filter(|hook| hook.point() == point)
            .cloned();
        #[cfg(not(test))]
        let hook = {
            let _ = point;
            None
        };
        hook
    }

    fn publication_blocking_hook(&self) -> Option<BlockingTestHook> {
        #[cfg(test)]
        let hook = self
            .blocking_hook
            .as_ref()
            .filter(|hook| {
                matches!(
                    hook.point(),
                    BlockingTestHookPoint::Publication
                        | BlockingTestHookPoint::PublicationAfterLink
                )
            })
            .cloned();
        #[cfg(not(test))]
        let hook = None;
        hook
    }

    #[cfg(test)]
    async fn pause_at(
        &self,
        point: TestHookPoint,
        cancellation: &AcquisitionCancellation,
        deadline: Instant,
    ) -> Result<(), AcquireError> {
        if let Some(hook) = &self.hook
            && hook.point() == point
        {
            await_phase(cancellation, deadline, hook.pause()).await?;
        }
        Ok(())
    }
}

struct SettledBlocking<T> {
    value: T,
    interruption: Option<AcquireError>,
}

async fn run_blocking_settled<T, F>(
    cancellation: &AcquisitionCancellation,
    deadline: Instant,
    operation: F,
) -> Result<SettledBlocking<T>, AcquireError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    check_ready(cancellation, deadline)?;
    let mut task = spawn_blocking(operation);
    let mut interruption = None;
    let value = tokio::select! {
        biased;
        () = cancellation.cancelled() => {
            interruption = Some(AcquireError::Cancelled);
            task.await.map_err(|_| AcquireError::Transport)?
        }
        () = sleep_until(deadline) => {
            interruption = Some(AcquireError::Timeout);
            task.await.map_err(|_| AcquireError::Transport)?
        }
        result = &mut task => result.map_err(|_| AcquireError::Transport)?,
    };
    if interruption.is_none() {
        interruption = current_interruption(cancellation, deadline);
    }
    Ok(SettledBlocking {
        value,
        interruption,
    })
}

fn current_interruption(
    cancellation: &AcquisitionCancellation,
    deadline: Instant,
) -> Option<AcquireError> {
    if cancellation.is_cancelled() {
        Some(AcquireError::Cancelled)
    } else if Instant::now() >= deadline {
        Some(AcquireError::Timeout)
    } else {
        None
    }
}

fn check_blocking_ready(
    cancellation: &AcquisitionCancellation,
    deadline: Instant,
) -> Result<(), AcquireError> {
    current_interruption(cancellation, deadline).map_or(Ok(()), Err)
}

fn fetched_object(verified: VerifiedOpen, sha256: Sha256Hex) -> FetchedObject {
    FetchedObject {
        file: verified.file,
        size: verified.size,
        sha256,
    }
}

struct VerifiedOpen {
    file: fs::File,
    size: u64,
}

struct PublishOutcome {
    verified: VerifiedOpen,
}

struct PublishBlockingRequest<'a> {
    name: &'a CStr,
    request: &'a FetchRequest,
    cancellation: &'a AcquisitionCancellation,
    deadline: Instant,
    control: &'a PublicationControl,
    hook: Option<&'a BlockingTestHook>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    size: u64,
    mode: u32,
    links: u64,
    uid: u32,
}

const PUBLICATION_UNDECIDED: u8 = 0;
const PUBLICATION_COMMIT: u8 = 1;
const PUBLICATION_ABORT: u8 = 2;

#[derive(Clone)]
struct PublicationControl {
    inner: Arc<PublicationControlInner>,
}

struct PublicationControlInner {
    tentative: AtomicBool,
    tentative_notify: Notify,
    decision: AtomicU8,
    decision_lock: Mutex<()>,
    decision_notify: Condvar,
}

impl PublicationControl {
    fn new() -> Self {
        Self {
            inner: Arc::new(PublicationControlInner {
                tentative: AtomicBool::new(false),
                tentative_notify: Notify::new(),
                decision: AtomicU8::new(PUBLICATION_UNDECIDED),
                decision_lock: Mutex::new(()),
                decision_notify: Condvar::new(),
            }),
        }
    }

    fn mark_tentative(&self) {
        self.inner.tentative.store(true, Ordering::Release);
        self.inner.tentative_notify.notify_waiters();
    }

    async fn tentative(&self) {
        loop {
            let notified = self.inner.tentative_notify.notified();
            if self.inner.tentative.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }

    fn decide(&self, decision: u8) {
        let _lock = self.inner.decision_lock.lock().expect("publication lock");
        if self
            .inner
            .decision
            .compare_exchange(
                PUBLICATION_UNDECIDED,
                decision,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            self.inner.decision_notify.notify_all();
        }
    }

    fn is_aborted(&self) -> bool {
        self.inner.decision.load(Ordering::Acquire) == PUBLICATION_ABORT
    }

    fn wait_for_decision(&self) -> bool {
        self.wait_for_decision_with_hook(None)
    }

    fn wait_for_decision_with_hook(&self, hook: Option<&BlockingTestHook>) -> bool {
        let mut lock = self.inner.decision_lock.lock().expect("publication lock");
        loop {
            match self.inner.decision.load(Ordering::Acquire) {
                PUBLICATION_COMMIT => return true,
                PUBLICATION_ABORT => return false,
                _ => {
                    if let Some(hook) = hook {
                        hook.block();
                    }
                    lock = self
                        .inner
                        .decision_notify
                        .wait(lock)
                        .expect("publication wait");
                }
            }
        }
    }
}

struct PublicationDecisionGuard {
    control: PublicationControl,
    active: bool,
}

impl PublicationDecisionGuard {
    fn new(control: PublicationControl) -> Self {
        Self {
            control,
            active: true,
        }
    }

    fn abort(&mut self) {
        self.control.decide(PUBLICATION_ABORT);
        self.active = false;
    }

    fn commit(&mut self) {
        self.control.decide(PUBLICATION_COMMIT);
        self.active = false;
    }

    fn disarm_without_decision(&mut self) {
        self.active = false;
    }
}

impl Drop for PublicationDecisionGuard {
    fn drop(&mut self) {
        if self.active {
            self.control.decide(PUBLICATION_ABORT);
        }
    }
}

impl FileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            mode: metadata.mode(),
            links: metadata.nlink(),
            uid: metadata.uid(),
        }
    }

    fn is_regular_owner_file(self, mode: u32, links: u64) -> bool {
        self.mode & libc::S_IFMT == libc::S_IFREG
            && self.uid == current_euid()
            && self.mode & 0o777 == mode
            && self.links == links
    }
}

struct VerifyOpenRequest<'a> {
    cache: &'a CacheRoot,
    object_name: Option<&'a CStr>,
    request: &'a FetchRequest,
    cancellation: &'a AcquisitionCancellation,
    deadline: Instant,
    category: AcquireError,
    expected_links: u64,
}

fn verify_open_file(
    mut file: fs::File,
    verification: VerifyOpenRequest<'_>,
) -> Result<(VerifiedOpen, FileIdentity), AcquireError> {
    let VerifyOpenRequest {
        cache,
        object_name,
        request,
        cancellation,
        deadline,
        category,
        expected_links,
    } = verification;
    check_blocking_ready(cancellation, deadline)?;
    let before = FileIdentity::from_metadata(&file.metadata().map_err(|_| category)?);
    if !before.is_regular_owner_file(0o400, expected_links)
        || before.size > request.maximum_size.get()
        || request
            .expected_size
            .is_some_and(|expected| before.size != expected)
    {
        return Err(category);
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| category)?;
    let mut sha256 = Sha256::new();
    let mut sha512 = Sha512::new();
    let mut buffer = [0_u8; STREAM_BUFFER_BYTES];
    let mut size = 0_u64;
    loop {
        check_blocking_ready(cancellation, deadline)?;
        let read = file.read(&mut buffer).map_err(|_| category)?;
        if read == 0 {
            break;
        }
        size = size.checked_add(read as u64).ok_or(category)?;
        if size > request.maximum_size.get()
            || request
                .expected_size
                .is_some_and(|expected| size > expected)
        {
            return Err(category);
        }
        sha256.update(&buffer[..read]);
        sha512.update(&buffer[..read]);
    }
    if size != before.size
        || request
            .expected_size
            .is_some_and(|expected| size != expected)
        || !digests_match(
            request,
            sha256.finalize().as_slice(),
            sha512.finalize().as_slice(),
        )
    {
        return Err(category);
    }
    let after = FileIdentity::from_metadata(&file.metadata().map_err(|_| category)?);
    if before != after || !after.is_regular_owner_file(0o400, expected_links) {
        return Err(category);
    }
    if let Some(name) = object_name {
        let named = cache.statat(name).map_err(|_| category)?.ok_or(category)?;
        if named != after {
            return Err(category);
        }
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| category)?;
    check_blocking_ready(cancellation, deadline)?;
    Ok((VerifiedOpen { file, size }, after))
}

async fn await_phase<T, F>(
    cancellation: &AcquisitionCancellation,
    deadline: Instant,
    future: F,
) -> Result<T, AcquireError>
where
    F: std::future::Future<Output = T>,
{
    check_ready(cancellation, deadline)?;
    tokio::pin!(future);
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(AcquireError::Cancelled),
        () = sleep_until(deadline) => Err(AcquireError::Timeout),
        value = &mut future => Ok(value),
    }
}

fn check_ready(
    cancellation: &AcquisitionCancellation,
    deadline: Instant,
) -> Result<(), AcquireError> {
    if cancellation.is_cancelled() {
        Err(AcquireError::Cancelled)
    } else if Instant::now() >= deadline {
        Err(AcquireError::Timeout)
    } else {
        Ok(())
    }
}

fn validate_request(
    request: &FetchRequest,
    profile: RedirectProfile,
    mode: TransportMode,
) -> Result<(), AcquireError> {
    if request.allowed_origins.is_empty()
        || request
            .expected_size
            .is_some_and(|size| size > request.maximum_size.get())
        || !is_lower_sha256(request.sha256.as_str())
        || request
            .sri
            .as_ref()
            .is_some_and(|sri| !is_canonical_sri_shape(sri.as_str()))
    {
        return Err(AcquireError::InvalidPolicy);
    }
    let url = Url::parse(request.url.as_str()).map_err(|_| AcquireError::InvalidPolicy)?;
    validate_common_url(&url, mode, true)?;
    if url.query().is_some() {
        return Err(AcquireError::InvalidPolicy);
    }
    require_allowed_origin(&url, &request.allowed_origins)
        .map_err(|_| AcquireError::InvalidPolicy)?;
    if profile == RedirectProfile::GitHubReleaseAsset && !is_exact_github_hop(&url, mode) {
        return Err(AcquireError::InvalidPolicy);
    }
    Ok(())
}

fn validate_hop(
    url: &Url,
    profile: RedirectProfile,
    mode: TransportMode,
) -> Result<(), AcquireError> {
    validate_common_url(url, mode, false).map_err(|_| AcquireError::RedirectDenied)?;
    match profile {
        RedirectProfile::Default => {
            if url.query().is_some() {
                return Err(AcquireError::RedirectDenied);
            }
        }
        RedirectProfile::GitHubReleaseAsset => {
            if is_exact_github_hop(url, mode) {
                if url.query().is_some() {
                    return Err(AcquireError::RedirectDenied);
                }
            } else if !is_exact_release_asset_hop(url, mode) {
                return Err(AcquireError::RedirectDenied);
            }
        }
    }
    Ok(())
}

fn validate_redirect_source(url: &Url, profile: RedirectProfile) -> Result<(), AcquireError> {
    if profile == RedirectProfile::GitHubReleaseAsset && url.host_str() == Some(GITHUB_ASSET_HOST) {
        return Err(AcquireError::RedirectDenied);
    }
    Ok(())
}

fn validate_redirect_target(
    url: &Url,
    allowed_origins: &BTreeSet<HttpsOrigin>,
    profile: RedirectProfile,
    mode: TransportMode,
) -> Result<(), AcquireError> {
    validate_hop(url, profile, mode)?;
    require_allowed_origin(url, allowed_origins).map_err(|_| AcquireError::RedirectDenied)
}

fn validate_common_url(url: &Url, mode: TransportMode, initial: bool) -> Result<(), AcquireError> {
    if url.as_str().len() > MAX_URL_BYTES
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.as_str().contains('\\')
    {
        return Err(if initial {
            AcquireError::InvalidPolicy
        } else {
            AcquireError::RedirectDenied
        });
    }
    match mode {
        TransportMode::Production if url.scheme() != "https" => {
            return Err(if initial {
                AcquireError::InvalidPolicy
            } else {
                AcquireError::RedirectDenied
            });
        }
        #[cfg(test)]
        TransportMode::Loopback(address) => {
            if url.scheme() != "http" {
                return Err(if initial {
                    AcquireError::InvalidPolicy
                } else {
                    AcquireError::RedirectDenied
                });
            }
            let host = url.host_str().ok_or(AcquireError::InvalidPolicy)?;
            let logical = matches!(host, GITHUB_HOST | GITHUB_ASSET_HOST);
            if (!logical && host.parse::<std::net::IpAddr>().ok() != Some(address.ip()))
                || url.port_or_known_default() != Some(address.port())
            {
                return Err(if initial {
                    AcquireError::InvalidPolicy
                } else {
                    AcquireError::RedirectDenied
                });
            }
        }
        _ => {}
    }
    Ok(())
}

fn is_exact_github_hop(url: &Url, mode: TransportMode) -> bool {
    if url.host_str() != Some(GITHUB_HOST) || url.query().is_some() || url.fragment().is_some() {
        return false;
    }
    if matches!(mode, TransportMode::Production) && url.port().is_some() {
        return false;
    }
    let segments = url
        .path()
        .strip_prefix('/')
        .unwrap_or(url.path())
        .split('/')
        .collect::<Vec<_>>();
    if segments.len() != 6
        || segments
            .iter()
            .any(|segment| segment.is_empty() || matches!(*segment, "." | ".."))
        || segments[2] != "releases"
    {
        return false;
    }
    (segments[3] == "latest" && segments[4] == "download") || segments[3] == "download"
}

fn is_exact_release_asset_hop(url: &Url, mode: TransportMode) -> bool {
    if url.host_str() != Some(GITHUB_ASSET_HOST)
        || url.fragment().is_some()
        || url.path().is_empty()
        || url.path() == "/"
        || (matches!(mode, TransportMode::Production) && url.port().is_some())
    {
        return false;
    }
    url.query()
        .is_some_and(|query| !query.is_empty() && query.len() <= MAX_QUERY_BYTES)
}

fn require_allowed_origin(
    url: &Url,
    allowed_origins: &BTreeSet<HttpsOrigin>,
) -> Result<(), AcquireError> {
    let origin = url.origin().ascii_serialization();
    allowed_origins
        .iter()
        .any(|allowed| allowed.as_str() == origin)
        .then_some(())
        .ok_or(AcquireError::RedirectDenied)
}

fn single_location(headers: &header::HeaderMap) -> Result<&str, AcquireError> {
    let mut values = headers.get_all(header::LOCATION).iter();
    let value = values.next().ok_or(AcquireError::RedirectDenied)?;
    if values.next().is_some() {
        return Err(AcquireError::RedirectDenied);
    }
    let value = value.to_str().map_err(|_| AcquireError::RedirectDenied)?;
    if value.is_empty()
        || value.len() > MAX_URL_BYTES
        || value.contains('\\')
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(AcquireError::RedirectDenied);
    }
    Ok(value)
}

fn redirect_target(current: &Url, location: &str) -> Result<Url, AcquireError> {
    current
        .join(location)
        .map_err(|_| AcquireError::RedirectDenied)
}

fn validate_content_length(
    headers: &header::HeaderMap,
    request: &FetchRequest,
) -> Result<(), AcquireError> {
    let mut values = headers.get_all(header::CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return Ok(());
    };
    if values.next().is_some() {
        return Err(AcquireError::Transport);
    }
    let value = value
        .to_str()
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or(AcquireError::Transport)?;
    if value > request.maximum_size.get() {
        return Err(AcquireError::SizeLimitExceeded);
    }
    if request
        .expected_size
        .is_some_and(|expected| value != expected)
    {
        return Err(AcquireError::SizeMismatch);
    }
    Ok(())
}

fn require_digests(
    request: &FetchRequest,
    sha256: &[u8],
    sha512: &[u8],
) -> Result<(), AcquireError> {
    if encode_hex(sha256) != request.sha256.as_str() {
        return Err(AcquireError::DigestMismatch);
    }
    if request.sri.as_ref().is_some_and(|expected| {
        format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(sha512)
        ) != expected.as_str()
    }) {
        return Err(AcquireError::SriMismatch);
    }
    Ok(())
}

fn digests_match(request: &FetchRequest, sha256: &[u8], sha512: &[u8]) -> bool {
    encode_hex(sha256) == request.sha256.as_str()
        && request.sri.as_ref().is_none_or(|expected| {
            format!(
                "sha512-{}",
                base64::engine::general_purpose::STANDARD.encode(sha512)
            ) == expected.as_str()
        })
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn is_canonical_sri_shape(value: &str) -> bool {
    value.len() == 95
        && value.starts_with("sha512-")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
}

#[cfg(test)]
fn is_canonical_test_sri(value: &str) -> bool {
    if !is_canonical_sri_shape(value) {
        return false;
    }
    base64::engine::general_purpose::STANDARD
        .decode(&value[7..])
        .is_ok_and(|decoded| decoded.len() == 64)
}

#[derive(Clone)]
struct CacheRoot {
    directory: Arc<fs::File>,
    #[cfg(test)]
    path: PathBuf,
}

impl CacheRoot {
    fn open(path: &Path) -> Result<Self, AcquireError> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if secure_directory(&metadata) => {}
            Ok(_) => return Err(AcquireError::InvalidPolicy),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::DirBuilder::new()
                    .recursive(false)
                    .mode(0o700)
                    .create(path)
                    .map_err(|_| AcquireError::InvalidPolicy)?;
            }
            Err(_) => return Err(AcquireError::InvalidPolicy),
        }
        let mut options = fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let directory = options
            .open(path)
            .map_err(|_| AcquireError::InvalidPolicy)?;
        let metadata = directory
            .metadata()
            .map_err(|_| AcquireError::InvalidPolicy)?;
        if !secure_directory(&metadata) {
            return Err(AcquireError::InvalidPolicy);
        }
        Ok(Self {
            directory: Arc::new(directory),
            #[cfg(test)]
            path: path.to_owned(),
        })
    }

    async fn open_verified(
        &self,
        request: &FetchRequest,
        cancellation: &AcquisitionCancellation,
        deadline: Instant,
        category: AcquireError,
        hook: Option<BlockingTestHook>,
    ) -> Result<Option<VerifiedOpen>, AcquireError> {
        let cache = self.clone();
        let request = request.clone();
        let cancellation_owned = cancellation.clone();
        let name = object_name(&request.sha256)?;
        let settled = run_blocking_settled(cancellation, deadline, move || {
            if let Some(hook) = hook {
                hook.block();
            }
            check_blocking_ready(&cancellation_owned, deadline)?;
            let Some(file) = cache
                .open_named(&name, libc::O_RDONLY)
                .map_err(|_| category)?
            else {
                return Ok(None);
            };
            verify_open_file(
                file,
                VerifyOpenRequest {
                    cache: &cache,
                    object_name: Some(&name),
                    request: &request,
                    cancellation: &cancellation_owned,
                    deadline,
                    category,
                    expected_links: 1,
                },
            )
            .map(|(verified, _)| Some(verified))
        })
        .await?;
        if let Some(interruption) = settled.interruption {
            return Err(interruption);
        }
        settled.value
    }

    async fn create_temporary(
        &self,
        cancellation: &AcquisitionCancellation,
        deadline: Instant,
        hook: Option<BlockingTestHook>,
    ) -> Result<fs::File, AcquireError> {
        let cache = self.clone();
        let cancellation_owned = cancellation.clone();
        let settled = run_blocking_settled(cancellation, deadline, move || {
            if let Some(hook) = hook {
                hook.block();
            }
            check_blocking_ready(&cancellation_owned, deadline)?;
            let dot = c_string(".")?;
            let file = cache
                .open_named_required(&dot, libc::O_TMPFILE | libc::O_RDWR, 0o600)
                .map_err(|_| AcquireError::TemporaryFile)?;
            let identity = FileIdentity::from_metadata(
                &file.metadata().map_err(|_| AcquireError::TemporaryFile)?,
            );
            if !identity.is_regular_owner_file(0o600, 0) {
                return Err(AcquireError::TemporaryFile);
            }
            check_blocking_ready(&cancellation_owned, deadline)?;
            Ok(file)
        })
        .await?;
        if let Some(interruption) = settled.interruption {
            return Err(interruption);
        }
        settled.value
    }

    async fn settle_temporary(
        &self,
        file: fs::File,
        request: &FetchRequest,
        cancellation: &AcquisitionCancellation,
        deadline: Instant,
        hook: Option<BlockingTestHook>,
    ) -> Result<fs::File, AcquireError> {
        let cache = self.clone();
        let request = request.clone();
        let cancellation_owned = cancellation.clone();
        let settled = run_blocking_settled(cancellation, deadline, move || {
            if let Some(hook) = hook {
                hook.block();
            }
            check_blocking_ready(&cancellation_owned, deadline)?;
            file.sync_all().map_err(|_| AcquireError::TemporaryFile)?;
            file.set_permissions(fs::Permissions::from_mode(0o400))
                .map_err(|_| AcquireError::TemporaryFile)?;
            verify_open_file(
                file,
                VerifyOpenRequest {
                    cache: &cache,
                    object_name: None,
                    request: &request,
                    cancellation: &cancellation_owned,
                    deadline,
                    category: AcquireError::TemporaryFile,
                    expected_links: 0,
                },
            )
            .map(|(verified, _)| verified.file)
        })
        .await?;
        if let Some(interruption) = settled.interruption {
            return Err(interruption);
        }
        settled.value
    }

    async fn publish(
        &self,
        temporary: fs::File,
        request: &FetchRequest,
        cancellation: &AcquisitionCancellation,
        deadline: Instant,
        hook: Option<BlockingTestHook>,
    ) -> Result<VerifiedOpen, AcquireError> {
        check_ready(cancellation, deadline)?;
        let cache = self.clone();
        let request_owned = request.clone();
        let cancellation_owned = cancellation.clone();
        let name = object_name(&request.sha256)?;
        let control = PublicationControl::new();
        let mut guard = PublicationDecisionGuard::new(control.clone());
        let operation_control = control.clone();
        let mut task = spawn_blocking(move || {
            if hook
                .as_ref()
                .is_some_and(|hook| hook.point() == BlockingTestHookPoint::Publication)
            {
                hook.as_ref().expect("publication hook").block();
            }
            if operation_control.is_aborted() {
                return Err(AcquireError::Cancelled);
            }
            check_blocking_ready(&cancellation_owned, deadline)?;
            cache.publish_blocking(
                temporary,
                PublishBlockingRequest {
                    name: &name,
                    request: &request_owned,
                    cancellation: &cancellation_owned,
                    deadline,
                    control: &operation_control,
                    hook: hook.as_ref(),
                },
            )
        });

        tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                guard.abort();
                let _ = task.await.map_err(|_| AcquireError::Publication)?;
                Err(AcquireError::Cancelled)
            }
            () = sleep_until(deadline) => {
                guard.abort();
                let _ = task.await.map_err(|_| AcquireError::Publication)?;
                Err(AcquireError::Timeout)
            }
            () = control.tentative() => {
                if let Some(interruption) = current_interruption(cancellation, deadline) {
                    guard.abort();
                    let _ = task.await.map_err(|_| AcquireError::Publication)?;
                    return Err(interruption);
                }
                guard.commit();
                task.await
                    .map_err(|_| AcquireError::Publication)?
                    .map(|outcome| outcome.verified)
            }
            result = &mut task => {
                guard.disarm_without_decision();
                let outcome = result.map_err(|_| AcquireError::Publication)??;
                if let Some(interruption) = current_interruption(cancellation, deadline) {
                    return Err(interruption);
                }
                Ok(outcome.verified)
            }
        }
    }

    fn publish_blocking(
        &self,
        temporary: fs::File,
        publication: PublishBlockingRequest<'_>,
    ) -> Result<PublishOutcome, AcquireError> {
        let PublishBlockingRequest {
            name,
            request,
            cancellation,
            deadline,
            control,
            hook,
        } = publication;
        let before = FileIdentity::from_metadata(
            &temporary
                .metadata()
                .map_err(|_| AcquireError::TemporaryFile)?,
        );
        if !before.is_regular_owner_file(0o400, 0) {
            return Err(AcquireError::TemporaryFile);
        }
        match self.link_unnamed(&temporary, name) {
            Ok(()) => {
                let linked = FileIdentity::from_metadata(
                    &temporary
                        .metadata()
                        .map_err(|_| AcquireError::TemporaryFile)?,
                );
                if !linked.is_regular_owner_file(0o400, 1) {
                    let _ = self.unlink_if_matches(name, linked);
                    return Err(AcquireError::TemporaryFile);
                }
                if hook
                    .is_some_and(|hook| hook.point() == BlockingTestHookPoint::PublicationAfterLink)
                {
                    hook.expect("after-link hook").block();
                    if let Err(error) = check_blocking_ready(cancellation, deadline) {
                        let _ = self.unlink_if_matches(name, linked);
                        let _ = self.sync_directory();
                        return Err(error);
                    }
                }
                let result = (|| {
                    self.sync_directory()?;
                    check_blocking_ready(cancellation, deadline)?;
                    let file = self
                        .open_named(name, libc::O_RDONLY)
                        .map_err(|_| AcquireError::Publication)?
                        .ok_or(AcquireError::Publication)?;
                    let (verified, identity) = verify_open_file(
                        file,
                        VerifyOpenRequest {
                            cache: self,
                            object_name: Some(name),
                            request,
                            cancellation,
                            deadline,
                            category: AcquireError::Publication,
                            expected_links: 1,
                        },
                    )?;
                    if identity != linked {
                        return Err(AcquireError::Publication);
                    }
                    self.sync_directory()?;
                    check_blocking_ready(cancellation, deadline)?;
                    control.mark_tentative();
                    if !control.wait_for_decision() {
                        return Err(AcquireError::Cancelled);
                    }
                    Ok(PublishOutcome { verified })
                })();
                if result.is_err() {
                    let _ = self.unlink_if_matches(name, linked);
                    let _ = self.sync_directory();
                }
                result
            }
            Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {
                let file = self
                    .open_named(name, libc::O_RDONLY)
                    .map_err(|_| AcquireError::CacheInvalid)?
                    .ok_or(AcquireError::CacheInvalid)?;
                let (verified, _) = verify_open_file(
                    file,
                    VerifyOpenRequest {
                        cache: self,
                        object_name: Some(name),
                        request,
                        cancellation,
                        deadline,
                        category: AcquireError::CacheInvalid,
                        expected_links: 1,
                    },
                )?;
                Ok(PublishOutcome { verified })
            }
            Err(_) => Err(AcquireError::Publication),
        }
    }

    fn open_named(&self, name: &CStr, flags: i32) -> io::Result<Option<fs::File>> {
        match self.open_named_required(name, flags, 0) {
            Ok(file) => Ok(Some(file)),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn open_named_required(&self, name: &CStr, flags: i32, mode: u32) -> io::Result<fs::File> {
        // SAFETY: the retained descriptor is an opened directory, `name` is NUL-terminated,
        // and a successful returned descriptor is immediately given unique `File` ownership.
        let descriptor = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                mode as libc::mode_t,
            )
        };
        if descriptor < 0 {
            Err(io::Error::last_os_error())
        } else {
            // SAFETY: `openat` returned a fresh owned descriptor.
            Ok(unsafe { fs::File::from_raw_fd(descriptor) })
        }
    }

    fn link_unnamed(&self, file: &fs::File, name: &CStr) -> io::Result<()> {
        // SAFETY: both descriptors are live, both pointers are NUL-terminated, and
        // `AT_EMPTY_PATH` names the O_TMPFILE inode held by `file`.
        let result = unsafe {
            libc::linkat(
                file.as_raw_fd(),
                c"".as_ptr(),
                self.directory.as_raw_fd(),
                name.as_ptr(),
                libc::AT_EMPTY_PATH,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn statat(&self, name: &CStr) -> io::Result<Option<FileIdentity>> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `stat` points to writable storage, the directory descriptor is live,
        // and `name` is NUL-terminated. No symlink is followed.
        let result = unsafe {
            libc::fstatat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result == 0 {
            // SAFETY: successful `fstatat` initialized the structure.
            let stat = unsafe { stat.assume_init() };
            if stat.st_size < 0 {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            Ok(Some(FileIdentity {
                device: stat.st_dev,
                inode: stat.st_ino,
                size: stat.st_size as u64,
                mode: stat.st_mode,
                links: stat.st_nlink,
                uid: stat.st_uid,
            }))
        } else {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENOENT) {
                Ok(None)
            } else {
                Err(error)
            }
        }
    }

    fn unlink_if_matches(&self, name: &CStr, identity: FileIdentity) -> io::Result<()> {
        if self.statat(name)? != Some(identity) {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        // SAFETY: the retained directory descriptor and NUL-terminated relative name are valid.
        let result = unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn sync_directory(&self) -> Result<(), AcquireError> {
        // SAFETY: the retained descriptor is live for the duration of the call.
        let result = unsafe { libc::fsync(self.directory.as_raw_fd()) };
        if result == 0 {
            Ok(())
        } else {
            Err(AcquireError::Publication)
        }
    }

    #[cfg(test)]
    fn object_path(&self, digest: &Sha256Hex) -> PathBuf {
        self.path.join(digest.as_str())
    }
}

fn object_name(digest: &Sha256Hex) -> Result<CString, AcquireError> {
    c_string(digest.as_str()).map_err(|_| AcquireError::InvalidPolicy)
}

fn c_string(value: &str) -> Result<CString, AcquireError> {
    CString::new(value).map_err(|_| AcquireError::InvalidPolicy)
}

fn current_euid() -> u32 {
    // SAFETY: `geteuid` has no arguments, no side effects, and always returns the caller's uid.
    unsafe { libc::geteuid() }
}

fn secure_directory(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_dir()
        && metadata.uid() == current_euid()
        && metadata.mode() & 0o777 == 0o700
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockingTestHookPoint {
    CacheReopen,
    TemporaryCreate,
    TemporarySettlement,
    Publication,
    PublicationAfterLink,
    #[cfg(test)]
    DecisionWait,
}

#[derive(Clone)]
pub(crate) struct BlockingTestHook {
    inner: Arc<BlockingTestHookInner>,
}

struct BlockingTestHookInner {
    point: BlockingTestHookPoint,
    reached: AtomicBool,
    reached_notify: Notify,
    released: Mutex<bool>,
    release_notify: Condvar,
}

impl BlockingTestHook {
    #[cfg(test)]
    pub(crate) fn new(point: BlockingTestHookPoint) -> Self {
        Self {
            inner: Arc::new(BlockingTestHookInner {
                point,
                reached: AtomicBool::new(false),
                reached_notify: Notify::new(),
                released: Mutex::new(false),
                release_notify: Condvar::new(),
            }),
        }
    }

    fn point(&self) -> BlockingTestHookPoint {
        self.inner.point
    }

    fn block(&self) {
        self.inner.reached.store(true, Ordering::Release);
        self.inner.reached_notify.notify_waiters();
        let mut released = self.inner.released.lock().expect("blocking hook lock");
        while !*released {
            released = self
                .inner
                .release_notify
                .wait(released)
                .expect("blocking hook wait");
        }
    }

    #[cfg(test)]
    pub(crate) async fn wait_until_reached(&self) {
        loop {
            let notified = self.inner.reached_notify.notified();
            if self.inner.reached.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }

    #[cfg(test)]
    pub(crate) fn release(&self) {
        *self.inner.released.lock().expect("blocking hook lock") = true;
        self.inner.release_notify.notify_all();
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TestPublicationDecision {
    Commit,
    Abort,
}

#[cfg(test)]
pub(crate) async fn publication_decision_race_for_test(decision: TestPublicationDecision) -> bool {
    let control = PublicationControl::new();
    let waiter_control = control.clone();
    let hook = BlockingTestHook::new(BlockingTestHookPoint::DecisionWait);
    let waiter_hook = hook.clone();
    let waiter =
        spawn_blocking(move || waiter_control.wait_for_decision_with_hook(Some(&waiter_hook)));
    hook.wait_until_reached().await;

    let attempted = Arc::new(AtomicBool::new(false));
    let attempted_notify = Arc::new(Notify::new());
    let decision_control = control.clone();
    let decision_attempted = attempted.clone();
    let decision_notify = attempted_notify.clone();
    let decider = spawn_blocking(move || {
        decision_attempted.store(true, Ordering::Release);
        decision_notify.notify_waiters();
        let (first, second) = match decision {
            TestPublicationDecision::Commit => (PUBLICATION_COMMIT, PUBLICATION_ABORT),
            TestPublicationDecision::Abort => (PUBLICATION_ABORT, PUBLICATION_COMMIT),
        };
        decision_control.decide(first);
        decision_control.decide(second);
    });
    loop {
        let notified = attempted_notify.notified();
        if attempted.load(Ordering::Acquire) {
            break;
        }
        notified.await;
    }
    hook.release();
    decider.await.expect("decision task");
    waiter.await.expect("decision waiter")
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TestHookPoint {
    BeforeTemporaryCreate,
    TemporaryCreated,
    BodyChunkWritten,
    BeforePublication,
}

#[cfg(test)]
#[derive(Clone)]
pub(crate) struct TestHook {
    inner: Arc<TestHookInner>,
}

#[cfg(test)]
struct TestHookInner {
    point: TestHookPoint,
    reached: AtomicBool,
    reached_notify: Notify,
    released: AtomicBool,
    release_notify: Notify,
}

#[cfg(test)]
impl TestHook {
    pub(crate) fn new(point: TestHookPoint) -> Self {
        Self {
            inner: Arc::new(TestHookInner {
                point,
                reached: AtomicBool::new(false),
                reached_notify: Notify::new(),
                released: AtomicBool::new(false),
                release_notify: Notify::new(),
            }),
        }
    }

    fn point(&self) -> TestHookPoint {
        self.inner.point
    }

    async fn pause(&self) {
        self.inner.reached.store(true, Ordering::Release);
        self.inner.reached_notify.notify_waiters();
        loop {
            let notified = self.inner.release_notify.notified();
            if self.inner.released.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }

    pub(crate) async fn wait_until_reached(&self) {
        loop {
            let notified = self.inner.reached_notify.notified();
            if self.inner.reached.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }

    pub(crate) fn release(&self) {
        self.inner.released.store(true, Ordering::Release);
        self.inner.release_notify.notify_waiters();
    }
}

#[cfg(test)]
pub(crate) fn validate_redirect_chain_for_test(
    initial: &str,
    redirects: &[&str],
    allowed_origins: &[&str],
    profile: RedirectProfile,
) -> Result<(), AcquireError> {
    let allowed_origins = allowed_origins
        .iter()
        .map(|origin| HttpsOrigin((*origin).to_owned()))
        .collect::<BTreeSet<_>>();
    let request = FetchRequest {
        url: HttpsUrl(initial.to_owned()),
        allowed_origins: allowed_origins.clone(),
        expected_size: Some(1),
        maximum_size: NonZeroU64::new(1).expect("one is nonzero"),
        sha256: Sha256Hex("0".repeat(64)),
        sri: None,
    };
    validate_request(&request, profile, TransportMode::Production)?;
    let mut current = Url::parse(initial).map_err(|_| AcquireError::InvalidPolicy)?;
    let mut visited = HashSet::from([current.as_str().to_owned()]);
    for (index, target) in redirects.iter().enumerate() {
        validate_redirect_source(&current, profile)?;
        if index >= MAX_REDIRECTS {
            return Err(AcquireError::TooManyRedirects);
        }
        let next = redirect_target(&current, target)?;
        validate_redirect_target(&next, &allowed_origins, profile, TransportMode::Production)?;
        if !visited.insert(next.as_str().to_owned()) {
            return Err(AcquireError::RedirectDenied);
        }
        current = next;
    }
    Ok(())
}
