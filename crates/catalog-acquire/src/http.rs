#![cfg_attr(test, allow(dead_code))]

use std::{
    collections::{BTreeSet, HashSet},
    fmt, fs, io,
    num::NonZeroU64,
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use base64::Engine as _;
use reqwest::{Client, StatusCode, Url, header, redirect::Policy};
use sha2::{Digest, Sha256, Sha512};
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Notify,
    time::{Instant, sleep_until},
};

const WHOLE_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REDIRECTS: usize = 5;
const MAX_QUERY_BYTES: usize = 8 * 1024;
const MAX_URL_BYTES: usize = 16 * 1024;
const STREAM_BUFFER_BYTES: usize = 64 * 1024;
const GITHUB_HOST: &str = "github.com";
const GITHUB_ASSET_HOST: &str = "release-assets.githubusercontent.com";
static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(1);

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

    async fn cancelled(&self) {
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
        })
    }
}

impl std::error::Error for AcquireError {}

/// A fully rehashed digest-addressed cache winner.
#[derive(Debug)]
pub struct FetchedObject {
    path: PathBuf,
    bytes: Vec<u8>,
    sha256: Sha256Hex,
}

impl FetchedObject {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn size(&self) -> u64 {
        self.bytes.len() as u64
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
        self.cache.revalidate()?;
        let object_path = self.cache.object_path(&request.sha256);
        if path_exists(&object_path)? {
            let bytes = reopen_and_verify(
                &self.cache,
                &object_path,
                &request,
                cancellation,
                deadline,
                AcquireError::CacheInvalid,
            )
            .await?;
            return Ok(FetchedObject {
                path: object_path,
                bytes,
                sha256: request.sha256,
            });
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
                .receive_and_publish(response, request, object_path, cancellation, deadline)
                .await;
        }
    }

    async fn receive_and_publish(
        &self,
        mut response: reqwest::Response,
        request: FetchRequest,
        object_path: PathBuf,
        cancellation: &AcquisitionCancellation,
        deadline: Instant,
    ) -> Result<FetchedObject, AcquireError> {
        validate_content_length(response.headers(), &request)?;
        let (mut temporary, mut output) =
            self.cache.create_temporary(cancellation, deadline).await?;
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
        await_phase(cancellation, deadline, output.sync_all())
            .await?
            .map_err(|_| AcquireError::TemporaryFile)?;
        await_phase(
            cancellation,
            deadline,
            output.set_permissions(fs::Permissions::from_mode(0o400)),
        )
        .await?
        .map_err(|_| AcquireError::TemporaryFile)?;
        drop(output);

        let temporary_path = temporary.path().to_owned();
        let _ = reopen_and_verify(
            &self.cache,
            &temporary_path,
            &request,
            cancellation,
            deadline,
            AcquireError::TemporaryFile,
        )
        .await?;
        #[cfg(test)]
        self.pause_at(TestHookPoint::BeforePublication, cancellation, deadline)
            .await?;
        check_ready(cancellation, deadline)?;
        self.cache.revalidate()?;
        validate_file_path(&temporary_path, 0o400, AcquireError::TemporaryFile)?;

        match fs::hard_link(&temporary_path, &object_path) {
            Ok(()) => {
                let mut published = PublishedGuard::new(object_path.clone());
                let linked =
                    fs::metadata(&temporary_path).map_err(|_| AcquireError::TemporaryFile)?;
                if !secure_file(&linked, 0o400, 2) {
                    return Err(AcquireError::TemporaryFile);
                }
                temporary.remove()?;
                check_ready(cancellation, deadline)?;
                sync_directory(&self.cache.path).map_err(|_| AcquireError::Publication)?;
                let bytes = reopen_and_verify(
                    &self.cache,
                    &object_path,
                    &request,
                    cancellation,
                    deadline,
                    AcquireError::Publication,
                )
                .await?;
                check_ready(cancellation, deadline)?;
                published.disarm();
                Ok(FetchedObject {
                    path: object_path,
                    bytes,
                    sha256: request.sha256,
                })
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                temporary.remove()?;
                let bytes = reopen_and_verify(
                    &self.cache,
                    &object_path,
                    &request,
                    cancellation,
                    deadline,
                    AcquireError::CacheInvalid,
                )
                .await?;
                Ok(FetchedObject {
                    path: object_path,
                    bytes,
                    sha256: request.sha256,
                })
            }
            Err(_) => Err(AcquireError::Publication),
        }
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

async fn reopen_and_verify(
    cache: &CacheRoot,
    path: &Path,
    request: &FetchRequest,
    cancellation: &AcquisitionCancellation,
    deadline: Instant,
    category: AcquireError,
) -> Result<Vec<u8>, AcquireError> {
    check_ready(cancellation, deadline)?;
    cache.revalidate().map_err(|_| category)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = await_phase(cancellation, deadline, options.open(path))
        .await?
        .map_err(|_| category)?;
    let before = await_phase(cancellation, deadline, file.metadata())
        .await?
        .map_err(|_| category)?;
    if !secure_file(&before, 0o400, 1)
        || before.len() > request.maximum_size.get()
        || request
            .expected_size
            .is_some_and(|expected| before.len() != expected)
    {
        return Err(category);
    }
    let capacity = usize::try_from(before.len()).map_err(|_| category)?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut sha256 = Sha256::new();
    let mut sha512 = Sha512::new();
    let mut buffer = vec![0_u8; STREAM_BUFFER_BYTES];
    let mut size = 0_u64;
    loop {
        let read = await_phase(cancellation, deadline, file.read(&mut buffer))
            .await?
            .map_err(|_| category)?;
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
        bytes.extend_from_slice(&buffer[..read]);
    }
    if size != before.len()
        || request
            .expected_size
            .is_some_and(|expected| size != expected)
    {
        return Err(category);
    }
    if !digests_match(
        request,
        sha256.finalize().as_slice(),
        sha512.finalize().as_slice(),
    ) {
        return Err(category);
    }
    let after = await_phase(cancellation, deadline, file.metadata())
        .await?
        .map_err(|_| category)?;
    if !same_file(&before, &after) || !secure_file(&after, 0o400, 1) {
        return Err(category);
    }
    validate_open_path(path, &after, category)?;
    cache.revalidate().map_err(|_| category)?;
    Ok(bytes)
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
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl CacheRoot {
    fn open(path: &Path) -> Result<Self, AcquireError> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if !secure_directory(&metadata) {
                    return Err(AcquireError::InvalidPolicy);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::DirBuilder::new()
                    .recursive(false)
                    .mode(0o700)
                    .create(path)
                    .map_err(|_| AcquireError::InvalidPolicy)?;
            }
            Err(_) => return Err(AcquireError::InvalidPolicy),
        }
        let canonical = fs::canonicalize(path).map_err(|_| AcquireError::InvalidPolicy)?;
        let metadata = fs::symlink_metadata(&canonical).map_err(|_| AcquireError::InvalidPolicy)?;
        if !secure_directory(&metadata) {
            return Err(AcquireError::InvalidPolicy);
        }
        Ok(Self {
            path: canonical,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    fn revalidate(&self) -> Result<(), AcquireError> {
        let metadata = fs::symlink_metadata(&self.path).map_err(|_| AcquireError::CacheInvalid)?;
        if !secure_directory(&metadata)
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
        {
            return Err(AcquireError::CacheInvalid);
        }
        Ok(())
    }

    fn object_path(&self, digest: &Sha256Hex) -> PathBuf {
        self.path.join(digest.as_str())
    }

    async fn create_temporary(
        &self,
        cancellation: &AcquisitionCancellation,
        deadline: Instant,
    ) -> Result<(TemporaryGuard, File), AcquireError> {
        self.revalidate()?;
        for _ in 0..64 {
            check_ready(cancellation, deadline)?;
            let nonce = NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed);
            let path = self
                .path
                .join(format!(".fetch-{}-{nonce}.tmp", std::process::id()));
            let mut options = OpenOptions::new();
            options
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            match await_phase(cancellation, deadline, options.open(&path)).await? {
                Ok(file) => {
                    let metadata = file
                        .metadata()
                        .await
                        .map_err(|_| AcquireError::TemporaryFile)?;
                    if !secure_file(&metadata, 0o600, 1) {
                        let _ = fs::remove_file(&path);
                        return Err(AcquireError::TemporaryFile);
                    }
                    return Ok((TemporaryGuard::new(path), file));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(AcquireError::TemporaryFile),
            }
        }
        Err(AcquireError::TemporaryFile)
    }
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

fn secure_file(metadata: &fs::Metadata, mode: u32, links: u64) -> bool {
    metadata.file_type().is_file()
        && metadata.uid() == current_euid()
        && metadata.mode() & 0o777 == mode
        && metadata.nlink() == links
}

fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mode() == right.mode()
        && left.nlink() == right.nlink()
}

fn validate_file_path(path: &Path, mode: u32, category: AcquireError) -> Result<(), AcquireError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| category)?;
    secure_file(&metadata, mode, 1)
        .then_some(())
        .ok_or(category)
}

fn validate_open_path(
    path: &Path,
    opened: &fs::Metadata,
    category: AcquireError,
) -> Result<(), AcquireError> {
    let path_metadata = fs::symlink_metadata(path).map_err(|_| category)?;
    if !secure_file(&path_metadata, 0o400, 1)
        || path_metadata.dev() != opened.dev()
        || path_metadata.ino() != opened.ino()
    {
        return Err(category);
    }
    Ok(())
}

fn path_exists(path: &Path) -> Result<bool, AcquireError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(AcquireError::CacheInvalid),
    }
}

fn sync_directory(path: &Path) -> io::Result<()> {
    fs::File::open(path)?.sync_all()
}

struct TemporaryGuard {
    path: Option<PathBuf>,
}

impl TemporaryGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn path(&self) -> &Path {
        self.path.as_deref().expect("temporary path remains armed")
    }

    fn remove(&mut self) -> Result<(), AcquireError> {
        if let Some(path) = self.path.take()
            && let Err(error) = fs::remove_file(&path)
        {
            self.path = Some(path);
            return Err(if error.kind() == io::ErrorKind::NotFound {
                AcquireError::TemporaryFile
            } else {
                AcquireError::Publication
            });
        }
        Ok(())
    }
}

impl Drop for TemporaryGuard {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }
}

struct PublishedGuard {
    path: Option<PathBuf>,
}

impl PublishedGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for PublishedGuard {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TestHookPoint {
    TemporaryCreated,
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
