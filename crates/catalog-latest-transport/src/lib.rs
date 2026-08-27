use std::{collections::HashSet, fmt, time::Duration};

#[cfg(test)]
use std::net::SocketAddr;

use reqwest::{Client, StatusCode, Url, header, redirect::Policy};
use sha2::{Digest, Sha256};

const RUNTIME_CATALOG_LATEST_URL: &str = "https://github.com/Devalch/Fluxsemble-runtime-catalog/releases/latest/download/catalog-v1.json";
const GITHUB_HOST: &str = "github.com";
const GITHUB_ASSET_HOST: &str = "release-assets.githubusercontent.com";
const MAX_RUNTIME_CATALOG_BYTES: u64 = 8 * 1024 * 1024;
const MAX_REDIRECTS: usize = 5;
const MAX_QUERY_BYTES: usize = 8 * 1024;
const MAX_URL_BYTES: usize = 16 * 1024;
const WHOLE_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Stable, non-echoing failures for the one fixed public latest transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LatestTransportError {
    InvalidContentIdentity,
    RedirectDenied,
    TooManyRedirects,
    UnexpectedStatus,
    Transport,
    Timeout,
    SizeMismatch,
    DigestMismatch,
}

impl fmt::Display for LatestTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidContentIdentity => "invalid latest content identity",
            Self::RedirectDenied => "latest redirect denied",
            Self::TooManyRedirects => "too many latest redirects",
            Self::UnexpectedStatus => "unexpected latest response status",
            Self::Transport => "latest transport failed",
            Self::Timeout => "latest transport timed out",
            Self::SizeMismatch => "latest size mismatch",
            Self::DigestMismatch => "latest digest mismatch",
        })
    }
}

impl std::error::Error for LatestTransportError {}

/// Exact verified bytes returned from the fixed runtime-catalog latest endpoint.
#[derive(Debug, PartialEq, Eq)]
pub struct RuntimeCatalogLatest {
    bytes: Vec<u8>,
    sha256: String,
}

impl RuntimeCatalogLatest {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

/// Fetches only the compiled runtime-catalog latest endpoint under the exact credential-free,
/// no-proxy, Rustls, bounded GitHub-to-release-assets policy. This API never creates a runtime.
pub async fn fetch_runtime_catalog_latest_exact(
    expected_size: u64,
    expected_sha256: &str,
) -> Result<RuntimeCatalogLatest, LatestTransportError> {
    let endpoint = Endpoint::production();
    fetch_with_endpoint(expected_size, expected_sha256, &endpoint).await
}

struct Endpoint {
    initial_url: String,
    mode: TransportMode,
}

impl Endpoint {
    fn production() -> Self {
        Self {
            initial_url: RUNTIME_CATALOG_LATEST_URL.to_owned(),
            mode: TransportMode::Production,
        }
    }

    #[cfg(test)]
    fn loopback(address: SocketAddr) -> Self {
        Self {
            initial_url: format!(
                "http://{GITHUB_HOST}:{}/Devalch/Fluxsemble-runtime-catalog/releases/latest/download/catalog-v1.json",
                address.port()
            ),
            mode: TransportMode::Loopback(address),
        }
    }
}

#[derive(Clone, Copy)]
enum TransportMode {
    Production,
    #[cfg(test)]
    Loopback(SocketAddr),
}

async fn fetch_with_endpoint(
    expected_size: u64,
    expected_sha256: &str,
    endpoint: &Endpoint,
) -> Result<RuntimeCatalogLatest, LatestTransportError> {
    if expected_size == 0
        || expected_size > MAX_RUNTIME_CATALOG_BYTES
        || !valid_sha256(expected_sha256)
    {
        return Err(LatestTransportError::InvalidContentIdentity);
    }
    let initial = Url::parse(&endpoint.initial_url)
        .map_err(|_| LatestTransportError::InvalidContentIdentity)?;
    validate_initial(&initial, endpoint.mode)?;
    let client = credential_free_client(endpoint.mode)?;
    match tokio::time::timeout(
        WHOLE_REQUEST_TIMEOUT,
        fetch_inner(
            &client,
            initial,
            endpoint.mode,
            expected_size,
            expected_sha256,
        ),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(LatestTransportError::Timeout),
    }
}

async fn fetch_inner(
    client: &Client,
    mut current: Url,
    mode: TransportMode,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<RuntimeCatalogLatest, LatestTransportError> {
    let mut visited = HashSet::from([current.as_str().to_owned()]);
    for redirects in 0..=MAX_REDIRECTS {
        let mut response = client
            .get(current.clone())
            .send()
            .await
            .map_err(|_| LatestTransportError::Transport)?;
        if response.status().is_redirection() {
            if redirects == MAX_REDIRECTS {
                return Err(LatestTransportError::TooManyRedirects);
            }
            if current.host_str() == Some(GITHUB_ASSET_HOST) {
                return Err(LatestTransportError::RedirectDenied);
            }
            let location = single_location(response.headers())?;
            let next = current
                .join(location)
                .map_err(|_| LatestTransportError::RedirectDenied)?;
            validate_hop(&next, mode)?;
            if !visited.insert(next.as_str().to_owned()) {
                return Err(LatestTransportError::RedirectDenied);
            }
            current = next;
            continue;
        }
        if response.status() != StatusCode::OK {
            return Err(LatestTransportError::UnexpectedStatus);
        }
        validate_hop(&current, mode)?;
        if response
            .content_length()
            .is_some_and(|length| length != expected_size)
        {
            return Err(LatestTransportError::SizeMismatch);
        }
        let capacity = usize::try_from(expected_size)
            .map_err(|_| LatestTransportError::InvalidContentIdentity)?;
        let mut bytes = Vec::with_capacity(capacity);
        let mut hasher = Sha256::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| LatestTransportError::Transport)?
        {
            let next = bytes
                .len()
                .checked_add(chunk.len())
                .ok_or(LatestTransportError::SizeMismatch)?;
            if next as u64 > expected_size {
                return Err(LatestTransportError::SizeMismatch);
            }
            hasher.update(&chunk);
            bytes.extend_from_slice(&chunk);
        }
        if bytes.len() as u64 != expected_size {
            return Err(LatestTransportError::SizeMismatch);
        }
        let actual = format!("{:x}", hasher.finalize());
        if actual != expected_sha256 {
            return Err(LatestTransportError::DigestMismatch);
        }
        return Ok(RuntimeCatalogLatest {
            bytes,
            sha256: actual,
        });
    }
    Err(LatestTransportError::TooManyRedirects)
}

fn credential_free_client(mode: TransportMode) -> Result<Client, LatestTransportError> {
    let mut builder = Client::builder()
        .redirect(Policy::none())
        .referer(false)
        .no_proxy()
        .timeout(WHOLE_REQUEST_TIMEOUT)
        .use_rustls_tls();
    match mode {
        TransportMode::Production => builder = builder.https_only(true),
        #[cfg(test)]
        TransportMode::Loopback(address) => {
            builder = builder
                .resolve(GITHUB_HOST, address)
                .resolve(GITHUB_ASSET_HOST, address);
        }
    }
    builder.build().map_err(|_| LatestTransportError::Transport)
}

fn validate_initial(url: &Url, mode: TransportMode) -> Result<(), LatestTransportError> {
    if matches!(mode, TransportMode::Production) && url.as_str() != RUNTIME_CATALOG_LATEST_URL {
        return Err(LatestTransportError::InvalidContentIdentity);
    }
    validate_common(url, mode).map_err(|_| LatestTransportError::InvalidContentIdentity)?;
    if !is_github_hop(url, mode) || url.query().is_some() {
        return Err(LatestTransportError::InvalidContentIdentity);
    }
    Ok(())
}

fn validate_hop(url: &Url, mode: TransportMode) -> Result<(), LatestTransportError> {
    validate_common(url, mode)?;
    if is_github_hop(url, mode) {
        if url.query().is_some() {
            return Err(LatestTransportError::RedirectDenied);
        }
    } else if !is_release_asset_hop(url, mode) {
        return Err(LatestTransportError::RedirectDenied);
    }
    Ok(())
}

fn validate_common(url: &Url, mode: TransportMode) -> Result<(), LatestTransportError> {
    if url.as_str().len() > MAX_URL_BYTES
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.as_str().contains('\\')
    {
        return Err(LatestTransportError::RedirectDenied);
    }
    match mode {
        TransportMode::Production => {
            if url.scheme() != "https" || url.port().is_some() {
                return Err(LatestTransportError::RedirectDenied);
            }
        }
        #[cfg(test)]
        TransportMode::Loopback(address) => {
            if url.scheme() != "http"
                || !matches!(url.host_str(), Some(GITHUB_HOST | GITHUB_ASSET_HOST))
                || url.port_or_known_default() != Some(address.port())
            {
                return Err(LatestTransportError::RedirectDenied);
            }
        }
    }
    Ok(())
}

fn is_github_hop(url: &Url, mode: TransportMode) -> bool {
    if url.host_str() != Some(GITHUB_HOST)
        || url.query().is_some()
        || (matches!(mode, TransportMode::Production) && url.port().is_some())
    {
        return false;
    }
    let segments = url
        .path()
        .strip_prefix('/')
        .unwrap_or(url.path())
        .split('/')
        .collect::<Vec<_>>();
    segments.len() == 6
        && segments
            .iter()
            .all(|segment| !segment.is_empty() && !matches!(*segment, "." | ".."))
        && segments[2] == "releases"
        && ((segments[3] == "latest" && segments[4] == "download") || segments[3] == "download")
}

fn is_release_asset_hop(url: &Url, mode: TransportMode) -> bool {
    url.host_str() == Some(GITHUB_ASSET_HOST)
        && !url.path().is_empty()
        && url.path() != "/"
        && (!matches!(mode, TransportMode::Production) || url.port().is_none())
        && url
            .query()
            .is_some_and(|query| !query.is_empty() && query.len() <= MAX_QUERY_BYTES)
}

fn single_location(headers: &header::HeaderMap) -> Result<&str, LatestTransportError> {
    let mut values = headers.get_all(header::LOCATION).iter();
    let value = values.next().ok_or(LatestTransportError::RedirectDenied)?;
    if values.next().is_some() {
        return Err(LatestTransportError::RedirectDenied);
    }
    let value = value
        .to_str()
        .map_err(|_| LatestTransportError::RedirectDenied)?;
    if value.is_empty() || value.len() > MAX_URL_BYTES {
        return Err(LatestTransportError::RedirectDenied);
    }
    Ok(value)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use sha2::{Digest, Sha256};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinHandle,
    };

    use super::*;

    const CATALOG: &[u8] = b"exact catalog";

    #[tokio::test]
    async fn fixed_latest_policy_is_async_exact_and_credential_free() {
        let server = Server::start(vec![
            Response::redirect("/Devalch/Fluxsemble-runtime-catalog/releases/download/catalog-v1-sequence-1/catalog-v1.json"),
            Response::redirect_with_asset_host("/objects/catalog?opaque=one"),
            Response::exact(CATALOG),
        ])
        .await;
        let endpoint = Endpoint::loopback(server.address);
        let digest = format!("{:x}", Sha256::digest(CATALOG));
        let fetched = fetch_with_endpoint(CATALOG.len() as u64, &digest, &endpoint)
            .await
            .unwrap();
        assert_eq!(fetched.as_bytes(), CATALOG);
        assert_eq!(fetched.sha256(), digest);
        let requests = server.requests.lock().unwrap().clone();
        assert_eq!(requests.len(), 3);
        for headers in requests {
            for forbidden in ["authorization", "cookie", "proxy-authorization", "referer"] {
                assert!(!headers.iter().any(|header| header == forbidden));
            }
        }
    }

    #[tokio::test]
    async fn fixed_latest_rejects_redirect_status_size_and_digest_mutations() {
        let digest = format!("{:x}", Sha256::digest(CATALOG));
        for (plans, size, expected_digest, error) in [
            (
                vec![Response::status(500)],
                CATALOG.len() as u64,
                digest.clone(),
                LatestTransportError::UnexpectedStatus,
            ),
            (
                vec![Response::exact(b"short")],
                CATALOG.len() as u64,
                digest.clone(),
                LatestTransportError::SizeMismatch,
            ),
            (
                vec![Response::exact(CATALOG)],
                CATALOG.len() as u64,
                "00".repeat(32),
                LatestTransportError::DigestMismatch,
            ),
            (
                vec![Response::redirect("https://evil.example/object")],
                CATALOG.len() as u64,
                digest.clone(),
                LatestTransportError::RedirectDenied,
            ),
        ] {
            let server = Server::start(plans).await;
            let endpoint = Endpoint::loopback(server.address);
            assert_eq!(
                fetch_with_endpoint(size, &expected_digest, &endpoint)
                    .await
                    .unwrap_err(),
                error
            );
        }
    }

    #[tokio::test]
    async fn public_async_api_returns_result_inside_existing_tokio_runtime_without_panicking() {
        assert_eq!(
            fetch_runtime_catalog_latest_exact(0, &"00".repeat(32)).await,
            Err(LatestTransportError::InvalidContentIdentity)
        );
    }

    #[derive(Clone)]
    struct Response {
        status: u16,
        location: Option<String>,
        body: Vec<u8>,
        asset_host: bool,
    }

    impl Response {
        fn exact(body: &[u8]) -> Self {
            Self {
                status: 200,
                location: None,
                body: body.to_vec(),
                asset_host: false,
            }
        }

        fn redirect(location: &str) -> Self {
            Self {
                status: 302,
                location: Some(location.to_owned()),
                body: Vec::new(),
                asset_host: false,
            }
        }

        fn redirect_with_asset_host(location: &str) -> Self {
            Self {
                asset_host: true,
                ..Self::redirect(location)
            }
        }

        fn status(status: u16) -> Self {
            Self {
                status,
                location: None,
                body: Vec::new(),
                asset_host: false,
            }
        }
    }

    struct Server {
        address: SocketAddr,
        requests: Arc<Mutex<Vec<Vec<String>>>>,
        task: JoinHandle<()>,
    }

    impl Server {
        async fn start(plans: Vec<Response>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let plans = Arc::new(Mutex::new(plans.into_iter().rev().collect::<Vec<_>>()));
            let requests = Arc::new(Mutex::new(Vec::new()));
            let task_plans = plans.clone();
            let task_requests = requests.clone();
            let task = tokio::spawn(async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    let plan = task_plans
                        .lock()
                        .unwrap()
                        .pop()
                        .unwrap_or_else(|| Response::status(500));
                    let requests = task_requests.clone();
                    let port = address.port();
                    tokio::spawn(async move {
                        let mut request = Vec::new();
                        let mut buffer = [0_u8; 1024];
                        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                            let count = stream.read(&mut buffer).await.unwrap();
                            if count == 0 || request.len() > 32 * 1024 {
                                return;
                            }
                            request.extend_from_slice(&buffer[..count]);
                        }
                        let text = String::from_utf8_lossy(&request);
                        let headers = text
                            .lines()
                            .skip(1)
                            .take_while(|line| !line.trim().is_empty())
                            .filter_map(|line| {
                                line.split_once(':')
                                    .map(|(name, _)| name.to_ascii_lowercase())
                            })
                            .collect();
                        requests.lock().unwrap().push(headers);
                        let reason = if plan.status == 200 {
                            "OK"
                        } else if plan.status == 302 {
                            "Found"
                        } else {
                            "Error"
                        };
                        let mut response = format!(
                            "HTTP/1.1 {} {}\r\nConnection: close\r\nContent-Length: {}\r\n",
                            plan.status,
                            reason,
                            plan.body.len()
                        );
                        if let Some(location) = plan.location {
                            let location = if plan.asset_host {
                                format!("http://{GITHUB_ASSET_HOST}:{port}{location}")
                            } else {
                                location
                            };
                            response.push_str(&format!("Location: {location}\r\n"));
                        }
                        response.push_str("\r\n");
                        stream.write_all(response.as_bytes()).await.unwrap();
                        stream.write_all(&plan.body).await.unwrap();
                    });
                }
            });
            Self {
                address,
                requests,
                task,
            }
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
}
