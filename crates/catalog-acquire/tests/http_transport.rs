#[path = "../src/http.rs"]
mod http;

use std::{
    fs,
    io::{Read, Seek, SeekFrom},
    num::NonZeroU64,
    os::unix::fs::{DirBuilderExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use http::{
    AcquireError, AcquisitionCancellation, BlockingTestHook, BlockingTestHookPoint,
    CredentialFreeFetcher, FetchRequest, FetchedObject, RedirectProfile, TestHook, TestHookPoint,
    TestPublicationDecision,
};
use sha2::{Digest, Sha256, Sha512};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::{sleep, timeout},
};

const ARTIFACT: &[u8] = b"artifact";

#[tokio::test]
async fn fetch_is_exact_bounded_and_credential_free() {
    let server = LoopbackServer::start(vec![
        ResponsePlan::redirect("/artifact"),
        ResponsePlan::exact(ARTIFACT),
    ])
    .await;
    let root = TestRoot::new();
    let fetcher = test_fetcher(root.path(), &server, RedirectProfile::Default);
    let request = request(&server.url("/start"), &[server.origin()], ARTIFACT, None, 8);

    let fetched = fetcher
        .fetch_exact(request, &AcquisitionCancellation::new())
        .await
        .unwrap();

    assert_eq!(fetched.size(), 8);
    assert_eq!(
        fetched.file().metadata().unwrap().permissions().mode() & 0o777,
        0o400
    );
    assert_eq!(fetched_bytes(fetched), ARTIFACT);
    let requests = server.wait_for_requests(2).await;
    for request in requests {
        for forbidden in ["authorization", "cookie", "proxy-authorization", "referer"] {
            assert!(
                !request.headers.contains(&forbidden.to_string()),
                "unexpected {forbidden}"
            );
        }
    }
}

#[test]
fn redirect_downgrade_unapproved_query_userinfo_origin_loop_and_overflow_fail_closed() {
    let initial = "https://downloads.example.test/start";
    let allowed = ["https://downloads.example.test", "https://cdn.example.test"];
    let overflow = format!("https://downloads.example.test/{}", "x".repeat(16 * 1024));
    let too_many = [
        "https://downloads.example.test/1",
        "https://downloads.example.test/2",
        "https://downloads.example.test/3",
        "https://downloads.example.test/4",
        "https://downloads.example.test/5",
        "https://downloads.example.test/6",
    ];
    let hostile = vec![
        vec!["http://downloads.example.test/end"],
        vec!["https://other.example.test/end"],
        vec!["https://downloads.example.test/end?token=opaque"],
        vec!["https://user@downloads.example.test/end"],
        vec!["https://downloads.example.test/end#fragment"],
        vec![initial],
        vec![overflow.as_str()],
        too_many.to_vec(),
    ];

    for redirects in hostile {
        assert!(
            http::validate_redirect_chain_for_test(
                initial,
                &redirects,
                &allowed,
                RedirectProfile::Default,
            )
            .is_err()
        );
    }
}

#[tokio::test]
async fn github_profile_allows_only_a_bounded_final_release_asset_query() {
    let body = b"github-asset";
    let server = LoopbackServer::start(vec![
        ResponsePlan::redirect("/owner/repository/releases/download/v1/asset.bin"),
        ResponsePlan::redirect(&format!(
            "http://release-assets.githubusercontent.com:{}/objects/asset?opaque=one",
            server_port_placeholder()
        )),
        ResponsePlan::exact(body),
    ])
    .await;
    server.replace_port_placeholder();
    let root = TestRoot::new();
    let fetcher = test_fetcher(root.path(), &server, RedirectProfile::GitHubReleaseAsset);
    let initial = format!(
        "http://github.com:{}/owner/repository/releases/latest/download/asset.bin",
        server.addr().port()
    );
    let allowed = [
        format!("http://github.com:{}", server.addr().port()),
        format!(
            "http://release-assets.githubusercontent.com:{}",
            server.addr().port()
        ),
    ];
    let fetched = fetcher
        .fetch_exact(
            request(&initial, &allowed, body, None, body.len() as u64),
            &AcquisitionCancellation::new(),
        )
        .await
        .unwrap();
    assert_eq!(fetched_bytes(fetched), body);

    let production_initial =
        "https://github.com/owner/repository/releases/latest/download/asset.bin";
    let production_tag = "https://github.com/owner/repository/releases/download/v1/asset.bin";
    let production_final = "https://release-assets.githubusercontent.com/objects/asset?opaque=one";
    let production_allowed = [
        "https://github.com",
        "https://release-assets.githubusercontent.com",
    ];
    assert!(
        http::validate_redirect_chain_for_test(
            production_initial,
            &[production_tag, production_final],
            &production_allowed,
            RedirectProfile::GitHubReleaseAsset,
        )
        .is_ok()
    );

    let long_query = format!(
        "https://release-assets.githubusercontent.com/objects/asset?{}",
        "q".repeat(8 * 1024 + 1)
    );
    let long_url = format!(
        "https://release-assets.githubusercontent.com/{}?q=1",
        "x".repeat(16 * 1024)
    );
    let mutations = vec![
        (
            format!("{production_initial}?bad=1"),
            vec![production_final.to_string()],
        ),
        (
            production_initial.to_string(),
            vec![format!("{production_tag}?bad=1")],
        ),
        (
            production_initial.to_string(),
            vec![format!("{production_final}#bad")],
        ),
        (
            production_initial.to_string(),
            vec!["https://user@release-assets.githubusercontent.com/object?q=1".to_string()],
        ),
        (
            production_initial.to_string(),
            vec!["https://objects.githubusercontent.com/object?q=1".to_string()],
        ),
        (
            production_initial.to_string(),
            vec![
                production_final.to_string(),
                "https://release-assets.githubusercontent.com/second?q=2".to_string(),
            ],
        ),
        (production_initial.to_string(), vec![long_query]),
        (production_initial.to_string(), vec![long_url]),
        (
            production_initial.to_string(),
            vec!["http://release-assets.githubusercontent.com/object?q=1".to_string()],
        ),
        (
            production_initial.to_string(),
            vec!["https://release-assets.githubusercontent.com/object".to_string()],
        ),
    ];
    for (initial, redirects) in mutations {
        let redirects = redirects.iter().map(String::as_str).collect::<Vec<_>>();
        assert!(
            http::validate_redirect_chain_for_test(
                &initial,
                &redirects,
                &production_allowed,
                RedirectProfile::GitHubReleaseAsset,
            )
            .is_err()
        );
    }
}

#[tokio::test]
async fn size_digest_sri_status_and_errors_are_closed() {
    let cases = [
        (
            ResponsePlan::with_declared_length(b"1234", 5),
            request_parts(b"1234", None, 5),
            AcquireError::SizeMismatch,
        ),
        (
            ResponsePlan::exact(b"123"),
            request_parts(b"1234", None, 4),
            AcquireError::SizeMismatch,
        ),
        (
            ResponsePlan::exact(b"12345"),
            request_parts(b"1234", None, 4),
            AcquireError::SizeLimitExceeded,
        ),
        (
            ResponsePlan::exact(b"bad!"),
            request_parts(b"good", None, 4),
            AcquireError::DigestMismatch,
        ),
        (
            ResponsePlan::exact(b"data"),
            request_parts(b"data", Some(b"other"), 4),
            AcquireError::SriMismatch,
        ),
        (
            ResponsePlan::status(500),
            request_parts(b"none", None, 4),
            AcquireError::UnexpectedStatus,
        ),
    ];
    for (plan, parts, expected) in cases {
        let server = LoopbackServer::start(vec![plan]).await;
        let root = TestRoot::new();
        let fetcher = test_fetcher(root.path(), &server, RedirectProfile::Default);
        let req = request_with_parts(
            &server.url("/attacker-secret-path"),
            &[server.origin()],
            parts,
        );
        let error = fetcher
            .fetch_exact(req, &AcquisitionCancellation::new())
            .await
            .unwrap_err();
        assert_eq!(error, expected);
        assert!(!error.to_string().contains("attacker-secret-path"));
        assert_no_partial(root.path());
    }
}

#[tokio::test]
async fn cancellation_before_headers_during_body_and_before_publication_leaves_no_partial() {
    let before_headers =
        LoopbackServer::start(vec![ResponsePlan::exact(ARTIFACT).hold_headers()]).await;
    let root = TestRoot::new();
    let fetcher = test_fetcher(root.path(), &before_headers, RedirectProfile::Default);
    let cancellation = AcquisitionCancellation::new();
    let trigger = cancellation.clone();
    tokio::spawn(async move {
        sleep(Duration::from_millis(30)).await;
        trigger.cancel();
    });
    assert_eq!(
        fetcher
            .fetch_exact(
                request(
                    &before_headers.url("/headers"),
                    &[before_headers.origin()],
                    ARTIFACT,
                    None,
                    8
                ),
                &cancellation,
            )
            .await
            .unwrap_err(),
        AcquireError::Cancelled
    );
    assert_no_partial(root.path());

    let during_body = LoopbackServer::start(vec![ResponsePlan::chunk_then_hold(b"arti")]).await;
    let root = TestRoot::new();
    let hook = TestHook::new(TestHookPoint::BodyChunkWritten);
    let fetcher = test_fetcher(root.path(), &during_body, RedirectProfile::Default)
        .with_test_hook(hook.clone());
    let cancellation = AcquisitionCancellation::new();
    let trigger = cancellation.clone();
    let release = hook.clone();
    tokio::spawn(async move {
        release.wait_until_reached().await;
        trigger.cancel();
        release.release();
    });
    assert_eq!(
        fetcher
            .fetch_exact(
                request(
                    &during_body.url("/body"),
                    &[during_body.origin()],
                    ARTIFACT,
                    None,
                    8
                ),
                &cancellation,
            )
            .await
            .unwrap_err(),
        AcquireError::Cancelled
    );
    assert_no_partial(root.path());

    let complete = LoopbackServer::start(vec![ResponsePlan::exact(ARTIFACT)]).await;
    let root = TestRoot::new();
    let hook = TestHook::new(TestHookPoint::BeforePublication);
    let fetcher =
        test_fetcher(root.path(), &complete, RedirectProfile::Default).with_test_hook(hook.clone());
    let cancellation = AcquisitionCancellation::new();
    let trigger = cancellation.clone();
    let release = hook.clone();
    tokio::spawn(async move {
        release.wait_until_reached().await;
        trigger.cancel();
        release.release();
    });
    assert_eq!(
        fetcher
            .fetch_exact(
                request(
                    &complete.url("/complete"),
                    &[complete.origin()],
                    ARTIFACT,
                    None,
                    8
                ),
                &cancellation,
            )
            .await
            .unwrap_err(),
        AcquireError::Cancelled
    );
    assert_no_partial(root.path());
}

#[tokio::test]
async fn dropped_future_and_timeout_remove_temporary_objects() {
    let server = LoopbackServer::start(vec![ResponsePlan::chunk_then_hold(b"arti")]).await;
    let root = TestRoot::new();
    let hook = TestHook::new(TestHookPoint::TemporaryCreated);
    let fetcher =
        test_fetcher(root.path(), &server, RedirectProfile::Default).with_test_hook(hook.clone());
    let fetch = tokio::spawn({
        let fetcher = fetcher.clone();
        let request = request(&server.url("/drop"), &[server.origin()], ARTIFACT, None, 8);
        async move {
            fetcher
                .fetch_exact(request, &AcquisitionCancellation::new())
                .await
        }
    });
    hook.wait_until_reached().await;
    fetch.abort();
    let _ = fetch.await;
    wait_for_no_temporary(root.path()).await;
    assert_no_partial(root.path());

    let server = LoopbackServer::start(vec![ResponsePlan::exact(ARTIFACT)]).await;
    let root = TestRoot::new();
    let hook = BlockingTestHook::new(BlockingTestHookPoint::PublicationAfterLink);
    let fetcher = test_fetcher(root.path(), &server, RedirectProfile::Default)
        .with_blocking_test_hook(hook.clone());
    let fetch = tokio::spawn({
        let request = request(
            &server.url("/drop-during-publication"),
            &[server.origin()],
            ARTIFACT,
            None,
            8,
        );
        async move {
            fetcher
                .fetch_exact(request, &AcquisitionCancellation::new())
                .await
        }
    });
    hook.wait_until_reached().await;
    assert_eq!(cache_objects(root.path()).len(), 1);
    fetch.abort();
    let _ = fetch.await;
    hook.release();
    wait_for_empty(root.path()).await;
    sleep(Duration::from_millis(50)).await;
    assert_no_partial(root.path());

    let server = LoopbackServer::start(vec![ResponsePlan::exact(ARTIFACT).hold_headers()]).await;
    let root = TestRoot::new();
    let fetcher = CredentialFreeFetcher::for_loopback_test(
        root.path(),
        RedirectProfile::Default,
        server.addr(),
        Duration::from_millis(75),
    )
    .unwrap();
    assert_eq!(
        fetcher
            .fetch_exact(
                request(
                    &server.url("/timeout"),
                    &[server.origin()],
                    ARTIFACT,
                    None,
                    8
                ),
                &AcquisitionCancellation::new(),
            )
            .await
            .unwrap_err(),
        AcquireError::Timeout
    );
    assert_no_partial(root.path());
}

#[tokio::test]
async fn cache_collision_link_attack_and_concurrent_exact_fetch_fail_or_settle_safely() {
    let collision_server = LoopbackServer::start(vec![ResponsePlan::exact(ARTIFACT)]).await;
    let root = TestRoot::new();
    let fetcher = test_fetcher(root.path(), &collision_server, RedirectProfile::Default);
    let req = request(
        &collision_server.url("/collision"),
        &[collision_server.origin()],
        ARTIFACT,
        None,
        8,
    );
    let cache_path = fetcher.cache_path_for_test(&req);
    fs::write(&cache_path, b"hostile!").unwrap();
    fs::set_permissions(&cache_path, fs::Permissions::from_mode(0o400)).unwrap();
    assert_eq!(
        fetcher
            .fetch_exact(req, &AcquisitionCancellation::new())
            .await
            .unwrap_err(),
        AcquireError::CacheInvalid
    );
    assert!(collision_server.requests().is_empty());

    let hardlink_server = LoopbackServer::start(vec![ResponsePlan::exact(ARTIFACT)]).await;
    let hardlink_root = TestRoot::new();
    let hardlink_fetcher = test_fetcher(
        hardlink_root.path(),
        &hardlink_server,
        RedirectProfile::Default,
    );
    let hardlink_request = request(
        &hardlink_server.url("/must-not-fetch-linked-cache"),
        &[hardlink_server.origin()],
        ARTIFACT,
        None,
        8,
    );
    let hardlink_cache = hardlink_fetcher.cache_path_for_test(&hardlink_request);
    let external_link = hardlink_root.external_path("cache-hardlink");
    fs::write(&hardlink_cache, ARTIFACT).unwrap();
    fs::set_permissions(&hardlink_cache, fs::Permissions::from_mode(0o400)).unwrap();
    fs::hard_link(&hardlink_cache, &external_link).unwrap();
    assert_eq!(
        hardlink_fetcher
            .fetch_exact(hardlink_request, &AcquisitionCancellation::new())
            .await
            .unwrap_err(),
        AcquireError::CacheInvalid
    );
    assert!(hardlink_server.requests().is_empty());
    fs::remove_file(external_link).unwrap();

    let linked_server = LoopbackServer::start(vec![ResponsePlan::exact(ARTIFACT)]).await;
    let root = TestRoot::new();
    let hook = TestHook::new(TestHookPoint::BeforePublication);
    let fetcher = test_fetcher(root.path(), &linked_server, RedirectProfile::Default)
        .with_test_hook(hook.clone());
    let req = request(
        &linked_server.url("/unnamed-temporary"),
        &[linked_server.origin()],
        ARTIFACT,
        None,
        8,
    );
    let observer_root = root.path().to_path_buf();
    let observer = hook.clone();
    let observation = tokio::spawn(async move {
        observer.wait_until_reached().await;
        assert!(temporary_paths(&observer_root).is_empty());
        observer.release();
    });
    let fetched = fetcher
        .fetch_exact(req, &AcquisitionCancellation::new())
        .await
        .unwrap();
    observation.await.unwrap();
    assert_eq!(fetched_bytes(fetched), ARTIFACT);
    assert_eq!(cache_objects(root.path()).len(), 1);

    let first = LoopbackServer::start(vec![ResponsePlan::exact(ARTIFACT)]).await;
    let second = LoopbackServer::start(vec![ResponsePlan::exact(ARTIFACT)]).await;
    let root = TestRoot::new();
    let fetcher_a = test_fetcher(root.path(), &first, RedirectProfile::Default);
    let fetcher_b = test_fetcher(root.path(), &second, RedirectProfile::Default);
    let cancellation_a = AcquisitionCancellation::new();
    let cancellation_b = AcquisitionCancellation::new();
    let a = fetcher_a.fetch_exact(
        request(&first.url("/a"), &[first.origin()], ARTIFACT, None, 8),
        &cancellation_a,
    );
    let b = fetcher_b.fetch_exact(
        request(&second.url("/b"), &[second.origin()], ARTIFACT, None, 8),
        &cancellation_b,
    );
    let (a, b) = tokio::join!(a, b);
    assert_eq!(fetched_bytes(a.unwrap()), ARTIFACT);
    assert_eq!(fetched_bytes(b.unwrap()), ARTIFACT);
    assert_eq!(cache_objects(root.path()).len(), 1);
    assert!(temporary_paths(root.path()).is_empty());
}

#[tokio::test]
async fn large_artifact_returns_descriptor_authority_without_retaining_artifact_bytes() {
    let body = vec![0x5a; 8 * 1024 * 1024];
    let server = LoopbackServer::start(vec![ResponsePlan::exact(&body)]).await;
    let root = TestRoot::new();
    let fetcher = CredentialFreeFetcher::for_loopback_test(
        root.path(),
        RedirectProfile::Default,
        server.addr(),
        Duration::from_secs(10),
    )
    .unwrap();
    let fetched = fetcher
        .fetch_exact(
            request(
                &server.url("/large"),
                &[server.origin()],
                &body,
                None,
                body.len() as u64,
            ),
            &AcquisitionCancellation::new(),
        )
        .await
        .unwrap();

    assert_eq!(fetched.size(), body.len() as u64);
    let mut file = fetched.into_file();
    let mut sample = [0_u8; 1];
    file.read_exact(&mut sample).unwrap();
    assert_eq!(sample, [0x5a]);
    file.seek(SeekFrom::End(-1)).unwrap();
    file.read_exact(&mut sample).unwrap();
    assert_eq!(sample, [0x5a]);

    let source = include_str!("../src/http.rs");
    let fetched_source = source
        .split("pub struct FetchedObject")
        .nth(1)
        .unwrap()
        .split("pub struct CredentialFreeFetcher")
        .next()
        .unwrap();
    assert!(!fetched_source.contains("Vec<u8>"));
    assert!(!fetched_source.contains("pub fn bytes"));
    assert!(fetched_source.contains("file: fs::File"));
}

#[tokio::test]
async fn publication_decision_cannot_lose_commit_or_abort_wakeup() {
    for (decision, expected) in [
        (TestPublicationDecision::Commit, true),
        (TestPublicationDecision::Abort, false),
    ] {
        let observed = timeout(
            Duration::from_secs(2),
            http::publication_decision_race_for_test(decision),
        )
        .await
        .expect("decision waiter must settle without a lost wakeup");
        assert_eq!(observed, expected);
    }
}

#[tokio::test]
async fn blocking_filesystem_cancellation_settles_without_starving_runtime_or_late_publication() {
    let server = LoopbackServer::start(vec![ResponsePlan::exact(ARTIFACT)]).await;
    let root = TestRoot::new();
    let hook = BlockingTestHook::new(BlockingTestHookPoint::PublicationAfterLink);
    let fetcher = test_fetcher(root.path(), &server, RedirectProfile::Default)
        .with_blocking_test_hook(hook.clone());
    let cancellation = AcquisitionCancellation::new();
    let fetch = tokio::spawn({
        let cancellation = cancellation.clone();
        let request = request(
            &server.url("/blocked"),
            &[server.origin()],
            ARTIFACT,
            None,
            8,
        );
        async move { fetcher.fetch_exact(request, &cancellation).await }
    });

    hook.wait_until_reached().await;
    cancellation.cancel();
    timeout(Duration::from_millis(100), sleep(Duration::from_millis(20)))
        .await
        .unwrap();
    assert!(
        !fetch.is_finished(),
        "filesystem mutation must settle before return"
    );
    assert_eq!(cache_objects(root.path()).len(), 1);
    hook.release();
    assert_eq!(fetch.await.unwrap().unwrap_err(), AcquireError::Cancelled);
    sleep(Duration::from_millis(50)).await;
    assert_no_partial(root.path());
}

#[tokio::test]
async fn blocking_filesystem_timeout_settles_before_return_and_stops_mutation() {
    let server = LoopbackServer::start(vec![ResponsePlan::exact(ARTIFACT)]).await;
    let root = TestRoot::new();
    let hook = BlockingTestHook::new(BlockingTestHookPoint::PublicationAfterLink);
    let fetcher = CredentialFreeFetcher::for_loopback_test(
        root.path(),
        RedirectProfile::Default,
        server.addr(),
        Duration::from_millis(75),
    )
    .unwrap()
    .with_blocking_test_hook(hook.clone());
    let fetch = tokio::spawn({
        let request = request(
            &server.url("/blocked-timeout"),
            &[server.origin()],
            ARTIFACT,
            None,
            8,
        );
        async move {
            fetcher
                .fetch_exact(request, &AcquisitionCancellation::new())
                .await
        }
    });

    hook.wait_until_reached().await;
    timeout(
        Duration::from_millis(150),
        sleep(Duration::from_millis(100)),
    )
    .await
    .unwrap();
    assert!(
        !fetch.is_finished(),
        "timed-out mutation must still settle before return"
    );
    assert_eq!(cache_objects(root.path()).len(), 1);
    hook.release();
    assert_eq!(fetch.await.unwrap().unwrap_err(), AcquireError::Timeout);
    sleep(Duration::from_millis(50)).await;
    assert_no_partial(root.path());
}

#[tokio::test]
async fn cache_root_directory_replacement_before_temp_creation_cannot_redirect_authority() {
    let server = LoopbackServer::start(vec![ResponsePlan::exact(ARTIFACT)]).await;
    let root = TestRoot::new();
    let hook = TestHook::new(TestHookPoint::BeforeTemporaryCreate);
    let fetcher =
        test_fetcher(root.path(), &server, RedirectProfile::Default).with_test_hook(hook.clone());
    let fetch = tokio::spawn({
        let request = request(
            &server.url("/replace-root"),
            &[server.origin()],
            ARTIFACT,
            None,
            8,
        );
        async move {
            fetcher
                .fetch_exact(request, &AcquisitionCancellation::new())
                .await
        }
    });

    hook.wait_until_reached().await;
    let original = root.external_path("original-before-temp");
    fs::rename(root.path(), &original).unwrap();
    fs::DirBuilder::new()
        .mode(0o700)
        .create(root.path())
        .unwrap();
    hook.release();
    let fetched = fetch.await.unwrap().unwrap();
    assert_eq!(fetched_bytes(fetched), ARTIFACT);
    assert_no_partial(root.path());
    assert_eq!(cache_objects(&original).len(), 1);
    fs::remove_dir_all(original).unwrap();
}

#[tokio::test]
async fn cache_root_symlink_replacement_before_publication_cannot_redirect_authority() {
    let server = LoopbackServer::start(vec![ResponsePlan::exact(ARTIFACT)]).await;
    let root = TestRoot::new();
    let hook = TestHook::new(TestHookPoint::BeforePublication);
    let fetcher =
        test_fetcher(root.path(), &server, RedirectProfile::Default).with_test_hook(hook.clone());
    let fetch = tokio::spawn({
        let request = request(
            &server.url("/replace-before-publish"),
            &[server.origin()],
            ARTIFACT,
            None,
            8,
        );
        async move {
            fetcher
                .fetch_exact(request, &AcquisitionCancellation::new())
                .await
        }
    });

    hook.wait_until_reached().await;
    let original = root.external_path("original-before-publish");
    let attacker = root.external_path("attacker-root");
    fs::rename(root.path(), &original).unwrap();
    fs::DirBuilder::new().mode(0o700).create(&attacker).unwrap();
    symlink(&attacker, root.path()).unwrap();
    hook.release();
    let fetched = fetch.await.unwrap().unwrap();
    assert_eq!(fetched_bytes(fetched), ARTIFACT);
    assert_no_partial(&attacker);
    assert_eq!(cache_objects(&original).len(), 1);

    fs::remove_file(root.path()).unwrap();
    fs::DirBuilder::new()
        .mode(0o700)
        .create(root.path())
        .unwrap();
    fs::remove_dir_all(original).unwrap();
    fs::remove_dir_all(attacker).unwrap();
}

#[test]
fn production_request_values_are_derived_from_catalog_core_records() {
    fn accepts_core_values(
        url: &catalog_core::HttpsArtifactUrl,
        origins: &[catalog_core::AllowedOrigin],
        digest: &catalog_core::Sha256Digest,
        sri: &catalog_core::RegistryIntegrity,
    ) -> FetchRequest {
        FetchRequest::from_catalog_values(
            url,
            origins,
            Some(8),
            NonZeroU64::new(8).unwrap(),
            digest,
            Some(sri),
        )
    }
    let _ = accepts_core_values;
}

fn request(
    url: &str,
    origins: &[String],
    bytes: &[u8],
    sri_bytes: Option<&[u8]>,
    maximum: u64,
) -> FetchRequest {
    request_with_parts(url, origins, request_parts(bytes, sri_bytes, maximum))
}

struct RequestParts {
    size: u64,
    maximum: u64,
    sha256: String,
    sri: Option<String>,
}

fn request_parts(bytes: &[u8], sri_bytes: Option<&[u8]>, maximum: u64) -> RequestParts {
    RequestParts {
        size: bytes.len() as u64,
        maximum,
        sha256: hex(&Sha256::digest(bytes)),
        sri: sri_bytes.map(|bytes| {
            use base64::Engine as _;
            format!(
                "sha512-{}",
                base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
            )
        }),
    }
}

fn request_with_parts(url: &str, origins: &[String], parts: RequestParts) -> FetchRequest {
    FetchRequest::for_test(
        url,
        origins,
        Some(parts.size),
        NonZeroU64::new(parts.maximum).unwrap(),
        &parts.sha256,
        parts.sri.as_deref(),
    )
    .unwrap()
}

fn test_fetcher(
    root: &Path,
    server: &LoopbackServer,
    profile: RedirectProfile,
) -> CredentialFreeFetcher {
    CredentialFreeFetcher::for_loopback_test(root, profile, server.addr(), Duration::from_secs(2))
        .unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn fetched_bytes(fetched: FetchedObject) -> Vec<u8> {
    let mut file = fetched.into_file();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    bytes
}

fn assert_no_partial(root: &Path) {
    assert!(
        fs::read_dir(root).unwrap().next().is_none(),
        "partial cache object remains"
    );
}

fn cache_objects(root: &Path) -> Vec<PathBuf> {
    fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            !path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".fetch-")
        })
        .collect()
}

fn temporary_paths(root: &Path) -> Vec<PathBuf> {
    fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".fetch-")
        })
        .collect()
}

async fn wait_for_no_temporary(root: &Path) {
    timeout(Duration::from_secs(2), async {
        while !temporary_paths(root).is_empty() {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

async fn wait_for_empty(root: &Path) {
    timeout(Duration::from_secs(2), async {
        while fs::read_dir(root).unwrap().next().is_some() {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

static NEXT_ROOT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

struct TestRoot {
    path: PathBuf,
}

impl TestRoot {
    fn new() -> Self {
        let nonce = NEXT_ROOT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "catalog-acquire-http-{}-{now}-{nonce}",
            std::process::id()
        ));
        fs::DirBuilder::new()
            .recursive(false)
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn external_path(&self, suffix: &str) -> PathBuf {
        self.path.with_extension(suffix)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
        let _ = fs::remove_file(self.path.with_extension("linked-temp"));
    }
}

#[derive(Clone)]
struct ResponsePlan {
    status: u16,
    location: Option<String>,
    content_length: Option<u64>,
    chunks: Vec<Vec<u8>>,
    hold_headers: bool,
    hold_body: bool,
}

impl ResponsePlan {
    fn exact(bytes: &[u8]) -> Self {
        Self {
            status: 200,
            location: None,
            content_length: Some(bytes.len() as u64),
            chunks: vec![bytes.to_vec()],
            hold_headers: false,
            hold_body: false,
        }
    }

    fn with_declared_length(bytes: &[u8], length: u64) -> Self {
        Self {
            content_length: Some(length),
            ..Self::exact(bytes)
        }
    }

    fn status(status: u16) -> Self {
        Self {
            status,
            location: None,
            content_length: Some(0),
            chunks: Vec::new(),
            hold_headers: false,
            hold_body: false,
        }
    }

    fn redirect(location: &str) -> Self {
        Self {
            status: 302,
            location: Some(location.to_string()),
            content_length: Some(0),
            chunks: Vec::new(),
            hold_headers: false,
            hold_body: false,
        }
    }

    fn chunk_then_hold(bytes: &[u8]) -> Self {
        Self {
            content_length: None,
            chunks: vec![bytes.to_vec()],
            hold_body: true,
            ..Self::exact(&[])
        }
    }

    fn hold_headers(mut self) -> Self {
        self.hold_headers = true;
        self
    }
}

#[derive(Clone, Debug)]
struct CapturedRequest {
    headers: Vec<String>,
}

struct LoopbackServer {
    addr: std::net::SocketAddr,
    plans: Arc<Mutex<Vec<ResponsePlan>>>,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    task: JoinHandle<()>,
}

impl LoopbackServer {
    async fn start(plans: Vec<ResponsePlan>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let plans = Arc::new(Mutex::new(plans.into_iter().rev().collect::<Vec<_>>()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let task_plans = plans.clone();
        let task_requests = requests.clone();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let plan = task_plans
                    .lock()
                    .unwrap()
                    .pop()
                    .unwrap_or_else(|| ResponsePlan::status(500));
                let requests = task_requests.clone();
                tokio::spawn(async move {
                    let _ = serve(stream, plan, requests).await;
                });
            }
        });
        Self {
            addr,
            plans,
            requests,
            task,
        }
    }

    fn addr(&self) -> std::net::SocketAddr {
        self.addr
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }

    fn origin(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn requests(&self) -> Vec<CapturedRequest> {
        self.requests.lock().unwrap().clone()
    }

    async fn wait_for_requests(&self, count: usize) -> Vec<CapturedRequest> {
        timeout(Duration::from_secs(2), async {
            while self.requests.lock().unwrap().len() < count {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        self.requests()
    }

    fn replace_port_placeholder(&self) {
        let port = self.addr.port().to_string();
        for plan in self.plans.lock().unwrap().iter_mut() {
            if let Some(location) = &mut plan.location {
                *location = location.replace("PORT_PLACEHOLDER", &port);
            }
        }
    }
}

impl Drop for LoopbackServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn server_port_placeholder() -> &'static str {
    "PORT_PLACEHOLDER"
}

async fn serve(
    mut stream: TcpStream,
    plan: ResponsePlan,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
) -> std::io::Result<()> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    while !bytes.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            return Ok(());
        }
        bytes.extend_from_slice(&buffer[..read]);
        if bytes.len() > 32 * 1024 {
            return Ok(());
        }
    }
    let text = String::from_utf8_lossy(&bytes);
    let headers = text
        .lines()
        .skip(1)
        .take_while(|line| !line.is_empty() && *line != "\r")
        .filter_map(|line| {
            line.split_once(':')
                .map(|(name, _)| name.trim().to_ascii_lowercase())
        })
        .collect();
    requests.lock().unwrap().push(CapturedRequest { headers });

    if plan.hold_headers {
        sleep(Duration::from_secs(10)).await;
        return Ok(());
    }
    let reason = match plan.status {
        200 => "OK",
        302 => "Found",
        500 => "Error",
        _ => "Status",
    };
    let mut response = format!(
        "HTTP/1.1 {} {}\r\nConnection: close\r\n",
        plan.status, reason
    );
    if let Some(location) = plan.location {
        response.push_str(&format!("Location: {location}\r\n"));
    }
    if let Some(length) = plan.content_length {
        response.push_str(&format!("Content-Length: {length}\r\n"));
    }
    response.push_str("\r\n");
    stream.write_all(response.as_bytes()).await?;
    for chunk in plan.chunks {
        stream.write_all(&chunk).await?;
        stream.flush().await?;
    }
    if plan.hold_body {
        sleep(Duration::from_secs(10)).await;
    }
    Ok(())
}
