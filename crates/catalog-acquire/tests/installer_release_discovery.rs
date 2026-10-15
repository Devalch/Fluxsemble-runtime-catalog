use catalog_acquire::{
    AcquireError, ReleaseDiscoveryTransport, discover_pi_installer_release_with_transport,
};
use catalog_core::pi_release_subject_sha256;
use serde_json::{Value, json};
use std::collections::BTreeMap;
#[path = "../../catalog-installer-verify/tests/support/mod.rs"]
mod support;
use support::{fixture_bytes, request, sha256};

#[test]
fn installer_discovery_requires_exact_registry_integrity_evidence() {
    assert!(discover_fixture("matching-missing-integrity-supplement").is_ok());
    assert!(discover_fixture("missing-registry-integrity").is_err());
    assert!(discover_fixture("substituted-registry-version").is_err());
}
#[test]
fn installer_discovery_derives_wrapper_identity_graph_locator_and_cli() {
    let candidate = discover_fixture("matching-missing-integrity-supplement").unwrap();
    let profile = serde_json::to_value(&candidate.profile).unwrap();
    assert_eq!(profile["installer_root"]["version"], "7.0.0");
    assert_eq!(profile["pi_package"]["version"], "1.2.0");
    assert_eq!(
        profile["pi_package_locator"],
        "node_modules/@earendil-works/pi-coding-agent"
    );
    assert_eq!(profile["cli_entrypoint"], "dist/start.js");
    assert_eq!(candidate.inputs.locked_package_count(), 2);
    assert_eq!(candidate.inputs.pre_prune_package_count(), 3);
    assert!(
        profile["pi_manifest"]["url"]
            .as_str()
            .unwrap()
            .contains("catalog-v1-sequence-9/pi-package-")
    );
    assert_eq!(
        candidate.release_subject_sha256().unwrap(),
        pi_release_subject_sha256(&candidate.profile).unwrap()
    );
    let bytes = candidate.inputs.canonical_bytes().unwrap();
    assert_eq!(
        catalog_acquire::PackageInputManifestV2::from_json(&bytes).unwrap(),
        candidate.inputs
    );
}
#[test]
fn installer_discovery_fails_closed_on_bad_graph_or_archive() {
    for mutation in [
        "extra-graph-node",
        "unsafe-archive",
        "unsupported-lock",
        "wrong-root",
        "substituted-registry-url",
        "mismatched-integrity",
        "unsupported-engine",
        "missing-dependency",
        "dependency-version-mismatch",
        "undeclared-archive-dependency",
        "required-platform-pruned",
        "null-dependency-map",
    ] {
        assert!(discover_fixture(mutation).is_err(), "accepted {mutation}");
    }
}
#[test]
fn installer_discovery_requires_explicit_policy_before_fetch() {
    let mut r = request();
    r.installer_policy = None;
    struct NoFetch;
    impl ReleaseDiscoveryTransport for NoFetch {
        fn fetch(&self, _: &str, _: usize) -> Result<Vec<u8>, AcquireError> {
            panic!("discovery fetched before rejecting absent explicit policy")
        }
    }
    assert_eq!(
        discover_pi_installer_release_with_transport(r, &NoFetch),
        Err(AcquireError::Input)
    );
}
#[test]
fn npm_partial_upper_engine_bound_includes_the_entire_major() {
    assert!(discover_fixture("partial-upper-engine").is_ok());
}
struct Transport(BTreeMap<String, Vec<u8>>);
impl ReleaseDiscoveryTransport for Transport {
    fn fetch(&self, url: &str, maximum_bytes: usize) -> Result<Vec<u8>, AcquireError> {
        self.0
            .get(url)
            .filter(|b| b.len() <= maximum_bytes)
            .cloned()
            .ok_or(AcquireError::UnexpectedStatus)
    }
}
fn discover_fixture(
    mutation: &str,
) -> Result<catalog_acquire::PiInstallerCandidateV1, AcquireError> {
    discover_fixture_for_version(mutation, "1.2.0")
}
fn discover_fixture_for_version(
    mutation: &str,
    pi_version: &str,
) -> Result<catalog_acquire::PiInstallerCandidateV1, AcquireError> {
    let transport = fixture_transport(mutation, pi_version);
    let mut r = request();
    r.pi_version = pi_version.into();
    if matches!(
        mutation,
        "root-overrides"
            | "null-root-overrides"
            | "lock-root-overrides"
            | "top-lock-overrides"
            | "unused-root-overrides"
            | "range-root-overrides"
            | "nested-root-overrides"
            | "selector-root-overrides"
            | "reference-root-overrides"
            | "oversized-root-overrides"
            | "conflicting-lock-root-overrides"
            | "conflicting-top-lock-overrides"
            | "outside-range-root-overrides"
            | "mixed-version-root-overrides"
    ) {
        struct SupportOnlyTransport<'a>(&'a Transport);
        impl ReleaseDiscoveryTransport for SupportOnlyTransport<'_> {
            fn fetch(&self, url: &str, maximum: usize) -> Result<Vec<u8>, AcquireError> {
                assert!(
                    url.starts_with("https://github.com/earendil-works/pi/releases/download/"),
                    "archive/registry acquisition before root override rejection: {url}"
                );
                self.0.fetch(url, maximum)
            }
        }
        discover_pi_installer_release_with_transport(r, &SupportOnlyTransport(&transport))
    } else {
        discover_pi_installer_release_with_transport(r, &transport)
    }
}
fn fixture_transport(mutation: &str, pi_version: &str) -> Transport {
    Transport(fixture_bytes(mutation, pi_version))
}

#[test]
fn immutable_input_graph_rejects_duplicate_unknown_unsafe_and_mismatched_count() {
    let candidate = discover_fixture("matching-missing-integrity-supplement").unwrap();
    let bytes = candidate.inputs.canonical_bytes().unwrap();
    let text = String::from_utf8(bytes.clone()).unwrap();
    assert!(
        catalog_acquire::PackageInputManifestV2::from_json(
            text.replacen("{", "{\"schema_version\":2,", 1).as_bytes()
        )
        .is_err()
    );
    assert!(
        catalog_acquire::PackageInputManifestV2::from_json(
            text.replacen("{", "{\"extra\":1,", 1).as_bytes()
        )
        .is_err()
    );
    for (pointer, value) in [
        (
            "/locked_packages/0/locator",
            json!("node_modules/../escape"),
        ),
        ("/locked_packages/0/archive_size", json!(0)),
        ("/pre_prune_package_count", json!(99)),
        ("/locked_packages/0/pruned_reasons", json!(["unknown"])),
    ] {
        let mut input: Value = serde_json::from_slice(&bytes).unwrap();
        *input.pointer_mut(pointer).unwrap() = value;
        assert!(
            catalog_acquire::PackageInputManifestV2::from_json(
                &serde_json::to_vec(&input).unwrap()
            )
            .is_err(),
            "accepted {pointer}"
        );
    }
}

#[test]
fn compatible_later_version_and_larger_graph_are_not_reference_allowlists() {
    assert!(discover_fixture_for_version("matching-missing-integrity-supplement", "1.3.0").is_ok());
    let candidate = discover_fixture("larger-graph").unwrap();
    assert_eq!(candidate.inputs.locked_package_count(), 3);
    assert_eq!(candidate.inputs.pre_prune_package_count(), 4);
}

#[test]
fn immutable_graph_retains_and_binds_exact_upstream_support_sources() {
    let candidate = discover_fixture("matching-missing-integrity-supplement").unwrap();
    candidate
        .inputs
        .validate_for_profile(&candidate.profile)
        .unwrap();
    let bytes = candidate.inputs.canonical_bytes().unwrap();
    let input: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        input["installer_manifest_source"]["url"],
        "https://github.com/earendil-works/pi/releases/download/v1.2.0/pi-coding-agent-install-package.json"
    );
    for (pointer, value) in [
        (
            "/installer_manifest_source/url",
            json!(
                "https://github.com/unrelated/repo/releases/download/v1.2.0/pi-coding-agent-install-package.json"
            ),
        ),
        (
            "/installer_lock_source/url",
            json!(
                "https://github.com/earendil-works/pi/releases/download/v1.3.0/pi-coding-agent-install-package-lock.json"
            ),
        ),
        ("/installer_manifest_source/sha256", json!("f".repeat(64))),
        ("/installer_manifest_source/size_bytes", json!("01")),
        ("/installer_manifest_source/size_bytes", json!(1)),
    ] {
        let mut mutated = input.clone();
        *mutated.pointer_mut(pointer).unwrap() = value;
        let result = catalog_acquire::PackageInputManifestV2::from_json(
            &serde_json::to_vec(&mutated).unwrap(),
        );
        assert!(
            result.is_err()
                || result
                    .unwrap()
                    .validate_for_profile(&candidate.profile)
                    .is_err(),
            "accepted {pointer}"
        );
    }
}

/// Commissioning is opt-in; ordinary tests do not need a captured upstream archive set.
#[test]
#[ignore = "requires explicitly admitted public inputs in local target/task3-admitted-inputs"]
fn installer_discovery_replays_admitted_reference_inputs_offline() {
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/task3-admitted-inputs");
    let receipt_bytes = std::fs::read(root.join("receipt.json")).unwrap();
    assert_eq!(
        sha256(&receipt_bytes),
        "65837d21e8f2aafbe889e3a885a81e8aababecfeae1f324fbb8c2c2683bcb2c5"
    );
    let receipt: Value = serde_json::from_slice(&receipt_bytes).unwrap();
    for (path, fact) in receipt["files"].as_object().unwrap() {
        let bytes = std::fs::read(root.join(path)).unwrap();
        assert_eq!(
            bytes.len().to_string(),
            fact["size_bytes"].as_str().unwrap()
        );
        assert_eq!(sha256(&bytes), fact["sha256"].as_str().unwrap());
    }
    let mut responses = BTreeMap::new();
    for source in receipt["sources"].as_array().unwrap() {
        let bytes = std::fs::read(root.join(source["path"].as_str().unwrap())).unwrap();
        assert_eq!(sha256(&bytes), source["sha256"].as_str().unwrap());
        responses.insert(source["url"].as_str().unwrap().to_owned(), bytes);
    }
    // DERIVED fixture response, not an observed plain .txt acquisition: Task2 captured
    // and authenticated this exact .asc evidence. Preserve clear-sign dash unescaping.
    let armored = std::str::from_utf8(
        responses
            .get("https://nodejs.org/dist/v22.19.0/SHASUMS256.txt.asc")
            .unwrap(),
    )
    .unwrap();
    assert!(armored.starts_with("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"));
    let (_, payload) = armored.split_once("\n\n").unwrap();
    let (payload, _) = payload
        .split_once("\n-----BEGIN PGP SIGNATURE-----")
        .unwrap();
    let lines: Vec<_> = payload
        .lines()
        .map(|line| {
            if line.starts_with('-') {
                line.strip_prefix("- ").expect("clear-sign dash escape")
            } else {
                line
            }
        })
        .collect();
    let checksums = format!("{}\n", lines.join("\n")).into_bytes();
    assert!(std::str::from_utf8(&checksums).unwrap().lines().any(|line| line == "c0649af18e6a24f6fe5535a3e86b341dd49a8e71117c8b68bde973ef834f16f2  node-v22.19.0-linux-x64.tar.xz"));
    responses.insert(
        "https://nodejs.org/dist/v22.19.0/SHASUMS256.txt".into(),
        checksums,
    );
    struct ReplayTransport {
        responses: Transport,
        requested: std::cell::RefCell<Vec<String>>,
    }
    impl ReleaseDiscoveryTransport for ReplayTransport {
        fn fetch(&self, url: &str, limit: usize) -> Result<Vec<u8>, AcquireError> {
            self.requested.borrow_mut().push(url.to_owned());
            self.responses.fetch(url, limit)
        }
    }
    let transport = ReplayTransport {
        responses: Transport(responses),
        requested: Default::default(),
    };
    let result = discover_pi_installer_release_with_transport(request(), &transport);
    assert!(
        result.is_ok(),
        "replay failed {:?}; last request {:?}",
        result.as_ref().err(),
        transport.requested.borrow().last()
    );
    let candidate = result.unwrap();
    candidate
        .inputs
        .validate_for_profile(&candidate.profile)
        .unwrap();
    assert_eq!(
        candidate.inputs.locked_package_count(),
        receipt["package_count"].as_u64().unwrap() as usize
    );
    assert_eq!(
        candidate.inputs.pre_prune_package_count(),
        candidate.inputs.locked_package_count() + 1
    );
    println!(
        "offline admitted candidate: {} locked packages, {} packages including wrapper; subject {}",
        candidate.inputs.locked_package_count(),
        candidate.inputs.pre_prune_package_count(),
        candidate
            .release_subject_sha256()
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
}

#[test]
fn npm_omitted_and_empty_dependency_maps_are_equivalent() {
    assert!(discover_fixture("empty-dependency-map").is_ok());
    assert!(discover_fixture("null-dependency-map").is_err());
    assert!(discover_fixture("undeclared-archive-dependency").is_err());
}

#[test]
fn scoped_registry_supplementation_uses_the_exact_encoded_name_version_route() {
    assert!(discover_fixture("scoped-missing-integrity").is_ok());
    assert!(discover_fixture("scoped-substituted-name").is_err());
}

#[test]
fn pruning_derives_requiredness_from_verified_edges_not_optional_flags() {
    for mutation in [
        "false-optional-pruned",
        "false-optional-applicable",
        "shared-required-pruned",
        "shared-upgrade-pruned",
        "optional-parent-required-child-pruned",
        "optional-overlap-effective-mismatch",
    ] {
        assert!(discover_fixture(mutation).is_err(), "accepted {mutation}");
    }
    for mutation in [
        "valid-optional-pruned",
        "valid-optional-applicable",
        "shared-required-applicable",
        "shared-upgrade-applicable",
        "optional-overlap",
    ] {
        assert!(discover_fixture(mutation).is_ok(), "rejected {mutation}");
    }
}

#[test]
fn root_overrides_require_a_bounded_exact_source_consistent_subset() {
    for mutation in [
        "root-overrides",
        "null-root-overrides",
        "lock-root-overrides",
        "top-lock-overrides",
        "unused-root-overrides",
        "range-root-overrides",
        "nested-root-overrides",
        "selector-root-overrides",
        "reference-root-overrides",
        "oversized-root-overrides",
        "conflicting-lock-root-overrides",
        "conflicting-top-lock-overrides",
        "outside-range-root-overrides",
        "mixed-version-root-overrides",
    ] {
        assert_eq!(
            discover_fixture(mutation).unwrap_err(),
            AcquireError::Graph,
            "accepted {mutation}"
        );
    }
    for mutation in [
        "valid-root-overrides",
        "equal-lock-overrides",
        "empty-root-overrides",
        "two-version-graph",
    ] {
        assert!(discover_fixture(mutation).is_ok(), "rejected {mutation}");
    }
}

#[test]
fn acquisition_reverifies_original_support_sources_before_materialization() {
    use catalog_core::PiReleaseIntentV2;
    let transport = fixture_transport("matching-missing-integrity-supplement", "1.2.0");
    let candidate = discover_pi_installer_release_with_transport(request(), &transport).unwrap();
    let intent = PiReleaseIntentV2::from_json(&serde_jcs::to_vec(&json!({"schema_version":2,"sequence":"9","tag":"catalog-v1-sequence-9","generated_at":"2026-10-01T00:00:00Z","expires_at":"2026-11-01T00:00:00Z","title":"Pi","notes":"test only","profile":candidate.profile})).unwrap()).unwrap();
    let root = std::env::temp_dir().join(format!(
        "pi-acquire-v2-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let request = |name: &str| catalog_acquire::AcquireInstallerReleaseRequest {
        source: catalog_acquire::AcquireInstallerReleaseSource::Intent {
            intent: intent.clone(),
        },
        package_inputs: candidate.inputs.clone(),
        cache_root: root.join(name),
        output: root.join(format!("{name}-bundle")),
        cancellation: catalog_acquire::AcquisitionCancellation::new(),
    };
    for name in ["matching", "changed", "changed-observation"] {
        std::fs::create_dir(root.join(name)).unwrap();
        std::fs::set_permissions(root.join(name), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let verified =
        catalog_acquire::acquire_installer_release_with_transport(request("matching"), &transport)
            .unwrap();
    for descriptor in [
        candidate.profile.installer_manifest(),
        candidate.profile.installer_lock(),
        candidate.profile.pi_manifest(),
    ] {
        assert!(
            verified
                .objects()
                .iter()
                .any(|o| o.source_url().as_str() == descriptor.url().as_str()
                    && o.sha256().as_str() == descriptor.sha256().as_str()
                    && o.size() == descriptor.size_bytes().get())
        );
    }
    for (index, auxiliary) in candidate.inputs.auxiliary_inputs().iter().enumerate() {
        assert!(
            verified
                .objects()
                .iter()
                .any(|o| o.source_url().as_str() == auxiliary.url()
                    && o.sha256().as_str() == auxiliary.sha256()
                    && o.size() == auxiliary.size_bytes())
        );
        let mut replaced = fixture_transport("matching-missing-integrity-supplement", "1.2.0");
        replaced.0.get_mut(auxiliary.url()).unwrap().push(b' ');
        let name = format!("changed-auxiliary-{index}");
        std::fs::create_dir(root.join(&name)).unwrap();
        std::fs::set_permissions(root.join(&name), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            catalog_acquire::acquire_installer_release_with_transport(request(&name), &replaced)
                .is_err()
        );
        assert!(!root.join(format!("{name}-bundle")).exists());
    }
    let mut altered = fixture_transport("matching-missing-integrity-supplement", "1.2.0");
    altered
        .0
        .get_mut(candidate.inputs.installer_manifest_source().url())
        .unwrap()
        .push(b' ');
    assert!(
        catalog_acquire::acquire_installer_release_with_transport(request("changed"), &altered)
            .is_err()
    );
    assert!(!root.join("changed-bundle").exists());
    let mut observed = serde_json::to_value(&candidate.inputs).unwrap();
    observed["locked_packages"][0]["archive_member_count"] = json!(999);
    let mut altered_request = request("changed-observation");
    altered_request.package_inputs =
        catalog_acquire::PackageInputManifestV2::from_json(&serde_jcs::to_vec(&observed).unwrap())
            .unwrap();
    assert!(
        catalog_acquire::acquire_installer_release_with_transport(altered_request, &transport)
            .is_err()
    );
    assert!(!root.join("changed-observation-bundle").exists());
}
