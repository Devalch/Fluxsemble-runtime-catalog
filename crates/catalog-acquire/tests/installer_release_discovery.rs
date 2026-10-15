use base64::Engine as _;
use catalog_acquire::{
    AcquireError, DiscoverPiReleaseRequest, PiInstallerDiscoveryPolicy, ReleaseDiscoveryTransport,
    discover_pi_installer_release_with_transport,
};
use catalog_core::{PiRequiredContractsV1, pi_release_subject_sha256};
use flate2::{Compression, write::GzEncoder};
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha512};
use std::{collections::BTreeMap, io::Write};
use xz2::write::XzEncoder;
const PI: &str = "@earendil-works/pi-coding-agent";
const DEP_URL: &str = "https://registry.npmjs.org/dep/-/dep-1.0.0.tgz";

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
fn request() -> DiscoverPiReleaseRequest {
    let contracts: Value = serde_json::from_slice(include_bytes!(
        "fixtures/pi-installer/supported-contracts-v1.json"
    ))
    .unwrap();
    DiscoverPiReleaseRequest {
        sequence: 9,
        generated_at: "2026-10-01T00:00:00Z".into(),
        expires_at: "2026-11-01T00:00:00Z".into(),
        pi_version: "1.2.0".into(),
        node_version: "22.19.0".into(),
        title: "candidate".into(),
        notes: "inputs only".into(),
        target: "linux_x86_64".into(),
        installer_policy: Some(PiInstallerDiscoveryPolicy {
            consumer_requirement: ">=0.1.0".into(),
            required_contracts: PiRequiredContractsV1::from_json(
                &serde_json::to_vec(&contracts["required_contracts"]).unwrap(),
            )
            .unwrap(),
        }),
    }
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
    let pi_url = format!(
        "https://registry.npmjs.org/@earendil-works/pi-coding-agent/-/pi-coding-agent-{pi_version}.tgz"
    );
    let upstream = format!("https://github.com/earendil-works/pi/releases/download/v{pi_version}");
    let mut dep_manifest = json!({"name":"dep","version":"1.0.0"});
    if mutation == "empty-dependency-map" {
        dep_manifest["dependencies"] = json!({});
    }
    if mutation == "null-dependency-map" {
        dep_manifest["dependencies"] = Value::Null;
    }
    if matches!(
        mutation,
        "required-platform-pruned"
            | "shared-upgrade-pruned"
            | "false-optional-pruned"
            | "shared-required-pruned"
            | "valid-optional-pruned"
            | "optional-parent-required-child-pruned"
    ) {
        dep_manifest["os"] = json!(["darwin"]);
    }
    let mut pi_manifest = json!({"name":PI,"version":pi_version,"bin":{"pi":"dist/start.js"},"dependencies":{"dep":"^1.0.0"},"engines":{"node":">=22.19.0"}});
    if matches!(
        mutation,
        "shared-required-pruned"
            | "shared-required-applicable"
            | "valid-optional-pruned"
            | "valid-optional-applicable"
            | "optional-parent-required-child-pruned"
    ) {
        pi_manifest.as_object_mut().unwrap().remove("dependencies");
        pi_manifest["optionalDependencies"] = if mutation == "optional-parent-required-child-pruned"
        {
            json!({"bridge":"1.0.0"})
        } else {
            json!({"dep":"^1.0.0"})
        };
    }
    if mutation == "optional-overlap" {
        pi_manifest["dependencies"]["dep"] = json!("^2.0.0");
        pi_manifest["optionalDependencies"] = json!({"dep":"^1.0.0"});
    }
    if mutation == "optional-overlap-effective-mismatch" {
        pi_manifest["optionalDependencies"] = json!({"dep":"^2.0.0"});
    }
    if mutation == "outside-range-root-overrides" {
        pi_manifest["dependencies"]["dep"] = json!("^2.0.0");
    }
    if mutation == "unsupported-engine" {
        pi_manifest["engines"]["node"] = json!(">=23");
    }
    if mutation == "partial-upper-engine" {
        pi_manifest["engines"]["node"] = json!("<=22");
    }
    if mutation == "undeclared-archive-dependency" {
        pi_manifest["dependencies"]["other"] = json!("1.0.0");
    }
    let dep_archive = gzip(&tar(&[TarEntry::file(
        "package/package.json",
        &serde_json::to_vec(&dep_manifest).unwrap(),
    )]));
    let mut entries = vec![
        TarEntry::file(
            "package/package.json",
            &serde_json::to_vec(&pi_manifest).unwrap(),
        ),
        TarEntry::file("package/dist/start.js", b"cli"),
    ];
    if mutation == "unsafe-archive" {
        entries.push(TarEntry::file("../escape", b"bad"));
    }
    let pi_archive = gzip(&tar(&entries));
    let mut root = json!({"name":"@earendil-works/pi-coding-agent-install","version":"7.0.0","private":true,"dependencies":{PI:pi_version},"engines":{"node":">=22.19.0"}});
    if matches!(
        mutation,
        "larger-graph" | "two-version-graph" | "mixed-version-root-overrides"
    ) {
        root["dependencies"]["extra"] = json!("1.0.0");
    }
    if matches!(
        mutation,
        "shared-required-pruned" | "shared-required-applicable"
    ) {
        root["dependencies"]["dep"] = json!("^1.0.0");
    }
    if matches!(
        mutation,
        "shared-upgrade-pruned" | "shared-upgrade-applicable"
    ) {
        root["optionalDependencies"] = json!({"dep":"^1.0.0"});
    }
    if mutation == "root-overrides" {
        root["overrides"] = json!({"dep":"2.0.0"});
    }
    if matches!(
        mutation,
        "valid-root-overrides"
            | "equal-lock-overrides"
            | "conflicting-lock-root-overrides"
            | "conflicting-top-lock-overrides"
            | "outside-range-root-overrides"
            | "mixed-version-root-overrides"
    ) {
        root["overrides"] = json!({"dep":"1.0.0"});
    }
    if mutation == "unused-root-overrides" {
        root["overrides"] = json!({"absent":"1.0.0"});
    }
    if mutation == "range-root-overrides" {
        root["overrides"] = json!({"dep":"^1.0.0"});
    }
    if mutation == "nested-root-overrides" {
        root["overrides"] = json!({"dep":{".":"1.0.0"}});
    }
    if mutation == "selector-root-overrides" {
        root["overrides"] = json!({"dep@^1":"1.0.0"});
    }
    if mutation == "reference-root-overrides" {
        root["overrides"] = json!({"dep":"$dep"});
    }
    if mutation == "oversized-root-overrides" {
        root["overrides"] = Value::Object(
            (0..513)
                .map(|i| (format!("dep{i}"), json!("1.0.0")))
                .collect(),
        );
    }
    if mutation == "empty-root-overrides" {
        root["overrides"] = json!({});
    }
    if mutation == "null-root-overrides" {
        root["overrides"] = Value::Null;
    }
    let mut lock = json!({"name":root["name"],"version":"7.0.0","lockfileVersion":3,"requires":true,"packages":{"":root.clone(),"node_modules/@earendil-works/pi-coding-agent":{"version":pi_version,"resolved":pi_url,"integrity":sri(&pi_archive),"dependencies":{"dep":"^1.0.0"}},"node_modules/dep":{"version":"1.0.0","resolved":DEP_URL}}});
    if pi_manifest.get("optionalDependencies").is_some() {
        let pi_lock = lock["packages"]["node_modules/@earendil-works/pi-coding-agent"]
            .as_object_mut()
            .unwrap();
        if !mutation.starts_with("optional-overlap") {
            pi_lock.remove("dependencies");
        }
        pi_lock.insert(
            "optionalDependencies".into(),
            pi_manifest["optionalDependencies"].clone(),
        );
    }
    if matches!(
        mutation,
        "optional-overlap" | "optional-overlap-effective-mismatch" | "outside-range-root-overrides"
    ) {
        lock["packages"]["node_modules/@earendil-works/pi-coding-agent"]["dependencies"] =
            pi_manifest["dependencies"].clone();
    }
    if matches!(
        mutation,
        "false-optional-pruned"
            | "optional-overlap"
            | "optional-overlap-effective-mismatch"
            | "shared-upgrade-pruned"
            | "false-optional-applicable"
            | "shared-required-pruned"
            | "valid-optional-pruned"
            | "valid-optional-applicable"
            | "optional-parent-required-child-pruned"
    ) {
        lock["packages"]["node_modules/dep"]["optional"] = json!(true);
    }
    if mutation == "valid-root-overrides" {
        lock["packages"][""]
            .as_object_mut()
            .unwrap()
            .remove("overrides");
    }
    if mutation == "conflicting-lock-root-overrides" {
        lock["packages"][""]["overrides"] = json!({"dep":"2.0.0"});
    }
    if mutation == "conflicting-top-lock-overrides" {
        lock["overrides"] = json!({"dep":"2.0.0"});
    }
    if mutation == "lock-root-overrides" {
        lock["packages"][""]["overrides"] = json!({"dep":"2.0.0"});
    }
    if mutation == "equal-lock-overrides" {
        lock["overrides"] = root["overrides"].clone();
    }
    if mutation == "top-lock-overrides" {
        lock["overrides"] = json!({"dep":"2.0.0"});
    }
    if mutation == "unsupported-lock" {
        lock["lockfileVersion"] = json!(2);
    }
    if mutation == "wrong-root" {
        lock["name"] = json!(PI);
    }
    if mutation == "extra-graph-node" {
        lock["packages"]["node_modules/extra"] = json!({"version":"1.0.0","resolved":DEP_URL});
    }
    if mutation == "missing-dependency" {
        lock["packages"]
            .as_object_mut()
            .unwrap()
            .remove("node_modules/dep");
    }
    if mutation == "dependency-version-mismatch" {
        lock["packages"]["node_modules/@earendil-works/pi-coding-agent"]["dependencies"]["dep"] =
            json!("2.0.0");
    }
    let mut metadata = json!({"name":"dep","version":"1.0.0","dist":{"tarball":DEP_URL,"integrity":sri(&dep_archive)}});
    if mutation == "missing-registry-integrity" {
        metadata["dist"]
            .as_object_mut()
            .unwrap()
            .remove("integrity");
    }
    if mutation == "substituted-registry-version" {
        metadata["version"] = json!("1.0.1");
    }
    if mutation == "substituted-registry-url" {
        metadata["dist"]["tarball"] = json!("https://registry.npmjs.org/other/-/other-1.0.0.tgz");
    }
    if mutation == "mismatched-integrity" {
        metadata["dist"]["integrity"] = json!(sri(b"bad"));
    }
    let node_root = "node-v22.19.0-linux-x64";
    let node = xz(&tar(&[
        TarEntry::directory(node_root),
        TarEntry::file(&format!("{node_root}/bin/node"), b"node"),
        TarEntry::file(
            &format!("{node_root}/lib/node_modules/corepack/dist/corepack.js"),
            b"corepack",
        ),
        TarEntry::file(
            &format!("{node_root}/lib/node_modules/npm/bin/npm-cli.js"),
            b"npm",
        ),
        TarEntry::file(
            &format!("{node_root}/lib/node_modules/npm/bin/npx-cli.js"),
            b"npx",
        ),
        TarEntry::symlink(
            &format!("{node_root}/bin/corepack"),
            "../lib/node_modules/corepack/dist/corepack.js",
        ),
        TarEntry::symlink(
            &format!("{node_root}/bin/npm"),
            "../lib/node_modules/npm/bin/npm-cli.js",
        ),
        TarEntry::symlink(
            &format!("{node_root}/bin/npx"),
            "../lib/node_modules/npm/bin/npx-cli.js",
        ),
    ]));
    let pi_metadata = json!({"name": if mutation == "scoped-substituted-name" {"@other/substitution"} else {PI}, "version":pi_version,"dist":{"tarball":pi_url,"integrity":sri(&pi_archive)}});
    if matches!(
        mutation,
        "scoped-missing-integrity" | "scoped-substituted-name"
    ) {
        lock["packages"]["node_modules/@earendil-works/pi-coding-agent"]
            .as_object_mut()
            .unwrap()
            .remove("integrity");
    }
    let mut responses = BTreeMap::from([
        (
            format!("{upstream}/pi-coding-agent-install-package.json"),
            serde_json::to_vec(&root).unwrap(),
        ),
        (
            format!("{upstream}/pi-coding-agent-install-package-lock.json"),
            serde_json::to_vec(&lock).unwrap(),
        ),
        (pi_url.into(), pi_archive),
        (DEP_URL.into(), dep_archive),
        (
            "https://registry.npmjs.org/dep/1.0.0".into(),
            serde_json::to_vec(&metadata).unwrap(),
        ),
        (
            "https://nodejs.org/dist/v22.19.0/SHASUMS256.txt".into(),
            format!("{}  node-v22.19.0-linux-x64.tar.xz\n", sha256(&node)).into_bytes(),
        ),
        (
            "https://nodejs.org/dist/v22.19.0/node-v22.19.0-linux-x64.tar.xz".into(),
            node,
        ),
    ]);
    if matches!(
        mutation,
        "scoped-missing-integrity" | "scoped-substituted-name"
    ) {
        responses.insert(
            format!("https://registry.npmjs.org/%40earendil-works%2Fpi-coding-agent/{pi_version}"),
            serde_json::to_vec(&pi_metadata).unwrap(),
        );
    }
    if mutation == "optional-parent-required-child-pruned" {
        let url = "https://registry.npmjs.org/bridge/-/bridge-1.0.0.tgz";
        let archive = gzip(&tar(&[TarEntry::file(
            "package/package.json",
            br#"{"name":"bridge","version":"1.0.0","dependencies":{"dep":"^1.0.0"}}"#,
        )]));
        lock["packages"]["node_modules/bridge"] = json!({"version":"1.0.0","resolved":url,"integrity":sri(&archive),"dependencies":{"dep":"^1.0.0"},"optional":true});
        responses.insert(
            format!("{upstream}/pi-coding-agent-install-package-lock.json"),
            serde_json::to_vec(&lock).unwrap(),
        );
        responses.insert(url.into(), archive);
    }
    if matches!(
        mutation,
        "two-version-graph" | "mixed-version-root-overrides"
    ) {
        let url = "https://registry.npmjs.org/extra/-/extra-1.0.0.tgz";
        let archive = gzip(&tar(&[TarEntry::file(
            "package/package.json",
            br#"{"name":"extra","version":"1.0.0","dependencies":{"dep":"^1.0.0"}}"#,
        )]));
        lock["packages"]["node_modules/extra"] = json!({"version":"1.0.0","resolved":url,"integrity":sri(&archive),"dependencies":{"dep":"^1.0.0"}});
        let nested_url = "https://registry.npmjs.org/dep/-/dep-1.0.1.tgz";
        let nested = gzip(&tar(&[TarEntry::file(
            "package/package.json",
            br#"{"name":"dep","version":"1.0.1"}"#,
        )]));
        lock["packages"]["node_modules/extra/node_modules/dep"] =
            json!({"version":"1.0.1","resolved":nested_url,"integrity":sri(&nested)});
        responses.insert(
            format!("{upstream}/pi-coding-agent-install-package-lock.json"),
            serde_json::to_vec(&lock).unwrap(),
        );
        responses.insert(url.into(), archive);
        responses.insert(nested_url.into(), nested);
    }
    if mutation == "larger-graph" {
        let url = "https://registry.npmjs.org/extra/-/extra-1.0.0.tgz";
        let archive = gzip(&tar(&[TarEntry::file(
            "package/package.json",
            br#"{"name":"extra","version":"1.0.0"}"#,
        )]));
        lock["packages"]["node_modules/extra"] =
            json!({"version":"1.0.0","resolved":url,"integrity":sri(&archive)});
        responses.insert(
            format!("{upstream}/pi-coding-agent-install-package-lock.json"),
            serde_json::to_vec(&lock).unwrap(),
        );
        responses.insert(url.into(), archive);
    }
    Transport(responses)
}

struct TarEntry {
    path: String,
    data: Vec<u8>,
    kind: u8,
    target: String,
}

impl TarEntry {
    fn file(path: &str, data: &[u8]) -> Self {
        Self {
            path: path.to_owned(),
            data: data.to_vec(),
            kind: b'0',
            target: String::new(),
        }
    }
    fn directory(path: &str) -> Self {
        Self {
            path: path.to_owned(),
            data: Vec::new(),
            kind: b'5',
            target: String::new(),
        }
    }
    fn symlink(path: &str, target: &str) -> Self {
        Self {
            path: path.to_owned(),
            data: Vec::new(),
            kind: b'2',
            target: target.to_owned(),
        }
    }
}

fn tar(entries: &[TarEntry]) -> Vec<u8> {
    let mut output = Vec::new();
    for entry in entries {
        let mut header = [0_u8; 512];
        header[..entry.path.len()].copy_from_slice(entry.path.as_bytes());
        write_octal(&mut header[100..108], 0o644);
        write_octal(&mut header[108..116], 0);
        write_octal(&mut header[116..124], 0);
        write_octal(&mut header[124..136], entry.data.len() as u64);
        write_octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = entry.kind;
        header[157..157 + entry.target.len()].copy_from_slice(entry.target.as_bytes());
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum = header.iter().map(|byte| u64::from(*byte)).sum::<u64>();
        header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
        output.extend_from_slice(&header);
        output.extend_from_slice(&entry.data);
        output.resize(output.len().div_ceil(512) * 512, 0);
    }
    output.resize(output.len() + 1024, 0);
    output
}

fn write_octal(field: &mut [u8], value: u64) {
    let width = field.len() - 1;
    field.fill(0);
    field[..width].copy_from_slice(format!("{value:0width$o}").as_bytes());
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut output = GzEncoder::new(Vec::new(), Compression::default());
    output.write_all(bytes).unwrap();
    output.finish().unwrap()
}

fn xz(bytes: &[u8]) -> Vec<u8> {
    let mut output = XzEncoder::new(Vec::new(), 6);
    output.write_all(bytes).unwrap();
    output.finish().unwrap()
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn sri(bytes: &[u8]) -> String {
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
    )
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
