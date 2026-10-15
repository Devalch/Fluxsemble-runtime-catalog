#![allow(dead_code)]
// Shared bounded synthetic archive fixtures; no verification logic is duplicated here.
use base64::Engine as _;
use catalog_core::PiRequiredContractsV1;
use catalog_installer_verify::{DiscoverPiReleaseRequest, PiInstallerDiscoveryPolicy};
use flate2::{Compression, write::GzEncoder};
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha512};
use std::{collections::BTreeMap, io::Write};
use xz2::write::XzEncoder;
const PI: &str = "@earendil-works/pi-coding-agent";
const DEP_URL: &str = "https://registry.npmjs.org/dep/-/dep-1.0.0.tgz";
pub fn request() -> DiscoverPiReleaseRequest {
    let contracts: Value = serde_json::from_slice(include_bytes!(
        "../../../../resources/pi/supported-contracts-v1.json"
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
pub fn fixture_bytes(mutation: &str, pi_version: &str) -> BTreeMap<String, Vec<u8>> {
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
    responses
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

pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn sri(bytes: &[u8]) -> String {
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
    )
}

pub fn transferred_fixture() -> (
    catalog_core::PiReleaseIntentV2,
    catalog_installer_verify::PackageInputManifestV2,
    BTreeMap<String, Vec<u8>>,
) {
    struct Bytes(BTreeMap<String, Vec<u8>>);
    impl catalog_installer_verify::InstallerInputs for Bytes {
        fn read(
            &self,
            url: &str,
            maximum: usize,
        ) -> Result<Vec<u8>, catalog_installer_verify::AcquireError> {
            self.0
                .get(url)
                .filter(|b| b.len() <= maximum)
                .cloned()
                .ok_or(catalog_installer_verify::AcquireError::Input)
        }
    }
    let bytes = Bytes(fixture_bytes(
        "matching-missing-integrity-supplement",
        "1.2.0",
    ));
    let candidate = catalog_installer_verify::derive_installer_release(request(), &bytes).unwrap();
    let intent = catalog_core::PiReleaseIntentV2::from_json(&serde_jcs::to_vec(&json!({
        "schema_version": 2, "sequence": "9", "tag": "catalog-v1-sequence-9",
        "generated_at": "2026-10-01T00:00:00Z", "expires_at": "2026-11-01T00:00:00Z",
        "title": "Bounded synthetic archives", "notes": "No real release qualification", "profile": candidate.profile,
    })).unwrap()).unwrap();
    let mut objects = BTreeMap::new();
    for (original, descriptor) in [
        (
            candidate.inputs.installer_manifest_source(),
            intent.profile().installer_manifest(),
        ),
        (
            candidate.inputs.installer_lock_source(),
            intent.profile().installer_lock(),
        ),
    ] {
        objects.insert(
            descriptor.url().as_str().into(),
            bytes.0[original.url()].clone(),
        );
    }
    for auxiliary in candidate.inputs.auxiliary_inputs() {
        objects.insert(auxiliary.url().into(), bytes.0[auxiliary.url()].clone());
    }
    for artifact in intent
        .profile()
        .components()
        .iter()
        .flat_map(|c| c.artifacts())
    {
        objects.insert(
            artifact.url().as_str().into(),
            bytes.0[artifact.url().as_str()].clone(),
        );
    }
    for package in intent.profile().locked_packages() {
        objects.insert(
            package.resolved_url().as_str().into(),
            bytes.0[package.resolved_url().as_str()].clone(),
        );
    }
    let pi = intent
        .profile()
        .locked_packages()
        .iter()
        .find(|p| p.locator() == intent.profile().pi_package_locator())
        .unwrap();
    let pi_bytes = &bytes.0[pi.resolved_url().as_str()];
    let mut archive = catalog_installer_verify::archive::VerifiedArchive::verify(
        std::io::Cursor::new(pi_bytes),
        pi.resolved_url().as_str().into(),
        pi_bytes.len() as u64,
        sha256(pi_bytes),
        Some(pi.registry_integrity().as_str().into()),
    )
    .unwrap();
    let inspection =
        catalog_installer_verify::archive::inspect_npm_archive(&mut archive, false).unwrap();
    objects.insert(
        intent.profile().pi_manifest().url().as_str().into(),
        inspection.declaration,
    );
    (intent, candidate.inputs, objects)
}
