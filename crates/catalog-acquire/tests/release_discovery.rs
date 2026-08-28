use std::{collections::BTreeMap, io::Write};

use base64::Engine as _;
use catalog_acquire::{
    AcquireError, DiscoverPiReleaseRequest, ReleaseDiscoveryTransport,
    discover_pi_release_with_transport,
};
use flate2::{Compression, write::GzEncoder};
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha512};
use xz2::write::XzEncoder;

const PI_VERSION: &str = "0.84.0";
const NODE_VERSION: &str = "22.20.0";
const ROOT_URL: &str =
    "https://registry.npmjs.org/@earendil-works/pi-coding-agent/-/pi-coding-agent-0.84.0.tgz";
const PACKAGE_URL: &str = "https://registry.npmjs.org/package-a/-/package-a-1.0.0.tgz";
const OPTIONAL_URL: &str = "https://registry.npmjs.org/optional-darwin/-/optional-darwin-1.0.0.tgz";

#[test]
fn discovery_builds_a_coherent_intent_and_package_manifest() {
    let fixture = PublicReleaseFixture::new(Mutation::None);
    let discovered = fixture.discover(request()).unwrap();

    assert_eq!(discovered.intent.sequence().get(), 2);
    assert_eq!(
        discovered.intent.release().pi_version().as_str(),
        PI_VERSION
    );
    assert_eq!(discovered.package_inputs.root_version(), PI_VERSION);
    assert_eq!(discovered.package_inputs.locked_package_count(), 2);
}

#[test]
fn discovery_rejects_missing_package_version() {
    assert_closed_rejection(Mutation::MissingPackageVersion);
}

#[test]
fn discovery_rejects_mismatched_npm_integrity() {
    assert_closed_rejection(Mutation::MismatchedNpmIntegrity);
}

#[test]
fn discovery_rejects_wrong_node_checksum() {
    assert_closed_rejection(Mutation::WrongNodeChecksum);
}

#[test]
fn discovery_rejects_unsafe_archive_path() {
    assert_closed_rejection(Mutation::UnsafeArchivePath);
}

#[test]
fn discovery_rejects_shrinkwrap_root_mismatch() {
    assert_closed_rejection(Mutation::ShrinkwrapRootMismatch);
}

#[test]
fn discovery_rejects_unsupported_target_without_fetching() {
    let fixture = PublicReleaseFixture::new(Mutation::None);
    let mut request = request();
    request.target = "darwin_aarch64".to_owned();
    let error = fixture.discover(request).unwrap_err();
    assert_eq!(error, AcquireError::Input);
    assert_eq!(fixture.transport.fetch_count.get(), 0);
}

#[test]
fn package_manifest_rejects_intent_semantic_mismatch() {
    let fixture = PublicReleaseFixture::new(Mutation::None);
    let discovered = fixture.discover(request()).unwrap();
    let mut bytes: Value =
        serde_json::from_slice(&discovered.package_inputs.canonical_bytes().unwrap()).unwrap();
    bytes["root"]["version"] = Value::String("0.84.1".to_owned());
    let mismatched =
        catalog_acquire::PackageInputManifestV1::from_json(&serde_json::to_vec(&bytes).unwrap())
            .unwrap();

    assert_eq!(
        mismatched.validate_for_intent(&discovered.intent),
        Err(AcquireError::Graph)
    );
}

fn assert_closed_rejection(mutation: Mutation) {
    let fixture = PublicReleaseFixture::new(mutation);
    let error = fixture.discover(request()).unwrap_err();
    let rendered = format!("{error:?}");
    assert!(!rendered.contains("fixture-secret"));
    assert!(!rendered.contains('?'));
}

fn request() -> DiscoverPiReleaseRequest {
    DiscoverPiReleaseRequest {
        sequence: 2,
        generated_at: "2026-09-01T00:00:00Z".to_owned(),
        expires_at: "2026-10-01T00:00:00Z".to_owned(),
        pi_version: PI_VERSION.to_owned(),
        node_version: NODE_VERSION.to_owned(),
        title: "Pi 0.84.0".to_owned(),
        notes: "Approved managed Pi release.".to_owned(),
        target: "linux_x86_64".to_owned(),
    }
}

#[derive(Clone, Copy)]
enum Mutation {
    None,
    MissingPackageVersion,
    MismatchedNpmIntegrity,
    WrongNodeChecksum,
    UnsafeArchivePath,
    ShrinkwrapRootMismatch,
}

struct PublicReleaseFixture {
    transport: FixtureTransport,
}

impl PublicReleaseFixture {
    fn new(mutation: Mutation) -> Self {
        let package_archive = npm_archive("package-a", "1.0.0", &[], false);
        let optional_archive = npm_archive(
            "optional-darwin",
            "1.0.0",
            &[("os", Value::String("darwin".to_owned()))],
            false,
        );
        let package_integrity = sri(&package_archive);
        let optional_integrity = sri(&optional_archive);

        let package_lock = if matches!(mutation, Mutation::MissingPackageVersion) {
            json!({"resolved": PACKAGE_URL, "integrity": package_integrity})
        } else {
            json!({"version":"1.0.0", "resolved": PACKAGE_URL, "integrity": package_integrity})
        };
        let shrinkwrap_version = if matches!(mutation, Mutation::ShrinkwrapRootMismatch) {
            "0.84.1"
        } else {
            PI_VERSION
        };
        let shrinkwrap = serde_json::to_vec(&json!({
            "name":"@earendil-works/pi-coding-agent",
            "version":shrinkwrap_version,
            "lockfileVersion":3,
            "requires":true,
            "packages": {
                "": {
                    "name":"@earendil-works/pi-coding-agent",
                    "version":PI_VERSION,
                    "dependencies":{"package-a":"1.0.0"},
                    "optionalDependencies":{"optional-darwin":"1.0.0"}
                },
                "node_modules/package-a": package_lock,
                "node_modules/optional-darwin": {
                    "version":"1.0.0",
                    "resolved":OPTIONAL_URL,
                    "integrity":optional_integrity,
                    "optional":true,
                    "os":"darwin"
                }
            }
        }))
        .unwrap();
        let declaration = serde_json::to_vec(&json!({
            "name":"@earendil-works/pi-coding-agent",
            "version":PI_VERSION,
            "bin":{"pi":"dist/cli.js"}
        }))
        .unwrap();
        let mut root_entries = vec![
            TarEntry::file("package/package.json", &declaration),
            TarEntry::file("package/npm-shrinkwrap.json", &shrinkwrap),
            TarEntry::file("package/dist/cli.js", b"entrypoint"),
        ];
        if matches!(mutation, Mutation::UnsafeArchivePath) {
            root_entries.push(TarEntry::file("../fixture-secret?redirect=1", b"unsafe"));
        }
        let root_archive = gzip(&tar(&root_entries));
        let root_integrity = if matches!(mutation, Mutation::MismatchedNpmIntegrity) {
            format!("sha512-{}", "A".repeat(88))
        } else {
            sri(&root_archive)
        };

        let node_root = format!("node-v{NODE_VERSION}-linux-x64");
        let node_archive = xz(&tar(&[
            TarEntry::directory(&node_root),
            TarEntry::file(&format!("{node_root}/bin/node"), b"node-binary"),
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
        let checksum = if matches!(mutation, Mutation::WrongNodeChecksum) {
            "0".repeat(64)
        } else {
            sha256(&node_archive)
        };

        let mut responses = BTreeMap::new();
        responses.insert(
            format!("https://registry.npmjs.org/@earendil-works%2Fpi-coding-agent/{PI_VERSION}"),
            serde_json::to_vec(&json!({
                "name":"@earendil-works/pi-coding-agent",
                "version":PI_VERSION,
                "dist":{"tarball":ROOT_URL,"integrity":root_integrity}
            }))
            .unwrap(),
        );
        responses.insert(ROOT_URL.to_owned(), root_archive);
        responses.insert(PACKAGE_URL.to_owned(), package_archive);
        responses.insert(OPTIONAL_URL.to_owned(), optional_archive);
        responses.insert(
            format!("https://nodejs.org/dist/v{NODE_VERSION}/SHASUMS256.txt"),
            format!("{checksum}  node-v{NODE_VERSION}-linux-x64.tar.xz\n").into_bytes(),
        );
        responses.insert(
            format!(
                "https://nodejs.org/dist/v{NODE_VERSION}/node-v{NODE_VERSION}-linux-x64.tar.xz"
            ),
            node_archive,
        );
        Self {
            transport: FixtureTransport {
                responses,
                fetch_count: std::cell::Cell::new(0),
            },
        }
    }

    fn discover(
        &self,
        request: DiscoverPiReleaseRequest,
    ) -> Result<catalog_acquire::DiscoveredPiRelease, AcquireError> {
        discover_pi_release_with_transport(request, &self.transport)
    }
}

struct FixtureTransport {
    responses: BTreeMap<String, Vec<u8>>,
    fetch_count: std::cell::Cell<usize>,
}

impl ReleaseDiscoveryTransport for FixtureTransport {
    fn fetch(&self, url: &str, maximum_bytes: usize) -> Result<Vec<u8>, AcquireError> {
        self.fetch_count.set(self.fetch_count.get() + 1);
        self.responses
            .get(url)
            .filter(|bytes| bytes.len() <= maximum_bytes)
            .cloned()
            .ok_or(AcquireError::UnexpectedStatus)
    }
}

fn npm_archive(name: &str, version: &str, fields: &[(&str, Value)], root: bool) -> Vec<u8> {
    let mut declaration = serde_json::Map::from_iter([
        ("name".to_owned(), Value::String(name.to_owned())),
        ("version".to_owned(), Value::String(version.to_owned())),
    ]);
    declaration.extend(
        fields
            .iter()
            .map(|(name, value)| ((*name).to_owned(), value.clone())),
    );
    let declaration = serde_json::to_vec(&Value::Object(declaration)).unwrap();
    let entries = if root {
        unreachable!()
    } else {
        vec![TarEntry::file("package/package.json", &declaration)]
    };
    gzip(&tar(&entries))
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
