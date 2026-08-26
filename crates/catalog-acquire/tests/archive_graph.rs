use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::Engine as _;
use catalog_acquire::{
    NpmGraphRequest, PackageInputManifestV1, VerifiedArchive, discover_package_inputs,
    verify_node_archive_shape, verify_npm_archive_shape, verify_npm_graph,
};
use catalog_core::InitialPiReleaseIntentV1;
use flate2::{Compression, write::GzEncoder};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256, Sha512};
use xz2::write::XzEncoder;

const PRUNED: [(&str, &[&str]); 9] = [
    (
        "node_modules/@mariozechner/clipboard-darwin-arm64",
        &["declaration.cpu", "declaration.os", "lock.cpu", "lock.os"],
    ),
    (
        "node_modules/@mariozechner/clipboard-darwin-universal",
        &["declaration.os", "lock.os"],
    ),
    (
        "node_modules/@mariozechner/clipboard-darwin-x64",
        &["declaration.os", "lock.os"],
    ),
    (
        "node_modules/@mariozechner/clipboard-linux-arm64-gnu",
        &["declaration.cpu", "lock.cpu"],
    ),
    (
        "node_modules/@mariozechner/clipboard-linux-arm64-musl",
        &["declaration.cpu", "declaration.libc", "lock.cpu"],
    ),
    (
        "node_modules/@mariozechner/clipboard-linux-riscv64-gnu",
        &["declaration.cpu", "lock.cpu"],
    ),
    (
        "node_modules/@mariozechner/clipboard-linux-x64-musl",
        &["declaration.libc"],
    ),
    (
        "node_modules/@mariozechner/clipboard-win32-arm64-msvc",
        &["declaration.cpu", "declaration.os", "lock.cpu", "lock.os"],
    ),
    (
        "node_modules/@mariozechner/clipboard-win32-x64-msvc",
        &["declaration.os", "lock.os"],
    ),
];
const MISSING: [&str; 3] = [
    "node_modules/@earendil-works/pi-agent-core",
    "node_modules/@earendil-works/pi-ai",
    "node_modules/@earendil-works/pi-tui",
];

#[test]
fn exact_initial_graph_requires_root_plus_139_locked_archives() {
    let fixture = GraphFixture::new();
    let verified = verify_npm_graph(fixture.request()).unwrap();
    assert_eq!(verified.root_package_count(), 1);
    assert_eq!(verified.locked_package_count(), 139);
    assert_eq!(verified.total_archive_count(), 140);
}

#[test]
fn graph_rejects_manifest_lock_archive_and_platform_mutations() {
    let mut fixture = GraphFixture::new();
    fixture.locked.swap(0, 1);
    assert!(
        verify_npm_graph(fixture.request()).is_err(),
        "archive substitution"
    );

    let fixture = GraphFixture::new();
    let mut manifest: Value =
        serde_json::from_slice(&fixture.inputs.canonical_bytes().unwrap()).unwrap();
    manifest["root"]["archive_member_count"] = Value::from(999_u64);
    let mutated =
        PackageInputManifestV1::from_json(&serde_json::to_vec(&manifest).unwrap()).unwrap();
    assert!(
        verify_npm_graph(fixture.request_with_inputs(mutated)).is_err(),
        "manifest mutation"
    );

    let fixture = GraphFixture::new();
    let mut manifest: Value =
        serde_json::from_slice(&fixture.inputs.canonical_bytes().unwrap()).unwrap();
    manifest["applicable_package_count"] = Value::from(131_u64);
    assert!(PackageInputManifestV1::from_json(&serde_json::to_vec(&manifest).unwrap()).is_err());
}

#[test]
fn tar_readers_reject_unsafe_and_unsupported_entries() {
    for entries in [
        vec![TarEntry::file("../escape", b"{}")],
        vec![TarEntry::file("/absolute", b"{}")],
        vec![
            TarEntry::file("package/package.json", b"{}"),
            TarEntry::file("package/package.json", b"{}"),
        ],
        vec![TarEntry::link("package/package.json", "target")],
        vec![TarEntry::hardlink("package/package.json", "package/target")],
        vec![TarEntry::special("package/device", b'3')],
        vec![TarEntry::special("package/fifo", b'6')],
        vec![TarEntry::special("package/sparse", b'S')],
        vec![
            TarEntry::file("first/package.json", b"{}"),
            TarEntry::file("second/member", b"x"),
        ],
    ] {
        let bytes = gzip(&tar(&entries));
        let mut archive = verified(
            bytes,
            "https://registry.npmjs.org/test/-/test-1.0.0.tgz",
            None,
        );
        assert!(verify_npm_archive_shape(&mut archive, false).is_err());
    }
}

#[test]
fn transitive_npm_shape_accepts_one_safe_custom_root_and_one_exact_dot_alias() {
    let declaration = br#"{"name":"custom","version":"1.0.0"}"#;
    let bytes = gzip(&tar(&[
        TarEntry::directory("custom-root"),
        TarEntry::file("custom-root/package.json", declaration),
        TarEntry::file("custom-root/dist/index.js", b"same"),
        TarEntry::file("custom-root/./dist/index.js", b"same"),
    ]));
    let mut archive = verified(
        bytes,
        "https://registry.npmjs.org/custom/-/custom-1.0.0.tgz",
        None,
    );
    assert_eq!(verify_npm_archive_shape(&mut archive, false).unwrap(), 4);

    let bytes = gzip(&tar(&[
        TarEntry::file("custom-root/package.json", declaration),
        TarEntry::file("custom-root/dist/index.js", b"first"),
        TarEntry::file("custom-root/./dist/index.js", b"different"),
    ]));
    let mut archive = verified(
        bytes,
        "https://registry.npmjs.org/custom/-/custom-1.0.0.tgz",
        None,
    );
    assert!(verify_npm_archive_shape(&mut archive, false).is_err());
}

#[test]
fn exact_node_links_are_inert_and_every_mutation_is_rejected() {
    let valid = node_archive(NodeMutation::None);
    let mut archive = verified(
        valid,
        "https://nodejs.org/dist/v22.19.0/node-v22.19.0-linux-x64.tar.xz",
        None,
    );
    assert_eq!(verify_node_archive_shape(&mut archive).unwrap(), 5_780);
    for mutation in [
        NodeMutation::WrongTarget,
        NodeMutation::AbsoluteTarget,
        NodeMutation::ParentEscape,
        NodeMutation::MissingTarget,
        NodeMutation::TargetDirectory,
        NodeMutation::Hardlink,
        NodeMutation::MissingLink,
        NodeMutation::ExtraLink,
    ] {
        let mut archive = verified(
            node_archive(mutation),
            "https://nodejs.org/dist/v22.19.0/node-v22.19.0-linux-x64.tar.xz",
            None,
        );
        assert!(
            verify_node_archive_shape(&mut archive).is_err(),
            "{mutation:?}"
        );
    }
}

struct GraphFixture {
    intent: InitialPiReleaseIntentV1,
    node: VerifiedArchive,
    root: VerifiedArchive,
    locked: Vec<VerifiedArchive>,
    inputs: PackageInputManifestV1,
}

impl GraphFixture {
    fn new() -> Self {
        let mut locators = BTreeSet::new();
        locators.extend(PRUNED.iter().map(|(locator, _)| (*locator).to_owned()));
        locators.extend(MISSING.iter().map(|locator| (*locator).to_owned()));
        let mut index = 0;
        while locators.len() < 139 {
            locators.insert(format!("node_modules/package-{index:03}"));
            index += 1;
        }
        let mut locked = Vec::new();
        let mut locked_records = Vec::new();
        let mut lock_packages = Map::new();
        lock_packages.insert(
            "".into(),
            json!({"name":"@earendil-works/pi-coding-agent","version":"0.83.0"}),
        );
        for locator in locators {
            let name = locator.rsplit("node_modules/").next().unwrap().to_owned();
            let declaration_selectors = selectors(&locator, "declaration");
            let mut declaration = Map::from_iter([
                ("name".into(), Value::String(name.clone())),
                ("version".into(), Value::String("1.0.0".into())),
            ]);
            declaration.extend(declaration_selectors);
            let declaration = serde_json::to_vec(&Value::Object(declaration)).unwrap();
            let bytes = gzip(&tar(&[TarEntry::file(
                "package/package.json",
                &declaration,
            )]));
            let digest = sha256(&bytes);
            let integrity = sri(&bytes);
            let encoded_name = name.replace('@', "").replace('/', "-");
            let url =
                format!("https://registry.npmjs.org/{encoded_name}/-/{encoded_name}-1.0.0.tgz");
            let mut lock = Map::from_iter([
                ("version".into(), Value::String("1.0.0".into())),
                ("resolved".into(), Value::String(url.clone())),
            ]);
            if !MISSING.contains(&locator.as_str()) {
                lock.insert("integrity".into(), Value::String(integrity.clone()));
            }
            lock.extend(selectors(&locator, "lock"));
            if PRUNED.iter().any(|(expected, _)| *expected == locator) {
                lock.insert("optional".into(), Value::Bool(true));
            }
            lock_packages.insert(locator.clone(), Value::Object(lock));
            locked_records.push(json!({
                "locator": locator,
                "name": name,
                "version": "1.0.0",
                "resolved_url": url,
                "registry_integrity": integrity,
                "archive_sha256": digest,
            }));
            locked.push(verified(bytes, &url, Some(&integrity)));
        }
        let root_manifest = serde_json::to_vec(&json!({
            "name":"@earendil-works/pi-coding-agent","version":"0.83.0","bin":{"pi":"dist/cli.js"}
        }))
        .unwrap();
        let shrinkwrap = serde_json::to_vec(&json!({
            "name":"@earendil-works/pi-coding-agent","version":"0.83.0","lockfileVersion":3,"requires":true,"packages":lock_packages
        })).unwrap();
        let root_bytes = gzip(&tar(&[
            TarEntry::file("package/package.json", &root_manifest),
            TarEntry::file("package/npm-shrinkwrap.json", &shrinkwrap),
            TarEntry::file("package/dist/cli.js", b"entry"),
        ]));
        let root_digest = sha256(&root_bytes);
        let root_integrity = sri(&root_bytes);
        let node_bytes = node_archive(NodeMutation::None);
        let node_digest = sha256(&node_bytes);
        let intent_json = json!({
            "sequence":"1","tag":"catalog-v1-sequence-1","generated_at":"2026-08-26T00:00:00Z","expires_at":"2026-09-26T00:00:00Z","fluxsemble_requirement":"=0.1.0",
            "release":{"provider":"builtin:pi","allowed_origins":["https://nodejs.org","https://registry.npmjs.org"],"release":{
                "version":"0.83.0","target":"linux_x86_64","compatibility_ranges":["=0.1.0"],"release_metadata":{"title":"Pi","notes":"fixture"},
                "components":[
                    {"component_id":"component:node","version":"22.19.0","artifacts":[{"artifact_id":"artifact:node","url":"https://nodejs.org/dist/v22.19.0/node-v22.19.0-linux-x64.tar.xz","size_bytes":node_bytes.len().to_string(),"sha256":node_digest,"inventory":[]}]},
                    {"component_id":"component:pi","version":"0.83.0","artifacts":[{"artifact_id":"artifact:pi","url":"https://registry.npmjs.org/pi/-/pi-0.83.0.tgz","size_bytes":root_bytes.len().to_string(),"sha256":root_digest,"inventory":[{"path":"dist/cli.js","size_bytes":"5","sha256":sha256(b"entry")}]}]}
                ],
                "provider_extension":{"kind":"pi","metadata":{
                    "approved_package":{"name":"@earendil-works/pi-coding-agent","version":"0.83.0"},"expected_entrypoint":"dist/cli.js","component_id":"component:pi","package_artifact_id":"artifact:pi","registry_integrity":root_integrity,
                    "root_package_manifest":{"url":"https://registry.npmjs.org/support/package.json","size_bytes":root_manifest.len().to_string(),"sha256":sha256(&root_manifest)},
                    "shipped_shrinkwrap":{"lockfile_version":3,"root_package":{"name":"@earendil-works/pi-coding-agent","version":"0.83.0"},"artifact":{"url":"https://registry.npmjs.org/support/npm-shrinkwrap.json","size_bytes":shrinkwrap.len().to_string(),"sha256":sha256(&shrinkwrap)},"locked_packages":locked_records}
                }}
            }}
        });
        let intent =
            InitialPiReleaseIntentV1::from_json(&serde_json::to_vec(&intent_json).unwrap())
                .unwrap();
        let mut root = verified(
            root_bytes,
            "https://registry.npmjs.org/pi/-/pi-0.83.0.tgz",
            Some(&root_integrity),
        );
        let mut locked_for_discovery = locked;
        let inputs =
            discover_package_inputs(&intent, &mut root, &mut locked_for_discovery).unwrap();
        Self {
            intent,
            node: verified(
                node_bytes,
                "https://nodejs.org/dist/v22.19.0/node-v22.19.0-linux-x64.tar.xz",
                None,
            ),
            root,
            locked: locked_for_discovery,
            inputs,
        }
    }

    fn request(self) -> NpmGraphRequest {
        let inputs = self.inputs.clone();
        self.request_with_inputs(inputs)
    }

    fn request_with_inputs(self, package_inputs: PackageInputManifestV1) -> NpmGraphRequest {
        NpmGraphRequest {
            intent: self.intent,
            node_archive: self.node,
            root_archive: self.root,
            locked_archives: self.locked,
            package_inputs,
        }
    }
}

fn selectors(locator: &str, source: &str) -> Map<String, Value> {
    let mut result = Map::new();
    let Some((_, reasons)) = PRUNED.iter().find(|(expected, _)| *expected == locator) else {
        return result;
    };
    for reason in *reasons {
        let Some(field) = reason.strip_prefix(&format!("{source}.")) else {
            continue;
        };
        let value = match field {
            "os" => "darwin",
            "cpu" => "arm64",
            "libc" => "musl",
            _ => unreachable!(),
        };
        result.insert(field.into(), Value::String(value.into()));
    }
    result
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeMutation {
    None,
    WrongTarget,
    AbsoluteTarget,
    ParentEscape,
    MissingTarget,
    TargetDirectory,
    Hardlink,
    MissingLink,
    ExtraLink,
}

fn node_archive(mutation: NodeMutation) -> Vec<u8> {
    let root = "node-v22.19.0-linux-x64";
    let targets = [
        (
            format!("{root}/lib/node_modules/corepack/dist/corepack.js"),
            "corepack",
        ),
        (format!("{root}/lib/node_modules/npm/bin/npm-cli.js"), "npm"),
        (format!("{root}/lib/node_modules/npm/bin/npx-cli.js"), "npx"),
    ];
    let mut entries = vec![TarEntry::directory(&format!("{root}/"))];
    for (index, (path, bytes)) in targets.iter().enumerate() {
        if mutation == NodeMutation::MissingTarget && index == 0 {
            continue;
        }
        if mutation == NodeMutation::TargetDirectory && index == 0 {
            entries.push(TarEntry::directory(path));
        } else {
            entries.push(TarEntry::file(path, bytes.as_bytes()));
        }
    }
    let links = [
        (
            format!("{root}/bin/corepack"),
            "../lib/node_modules/corepack/dist/corepack.js",
        ),
        (
            format!("{root}/bin/npm"),
            "../lib/node_modules/npm/bin/npm-cli.js",
        ),
        (
            format!("{root}/bin/npx"),
            "../lib/node_modules/npm/bin/npx-cli.js",
        ),
    ];
    for (index, (path, target)) in links.iter().enumerate() {
        if mutation == NodeMutation::MissingLink && index == 0 {
            continue;
        }
        let target = if index == 0 {
            match mutation {
                NodeMutation::WrongTarget => "../wrong",
                NodeMutation::AbsoluteTarget => "/absolute",
                NodeMutation::ParentEscape => "../../../escape",
                _ => target,
            }
        } else {
            target
        };
        if mutation == NodeMutation::Hardlink && index == 0 {
            entries.push(TarEntry {
                path: path.clone(),
                data: vec![],
                kind: b'1',
                link: target.into(),
            });
        } else {
            entries.push(TarEntry::link(path, target));
        }
    }
    if mutation == NodeMutation::ExtraLink {
        entries.push(TarEntry::link(
            &format!("{root}/bin/extra"),
            "../lib/node_modules/npm/bin/npm-cli.js",
        ));
    }
    while entries.len() < 5_780 {
        let index = entries.len();
        entries.push(TarEntry::file(
            &format!("{root}/share/filler-{index:04}"),
            b"x",
        ));
    }
    xz(&tar(&entries))
}

#[derive(Clone)]
struct TarEntry {
    path: String,
    data: Vec<u8>,
    kind: u8,
    link: String,
}
impl TarEntry {
    fn file(path: &str, data: &[u8]) -> Self {
        Self {
            path: path.into(),
            data: data.into(),
            kind: b'0',
            link: String::new(),
        }
    }
    fn directory(path: &str) -> Self {
        Self {
            path: path.trim_end_matches('/').into(),
            data: vec![],
            kind: b'5',
            link: String::new(),
        }
    }
    fn link(path: &str, target: &str) -> Self {
        Self {
            path: path.into(),
            data: vec![],
            kind: b'2',
            link: target.into(),
        }
    }
    fn hardlink(path: &str, target: &str) -> Self {
        Self {
            path: path.into(),
            data: vec![],
            kind: b'1',
            link: target.into(),
        }
    }
    fn special(path: &str, kind: u8) -> Self {
        Self {
            path: path.into(),
            data: vec![],
            kind,
            link: String::new(),
        }
    }
}

fn tar(entries: &[TarEntry]) -> Vec<u8> {
    let mut output = Vec::new();
    for entry in entries {
        let mut header = [0_u8; 512];
        let bytes = entry.path.as_bytes();
        assert!(bytes.len() <= 100);
        header[..bytes.len()].copy_from_slice(bytes);
        write_octal(&mut header[100..108], 0o644);
        write_octal(&mut header[108..116], 0);
        write_octal(&mut header[116..124], 0);
        write_octal(&mut header[124..136], entry.data.len() as u64);
        write_octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = entry.kind;
        header[157..157 + entry.link.len()].copy_from_slice(entry.link.as_bytes());
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
        let checksum_text = format!("{checksum:06o}\0 ");
        header[148..156].copy_from_slice(checksum_text.as_bytes());
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
    let text = format!("{value:0width$o}");
    field[..width].copy_from_slice(text.as_bytes());
}
fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut out = GzEncoder::new(Vec::new(), Compression::default());
    out.write_all(bytes).unwrap();
    out.finish().unwrap()
}
fn xz(bytes: &[u8]) -> Vec<u8> {
    let mut out = XzEncoder::new(Vec::new(), 6);
    out.write_all(bytes).unwrap();
    out.finish().unwrap()
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
fn verified(bytes: Vec<u8>, url: &str, sri_value: Option<&str>) -> VerifiedArchive {
    let path = temp_file();
    fs::write(&path, &bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    let file = fs::File::open(&path).unwrap();
    let archive = VerifiedArchive::verify(
        file,
        url.into(),
        bytes.len() as u64,
        sha256(&bytes),
        sri_value.map(str::to_owned),
    )
    .unwrap();
    fs::remove_file(path).unwrap();
    archive
}
fn temp_file() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("catalog-archive-{}-{nanos}", std::process::id()))
}
