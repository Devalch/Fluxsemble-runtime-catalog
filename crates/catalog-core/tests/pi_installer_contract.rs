use catalog_core::{
    PiInstallerLockMetadataV1, PiReleaseProfileV1, PiReleaseQualificationV1,
    pi_release_subject_sha256,
};
use serde_json::{Value, json};
const ROOT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/catalog/pi-installer-v1/"
);
fn bytes(name: &str) -> Vec<u8> {
    std::fs::read(format!("{ROOT}{name}.json")).unwrap()
}
fn profile() -> Value {
    serde_json::from_slice(&bytes("valid-wrapper-root")).unwrap()
}
fn parse(value: &Value) -> PiReleaseProfileV1 {
    PiReleaseProfileV1::from_json(&serde_json::to_vec(value).unwrap()).unwrap()
}
fn subject(value: &Value) -> [u8; 32] {
    pi_release_subject_sha256(&parse(value)).unwrap()
}
#[test]
fn installer_profile_subject_binds_inputs_without_qualification_cycle() {
    let p = profile();
    assert_eq!(subject(&p), subject(&p));
    assert_eq!(
        hex::encode(subject(&p)),
        std::fs::read_to_string(format!("{ROOT}subject.sha256"))
            .unwrap()
            .trim()
    );
    let mut other = p.clone();
    other["components"][1]["artifacts"][0]["sha256"] = json!("6".repeat(64));
    other["locked_packages"][0]["archive_sha256"] = json!("6".repeat(64));
    assert_ne!(subject(&p), subject(&other));
    assert!(PiReleaseProfileV1::from_json(&bytes("pi-root-substituted-for-wrapper")).is_err());
    let mut metadata: Value = serde_json::from_slice(&bytes("valid-metadata")).unwrap();
    let a = PiInstallerLockMetadataV1::from_json(&serde_json::to_vec(&metadata).unwrap()).unwrap();
    metadata["qualification"]["sha256"] = json!("7".repeat(64));
    let b = PiInstallerLockMetadataV1::from_json(&serde_json::to_vec(&metadata).unwrap()).unwrap();
    assert_eq!(
        pi_release_subject_sha256(a.profile()).unwrap(),
        pi_release_subject_sha256(b.profile()).unwrap()
    );
    metadata.as_object_mut().unwrap().remove("qualification");
    assert!(PiInstallerLockMetadataV1::from_json(&serde_json::to_vec(&metadata).unwrap()).is_err());
}
#[test]
fn strict_profile_rejects_unbound_or_unsafe_inputs() {
    for name in [
        "unsafe-path",
        "wrong-locator-identity",
        "unknown-contract",
        "duplicate-field",
    ] {
        assert!(
            PiReleaseProfileV1::from_json(&bytes(name)).is_err(),
            "{name}"
        );
    }
    for (pointer, value) in [
        ("/unexpected", json!(1)),
        ("/installer_manifest/url", json!("http://example.com/a")),
        ("/installer_lock/size_bytes", json!("0")),
        ("/pi_package/version", json!("1.3.0")),
        ("/components/0/version", json!("22.20.0")),
        ("/locked_packages/0/name", json!("other")),
        ("/required_contracts/unknown", json!(1)),
    ] {
        let mut p = profile();
        if let Some(slot) = p.pointer_mut(pointer) {
            *slot = value;
        } else {
            let (parent, key) = pointer.rsplit_once('/').unwrap();
            p.pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(key.into(), value);
        }
        assert!(
            PiReleaseProfileV1::from_json(&serde_json::to_vec(&p).unwrap()).is_err(),
            "{pointer}"
        );
    }
    let mut oversized = bytes("valid-wrapper-root");
    oversized.resize(2 * 1024 * 1024 + 1, b' ');
    assert!(PiReleaseProfileV1::from_json(&oversized).is_err());
    let mut p = profile();
    p["locked_packages"] = json!(vec![p["locked_packages"][0].clone(); 513]);
    assert!(PiReleaseProfileV1::from_json(&serde_json::to_vec(&p).unwrap()).is_err());
}
#[test]
fn security_relevant_profile_changes_alter_subject() {
    let p = profile();
    let expected = subject(&p);
    for (pointer, value) in [
        ("/consumer_requirement", json!(">=0.2.0")),
        ("/installer_root/version", json!("2.0.0")),
        ("/installer_manifest/sha256", json!("9".repeat(64))),
        ("/installer_lock/sha256", json!("9".repeat(64))),
        ("/pi_manifest/sha256", json!("9".repeat(64))),
        ("/components/0/artifacts/0/sha256", json!("9".repeat(64))),
        (
            "/required_contracts/resource_policy_sha256",
            json!("9".repeat(64)),
        ),
        (
            "/required_contracts/tool_policy_sha256",
            json!("9".repeat(64)),
        ),
        (
            "/required_contracts/execution_policy_sha256",
            json!("9".repeat(64)),
        ),
    ] {
        let mut changed = p.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert_ne!(subject(&changed), expected, "{pointer}");
    }
}
#[test]
fn qualification_is_bounded_complete_typed_evidence_only() {
    let mut q: Value = serde_json::from_slice(&bytes("valid-qualification")).unwrap();
    let parse = |q: &Value| PiReleaseQualificationV1::from_json(&serde_json::to_vec(q).unwrap());
    assert!(parse(&q).unwrap().is_complete_pass());
    q["results"]["lifecycle"] = json!("fail");
    assert!(!parse(&q).unwrap().is_complete_pass());
    q["results"]["lifecycle"] = json!("skip");
    assert!(parse(&q).is_err());
    q["results"].as_object_mut().unwrap().remove("lifecycle");
    assert!(parse(&q).is_err());
    let mut oversized = bytes("valid-qualification");
    oversized.resize(64 * 1024 + 1, b' ');
    assert!(PiReleaseQualificationV1::from_json(&oversized).is_err());
    let duplicate = String::from_utf8(bytes("valid-qualification"))
        .unwrap()
        .replace(
            "\"schema_version\": 1",
            "\"schema_version\": 1, \"schema_version\": 1",
        );
    assert!(PiReleaseQualificationV1::from_json(duplicate.as_bytes()).is_err());
}
#[test]
fn admitted_vectors_match_frozen_manifest() {
    use sha2::{Digest, Sha256};
    let manifest = std::fs::read(format!("{ROOT}manifest.json")).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&manifest)),
        std::fs::read_to_string(format!("{ROOT}manifest.sha256"))
            .unwrap()
            .trim()
    );
    let files: std::collections::BTreeMap<String, String> =
        serde_json::from_slice(&manifest).unwrap();
    for (name, sha) in files {
        assert_eq!(
            hex::encode(Sha256::digest(
                std::fs::read(format!("{ROOT}{name}")).unwrap()
            )),
            sha,
            "{name}"
        );
    }
}

fn catalog() -> Value {
    let p = profile();
    json!({"schema_version":1,"sequence":"1","generated_at":"2026-10-15T00:00:00Z","expires_at":"2026-10-16T00:00:00Z","compatibility_ranges":[">=0.1.0"],"providers":[{"provider_id":"builtin:pi","allowed_origins":["https://example.com"],"releases":[{"version":"1.2.0","target":"linux_x86_64","compatibility_ranges":[">=0.1.0"],"release_metadata":{"title":"Synthetic installer vector","notes":"No release qualification"},"components":p["components"],"provider_extension":{"kind":"pi_installer_lock_v1","metadata":serde_json::from_slice::<Value>(&bytes("valid-metadata")).unwrap()}}]}]})
}
#[test]
fn catalog_extension_binds_outer_release_and_origin_authority() {
    use catalog_core::{CatalogPayloadV1, ProviderExtensionV1};
    let parse = |v: &Value| CatalogPayloadV1::from_json(&serde_json::to_vec(v).unwrap());
    let c = catalog();
    let parsed = parse(&c).unwrap();
    assert!(matches!(
        parsed.providers()[0].releases()[0].provider_extension(),
        ProviderExtensionV1::PiInstallerLock(_)
    ));

    for (pointer, value) in [
        ("/providers/0/provider_id", json!("builtin:other")),
        (
            "/providers/0/allowed_origins",
            json!(["https://other.example.com"]),
        ),
        ("/providers/0/releases/0/version", json!("1.3.0")),
        (
            "/providers/0/releases/0/components/0/artifacts/0/sha256",
            json!("8".repeat(64)),
        ),
        (
            "/providers/0/releases/0/provider_extension/metadata/qualification/url",
            json!("https://other.example.com/qualification.json"),
        ),
    ] {
        let mut changed = c.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(parse(&changed).is_err(), "{pointer}");
    }
    let original = serde_json::to_string(&c).unwrap();
    for (old, new) in [
        (
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
        ),
        (
            "\"installer_policy\":1",
            "\"installer_policy\":1,\"installer_policy\":1",
        ),
    ] {
        assert!(CatalogPayloadV1::from_json(original.replace(old, new).as_bytes()).is_err());
    }
}
#[test]
fn later_release_is_structurally_decodable_without_reference_allowlist() {
    let mut p = profile();
    for pointer in [
        "/pi_package/version",
        "/locked_packages/0/version",
        "/components/1/version",
    ] {
        *p.pointer_mut(pointer).unwrap() = json!("1.3.0");
    }
    assert_ne!(subject(&p), subject(&profile()));
}
#[test]
fn nested_unknown_fields_bad_locators_and_qualification_fail_closed() {
    for pointer in [
        "/pi_package",
        "/installer_root",
        "/installer_manifest",
        "/installer_lock",
        "/pi_manifest",
        "/components/0",
        "/components/0/artifacts/0",
        "/components/0/artifacts/0/inventory/0",
        "/locked_packages/0",
        "/required_contracts",
    ] {
        let mut p = profile();
        p.pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unknown".into(), json!(1));
        assert!(
            PiReleaseProfileV1::from_json(&serde_json::to_vec(&p).unwrap()).is_err(),
            "{pointer}"
        );
    }
    let mut p = profile();
    let mut dep = p["locked_packages"][0].clone();
    dep["name"] = json!("other");
    dep["locator"] = json!("node_modules/parent/garbage/node_modules/other");
    p["locked_packages"].as_array_mut().unwrap().push(dep);
    assert!(PiReleaseProfileV1::from_json(&serde_json::to_vec(&p).unwrap()).is_err());
    let q: Value = serde_json::from_slice(&bytes("valid-qualification")).unwrap();
    for (pointer, value) in [
        ("/schema_version", json!(2)),
        ("/release_subject_sha256", json!("xyz")),
        ("/verification_build/implementation_commit", json!("HEAD")),
        (
            "/verification_build/compatibility_profile_id",
            json!("unknown"),
        ),
        ("/required_contracts/pi_rpc", json!(99)),
    ] {
        let mut q = q.clone();
        *q.pointer_mut(pointer).unwrap() = value;
        assert!(
            PiReleaseQualificationV1::from_json(&serde_json::to_vec(&q).unwrap()).is_err(),
            "{pointer}"
        );
    }
}

#[test]
fn qualified_graph_count_is_bounded_independently_of_uniqueness() {
    let mut p = profile();
    let mut records = vec![p["locked_packages"][0].clone()];
    for i in 0..511 {
        let mut record = records[0].clone();
        record["name"] = json!(format!("dep{i:03}"));
        record["locator"] = json!(format!("node_modules/dep{i:03}"));
        records.push(record);
    }
    p["locked_packages"] = json!(records);
    parse(&p);
    let mut excess = p["locked_packages"][0].clone();
    excess["name"] = json!("dep511");
    excess["locator"] = json!("node_modules/dep511");
    p["locked_packages"].as_array_mut().unwrap().push(excess);
    assert!(PiReleaseProfileV1::from_json(&serde_json::to_vec(&p).unwrap()).is_err());
    p["locked_packages"].as_array_mut().unwrap().pop();
    p["locked_packages"].as_array_mut().unwrap().swap(1, 2);
    assert!(PiReleaseProfileV1::from_json(&serde_json::to_vec(&p).unwrap()).is_err());
}

#[test]
fn subject_binds_every_descriptor_field_and_coupled_identity() {
    let p = profile();
    let expected = subject(&p);
    for descriptor in [
        "/installer_manifest",
        "/installer_lock",
        "/pi_manifest",
        "/components/0/artifacts/0",
    ] {
        for (field, value) in [
            ("url", json!("https://example.com/changed")),
            ("size_bytes", json!("2")),
            ("sha256", json!("8".repeat(64))),
        ] {
            let mut changed = p.clone();
            changed.pointer_mut(descriptor).unwrap()[field] = value;
            assert_ne!(subject(&changed), expected, "{descriptor}/{field}");
        }
    }
    let cases: Vec<Vec<(&str, Value)>> = vec![
        vec![
            ("/node_version", json!("22.20.0")),
            ("/components/0/version", json!("22.20.0")),
        ],
        vec![("/installer_root/name", json!("other-installer"))],
        vec![
            ("/cli_entrypoint", json!("other/cli.js")),
            (
                "/components/1/artifacts/0/inventory/0/path",
                json!("other/cli.js"),
            ),
        ],
        vec![
            (
                "/registry_integrity",
                json!(format!("sha512-{}==", "B".repeat(85) + "A")),
            ),
            (
                "/locked_packages/0/registry_integrity",
                json!(format!("sha512-{}==", "B".repeat(85) + "A")),
            ),
        ],
        vec![
            (
                "/components/1/artifacts/0/url",
                json!("https://example.com/other.tgz"),
            ),
            (
                "/locked_packages/0/resolved_url",
                json!("https://example.com/other.tgz"),
            ),
        ],
        vec![("/components/1/artifacts/0/size_bytes", json!("2"))],
        vec![(
            "/components/1/artifacts/0/inventory/0/size_bytes",
            json!("2"),
        )],
        vec![(
            "/components/1/artifacts/0/inventory/0/sha256",
            json!("9".repeat(64)),
        )],
        vec![
            ("/pi_component_id", json!("builtin:pi-other")),
            ("/components/1/component_id", json!("builtin:pi-other")),
        ],
        vec![
            ("/pi_artifact_id", json!("builtin:pi:other")),
            (
                "/components/1/artifacts/0/artifact_id",
                json!("builtin:pi:other"),
            ),
        ],
        vec![
            ("/node_component_id", json!("builtin:node-other")),
            ("/components/0/component_id", json!("builtin:node-other")),
        ],
        vec![
            ("/node_artifact_id", json!("builtin:node:other")),
            (
                "/components/0/artifacts/0/artifact_id",
                json!("builtin:node:other"),
            ),
        ],
    ];
    for changes in cases {
        let mut changed = p.clone();
        for (pointer, value) in changes {
            *changed.pointer_mut(pointer).unwrap() = value;
        }
        assert_ne!(subject(&changed), expected);
    }
}
