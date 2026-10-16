#![cfg(feature = "fixture-tools")]
//! Explicit immutable public DATA transfer; no sibling checkout code or runtime dependency.
use catalog_core::{
    PiReleaseQualificationV1, ProviderExtensionV1, verify_fixture_signed_catalog,
    verify_pi_release_qualification, verify_signed_catalog,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::Read;

const ROOT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../conformance/pi-consumer-v1/"
);
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn consumer_sha() -> String {
    let mut file = std::fs::File::open(std::env::current_exe().unwrap()).unwrap();
    let mut digest = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let count = file.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    hex::encode(digest.finalize())
}
fn data(name: &str) -> Vec<u8> {
    std::fs::read(format!("{ROOT}{name}")).unwrap()
}

#[test]
fn same_consumer_verifies_independent_transferred_a_and_b_qualification_bindings() {
    let before = consumer_sha();
    let reference = sha(&data("reference.json"));
    let supported = include_bytes!("../../../resources/pi/supported-contracts-v1.json");
    let contracts: Value = serde_json::from_slice(supported).unwrap();
    let manifest: Value = serde_json::from_slice(&data("manifest.json")).unwrap();
    for entry in manifest["entries"].as_array().unwrap() {
        let bytes = data(entry["path"].as_str().unwrap());
        assert_eq!(bytes.len() as u64, entry["size"].as_u64().unwrap());
        assert_eq!(sha(&bytes), entry["sha256"]);
    }
    let mut subjects = Vec::new();
    let mut builds = Vec::new();
    for (name, version) in [("a", "1.2.0"), ("b", "1.2.1")] {
        let envelope = data(&format!("{name}-envelope.json"));
        let qualification = data(&format!("{name}-qualification.json"));
        assert!(
            verify_signed_catalog(&envelope).is_err(),
            "fixture identity cannot become production trust"
        );
        let catalog = verify_fixture_signed_catalog(&envelope).unwrap();
        let release = &catalog.payload().providers()[0].releases()[0];
        let ProviderExtensionV1::PiInstallerLock(metadata) = release.provider_extension() else {
            panic!("installer lock required")
        };
        assert_eq!(metadata.profile().pi_package().version().as_str(), version);
        assert_eq!(
            serde_json::to_value(metadata.profile().required_contracts()).unwrap(),
            contracts["required_contracts"]
        );
        assert_eq!(
            sha(&qualification),
            metadata.qualification().sha256().as_str()
        );
        assert_eq!(
            qualification.len() as u64,
            metadata.qualification().size_bytes().get()
        );
        let q = PiReleaseQualificationV1::from_json(&qualification).unwrap();
        verify_pi_release_qualification(metadata.profile(), &q).unwrap();
        let wire: Value = serde_json::from_slice(&qualification).unwrap();
        subjects.push(wire["release_subject_sha256"].clone());
        builds.push(wire["verification_build"].clone());
        let other = data(&format!(
            "{}-qualification.json",
            if name == "a" { "b" } else { "a" }
        ));
        assert!(
            verify_pi_release_qualification(
                metadata.profile(),
                &PiReleaseQualificationV1::from_json(&other).unwrap()
            )
            .is_err()
        );
        let mut failed = wire;
        failed["results"]["lifecycle"] = serde_json::json!("fail");
        assert!(
            verify_pi_release_qualification(
                metadata.profile(),
                &PiReleaseQualificationV1::from_json(&serde_json::to_vec(&failed).unwrap())
                    .unwrap()
            )
            .is_err()
        );
    }
    assert_ne!(subjects[0], subjects[1]);
    assert_eq!(builds[0], builds[1]);
    assert_eq!(before, consumer_sha());
    assert_eq!(reference, sha(&data("reference.json")));
    assert_eq!(
        sha(supported),
        sha(&std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../resources/pi/supported-contracts-v1.json"
        ))
        .unwrap())
    );
    println!(
        "independent conformance consumer={before}; reference={reference}; contracts={}",
        sha(supported)
    );
}

#[test]
fn current_consumer_material_preserves_exact_backends_and_production_public_trust() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/pi-current-consumer-v1");
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(root.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(
        manifest["evidence_kind"],
        "immutable-public-consumer-material-not-qualification"
    );
    assert_eq!(
        manifest["artifact_set_sha256"],
        "16d38d760f2053b512fc4dab396fd73458beb19e339e8aaa29182da2d658ebdb"
    );
    assert_eq!(manifest["files"].as_array().unwrap().len(), 6);
    for row in manifest["files"].as_array().unwrap() {
        let name = row["path"].as_str().unwrap();
        assert!(!name.contains('/') && !name.contains(".."));
        let bytes = std::fs::read(root.join(name)).unwrap();
        assert_eq!(bytes.len().to_string(), row["size_bytes"].as_str().unwrap());
        assert_eq!(sha(&bytes), row["sha256"].as_str().unwrap());
    }
    let read = |name| -> Value {
        serde_json::from_slice(&std::fs::read(root.join(name)).unwrap()).unwrap()
    };
    let anchor = read("production-trust-anchor.json");
    let key = catalog_core::production_keyring()
        .verification_identity(anchor["key_id"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        key.public_key_base64url(),
        anchor["public_key_base64url"].as_str().unwrap()
    );
    assert_eq!(
        sha(key.public_key_bytes()),
        "d1a64e2d55c8e5d82fc22ef440d039396c7cca1cf6ac4e369e58ff4c91ae143a"
    );
    assert_eq!(
        sha(&std::fs::read(root.join("runtime-manifest.json")).unwrap()),
        "072c4b53f369dac914084574c1f2f1b2ddbebcde2c0bd801bcf021c8325b229d"
    );
    assert_eq!(
        read("native-backend-receipt.json")["artifactSha256"],
        "7baf3c8abb730f40656eac7a998fbecb98fcbd686bbacf8864d22830ea2b020e"
    );
    assert_eq!(
        read("execution-backend-receipt.json")["payloads"][0]["sha256"],
        "11495a48fb5b21626bac7de8795d4a7093d30eb0c69252cad5418e3214c1a66d"
    );
}
