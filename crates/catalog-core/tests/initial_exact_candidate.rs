// Genuine input conformance is inert: it carries no qualification or signature.
use catalog_core::{
    CatalogPayloadV1, PiReleaseIntentV2, canonical_catalog_payload, catalog_payload_sha256,
    pi_release_subject_sha256, verify_signed_catalog,
};
const PAYLOAD: &[u8] = include_bytes!("../../../conformance/catalog-v1/valid-payload.json");
const ENVELOPE: &[u8] = include_bytes!("../../../conformance/catalog-v1/valid-envelope.json");

#[test]
fn genuine_installer_intent_binds_the_independent_input_subject() {
    let bytes = include_bytes!(
        "../../../conformance/pi-installer-release-v1/generated/initial-release-intent-v2.json"
    );
    let intent = PiReleaseIntentV2::from_json(bytes).unwrap();
    assert_eq!(serde_jcs::to_vec(&intent).unwrap(), bytes);
    let inputs: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../conformance/pi-installer-release-v1/generated/package-input-manifest-v2.json"
    ))
    .unwrap();
    assert_eq!(
        hex::encode(pi_release_subject_sha256(intent.profile()).unwrap()),
        inputs["release_subject_sha256"]
    );
}

#[test]
fn synthetic_catalog_vector_is_canonical_and_not_production_signed() {
    let payload = CatalogPayloadV1::from_json(PAYLOAD).unwrap();
    let canonical = canonical_catalog_payload(&payload).unwrap();
    assert_eq!(canonical.len(), 2553);
    assert_eq!(
        hex::encode(catalog_payload_sha256(&payload).unwrap()),
        "a0eab9ad1e9741f8cf8cac9968d8d20cddcbee58e237ed7581202b2268488e5c"
    );
    assert!(verify_signed_catalog(ENVELOPE).is_err());
}

#[cfg(feature = "fixture-tools")]
#[test]
fn synthetic_envelope_verifies_only_with_fixture_authority() {
    let verified = catalog_core::verify_fixture_signed_catalog(ENVELOPE).unwrap();
    let payload = CatalogPayloadV1::from_json(PAYLOAD).unwrap();
    assert_eq!(
        verified.canonical_payload(),
        canonical_catalog_payload(&payload).unwrap()
    );
    assert_eq!(verified.key_id(), "catalog-test-key-v1");
    assert!(verify_signed_catalog(ENVELOPE).is_err());
}

#[test]
fn installer_vector_manifest_binds_exact_public_and_synthetic_data() {
    use sha2::{Digest, Sha256};
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/pi-installer-release-v1/vectors");
    let manifest_bytes = std::fs::read(root.join("manifest-v1.json")).unwrap();
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).unwrap();
    assert_eq!(serde_jcs::to_vec(&manifest).unwrap(), manifest_bytes);
    assert_eq!(
        manifest["evidence_kind"],
        "inert-installer-inputs-and-synthetic-catalog-vectors"
    );
    assert_eq!(
        manifest["input_admission"]["sha256"],
        "20b4402e9bedbb2c92caa2b04f4ee7552740c0c2ac2eb8c331c8e3f72f87db07"
    );
    let expected: [(&str, &[u8]); 5] = [
        (
            "initial-release-intent-v2.json",
            include_bytes!(
                "../../../conformance/pi-installer-release-v1/generated/initial-release-intent-v2.json"
            ),
        ),
        (
            "package-input-manifest-v2.json",
            include_bytes!(
                "../../../conformance/pi-installer-release-v1/generated/package-input-manifest-v2.json"
            ),
        ),
        (
            "rejected-fields.json",
            include_bytes!("../../../conformance/catalog-v1/rejected-fields.json"),
        ),
        ("valid-envelope.json", ENVELOPE),
        ("valid-payload.json", PAYLOAD),
    ];
    assert_eq!(
        manifest["entries"].as_array().unwrap().len(),
        expected.len()
    );
    assert_eq!(
        std::fs::read_dir(&root).unwrap().count(),
        expected.len() + 1
    );
    for (entry, (name, original)) in manifest["entries"].as_array().unwrap().iter().zip(expected) {
        assert_eq!(entry["path"], name);
        let copied = std::fs::read(root.join(name)).unwrap();
        assert_eq!(copied, original);
        assert_eq!(entry["size"], copied.len());
        assert_eq!(entry["sha256"], hex::encode(Sha256::digest(&copied)));
    }
}
