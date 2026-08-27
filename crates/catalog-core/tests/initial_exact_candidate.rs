use catalog_core::{
    CatalogPayloadV1, canonical_catalog_payload, catalog_payload_sha256, verify_signed_catalog,
};

const PAYLOAD: &[u8] =
    include_bytes!("../../../conformance/catalog-v1/initial-exact-candidate-payload.json");
const ENVELOPE: &[u8] =
    include_bytes!("../../../conformance/catalog-v1/initial-exact-candidate-envelope.json");

#[test]
fn initial_exact_candidate_is_canonical_and_not_production_signed() {
    let payload = CatalogPayloadV1::from_json(PAYLOAD).expect("exact candidate payload");
    assert_eq!(canonical_catalog_payload(&payload).unwrap(), PAYLOAD);
    assert_eq!(payload.sequence().get(), 1);
    assert_eq!(PAYLOAD.len(), 55_797);
    assert_eq!(
        hex::encode(catalog_payload_sha256(&payload).unwrap()),
        "7dba62c8b44883cbd7b3615fd9fe3b1a08a3aa2c75c7729704c14804d1cc2a2b"
    );
    assert!(verify_signed_catalog(ENVELOPE).is_err());
}

#[cfg(feature = "fixture-tools")]
#[test]
fn initial_exact_envelope_verifies_only_with_fixture_authority() {
    let verified = catalog_core::verify_fixture_signed_catalog(ENVELOPE)
        .expect("fixture-signed exact candidate");
    assert_eq!(verified.canonical_payload(), PAYLOAD);
    assert_eq!(verified.key_id(), "catalog-test-key-v1");
    assert!(verify_signed_catalog(ENVELOPE).is_err());
}
