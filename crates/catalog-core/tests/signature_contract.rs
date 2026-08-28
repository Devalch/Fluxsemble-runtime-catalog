use catalog_core::{
    MAX_SIGNED_CATALOG_ENVELOPE_BYTES, active_production_key_identity,
    derive_runtime_catalog_key_id, production_keyring, verify_signed_catalog,
    verify_signed_release_bundle_manifest,
};

const PRODUCTION_KEY_ID: &str = "runtime-catalog-ed25519-d1a64e2d55c8e5d8";
const PRODUCTION_PUBLIC_KEY: &str = "t9wPqaH5olhFkcPEcH6QPHX9AsCcrwxiKdzQo8xjW2o";

#[test]
fn reviewed_keyring_has_exactly_one_active_signing_key() {
    let keyring = production_keyring();
    assert_eq!(
        keyring
            .entries()
            .iter()
            .filter(|entry| entry.is_active_for_signing())
            .count(),
        1
    );
    assert_eq!(keyring.schema_version(), 1);
    assert_eq!(keyring.sha256().len(), 64);
}

#[test]
fn compiled_active_identity_is_exact_and_self_derived() {
    let identity = active_production_key_identity();
    assert_eq!(identity.key_id(), PRODUCTION_KEY_ID);
    assert_eq!(identity.public_key_base64url(), PRODUCTION_PUBLIC_KEY);
    assert_eq!(identity.generation(), 1);
    assert_eq!(
        derive_runtime_catalog_key_id(identity.public_key_bytes()),
        PRODUCTION_KEY_ID
    );
}

#[test]
fn verification_lookup_is_separate_from_active_signing_identity() {
    let keyring = production_keyring();
    assert_eq!(
        keyring.verification_identity(PRODUCTION_KEY_ID),
        Some(active_production_key_identity())
    );
    assert!(
        keyring
            .verification_identity("runtime-catalog-ed25519-0000000000000000")
            .is_none()
    );
}

#[test]
fn signed_envelope_scanning_is_bounded_duplicate_free_and_non_echoing() {
    let payload = std::str::from_utf8(include_bytes!(
        "../../../conformance/catalog-v1/valid-payload.json"
    ))
    .unwrap();
    let signature = "A".repeat(86);
    let baseline = format!(
        "{{\"envelope_version\":1,\"signature_algorithm\":\"ed25519\",\"key_id\":\"{PRODUCTION_KEY_ID}\",\"payload\":{payload},\"signature\":\"{signature}\"}}"
    );
    assert!(verify_signed_catalog(baseline.as_bytes()).is_err());

    for malformed in [
        baseline.replacen("\"payload\":", "\"payload\":null,\"payload\":", 1),
        baseline.replacen("\"payload\":", "\"unknown\":0,\"payload\":", 1),
        format!("{baseline} trailing"),
    ] {
        let error = verify_signed_catalog(malformed.as_bytes()).unwrap_err();
        assert_eq!(error.to_string(), "invalid signed catalog");
        assert!(!error.to_string().contains(PRODUCTION_KEY_ID));
    }

    assert!(verify_signed_catalog(&vec![b' '; MAX_SIGNED_CATALOG_ENVELOPE_BYTES + 1]).is_err());
}

#[test]
fn release_bundle_verifier_rejects_catalog_domain_and_malformed_manifest_bytes() {
    let payload = include_bytes!("../../../conformance/catalog-v1/valid-payload.json");
    assert!(verify_signed_release_bundle_manifest(payload).is_err());
    assert!(verify_signed_release_bundle_manifest(br#"{"schema_version":1}"#).is_err());
}
