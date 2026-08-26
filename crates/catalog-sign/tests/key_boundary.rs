use std::fs;

#[test]
fn committed_key_is_only_a_nonproduction_pkcs8_fixture() {
    let bytes = include_bytes!("fixtures/nonproduction-ed25519-pkcs8.pem");
    assert!(bytes.starts_with(b"-----BEGIN PRIVATE KEY-----\n"));
    assert!(bytes.ends_with(b"-----END PRIVATE KEY-----\n"));
    assert!(!bytes.windows(7).any(|window| window == b"OPENSSH"));
    assert!(!bytes.windows(9).any(|window| window == b"ENCRYPTED"));
}

#[test]
fn key_reader_is_private_and_production_cli_has_no_fixture_authority() {
    let key_source =
        fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/key.rs")).unwrap();
    let main_source = include_str!("../src/main.rs");
    assert!(key_source.contains("fn read_signing_key("));
    assert!(!key_source.contains("pub fn read_signing_key("));
    assert!(main_source.contains("production_key_identity"));
    assert!(!main_source.contains("catalog-test-key-v1"));
    assert!(!main_source.contains("fixture-tools"));
}
