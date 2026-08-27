#![cfg(feature = "fixture-tools")]

use catalog_core::{
    CatalogPayloadV1, canonical_catalog_payload, verify_fixture_signed_catalog,
    verify_signed_catalog,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;

const FIXTURE_KEY_ID: &str = "catalog-test-key-v1";
const FLUX_FIXTURE_PUBLIC_KEY: [u8; 32] = [
    0x03, 0xa1, 0x07, 0xbf, 0xf3, 0xce, 0x10, 0xbe, 0x1d, 0x70, 0xdd, 0x18, 0xe7, 0x4b, 0xc0, 0x99,
    0x67, 0xe4, 0xd6, 0x30, 0x9b, 0xa5, 0x0d, 0x5f, 0x1d, 0xdc, 0x86, 0x64, 0x12, 0x55, 0x31, 0xb8,
];
const OLD_PRODUCER_PUBLIC_KEY: [u8; 32] = [
    0x1b, 0xd3, 0x6a, 0xfe, 0xe9, 0x32, 0x3f, 0x1e, 0x38, 0x13, 0xf6, 0x8c, 0x4d, 0x5f, 0x2f, 0x2b,
    0x1b, 0xae, 0x44, 0xc0, 0xef, 0x69, 0x17, 0x62, 0x8e, 0xd6, 0xaf, 0xe1, 0x6a, 0xae, 0x44, 0xa9,
];

const INITIAL_ENVELOPE: &[u8] =
    include_bytes!("../../../conformance/catalog-v1/initial-exact-candidate-envelope.json");
const VALID_ENVELOPE: &[u8] = include_bytes!("../../../conformance/catalog-v1/valid-envelope.json");

#[test]
fn conformance_envelopes_use_the_shared_flux_fixture_identity() {
    for envelope in [INITIAL_ENVELOPE, VALID_ENVELOPE] {
        verify_fixture_signed_catalog(envelope).expect("producer fixture verifier");
        verify_with_pinned_identity(envelope, FIXTURE_KEY_ID, &FLUX_FIXTURE_PUBLIC_KEY)
            .expect("independent Flux-pinned verifier");
        assert!(verify_signed_catalog(envelope).is_err());
        assert!(
            verify_with_pinned_identity(envelope, FIXTURE_KEY_ID, &OLD_PRODUCER_PUBLIC_KEY)
                .is_err()
        );
    }
}

#[test]
fn fixture_key_id_and_public_key_cannot_be_changed_independently() {
    let mut envelope: Value = serde_json::from_slice(VALID_ENVELOPE).unwrap();
    envelope["key_id"] = Value::String("catalog-test-key-v2".to_owned());
    let wrong_id = serde_jcs::to_vec(&envelope).unwrap();

    assert!(verify_fixture_signed_catalog(&wrong_id).is_err());
    assert!(
        verify_with_pinned_identity(&wrong_id, FIXTURE_KEY_ID, &FLUX_FIXTURE_PUBLIC_KEY).is_err()
    );
    assert!(
        verify_with_pinned_identity(VALID_ENVELOPE, FIXTURE_KEY_ID, &OLD_PRODUCER_PUBLIC_KEY)
            .is_err()
    );
}

fn verify_with_pinned_identity(
    envelope_bytes: &[u8],
    expected_key_id: &str,
    public_key: &[u8; 32],
) -> Result<(), ()> {
    let envelope: Value = serde_json::from_slice(envelope_bytes).map_err(|_| ())?;
    if envelope["key_id"] != expected_key_id {
        return Err(());
    }
    let payload =
        CatalogPayloadV1::from_json(&serde_json::to_vec(&envelope["payload"]).map_err(|_| ())?)
            .map_err(|_| ())?;
    let signature_text = envelope["signature"].as_str().ok_or(())?;
    let signature = Signature::from_bytes(&decode_signature(signature_text).ok_or(())?);
    VerifyingKey::from_bytes(public_key)
        .map_err(|_| ())?
        .verify_strict(
            &canonical_catalog_payload(&payload).map_err(|_| ())?,
            &signature,
        )
        .map_err(|_| ())
}

fn decode_signature(value: &str) -> Option<[u8; 64]> {
    if value.len() != 86 || value.contains('=') {
        return None;
    }
    let decode = |byte| match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    };
    let mut output = [0_u8; 64];
    let mut index = 0;
    for chunk in value.as_bytes().chunks(4) {
        let a = decode(chunk[0])?;
        let b = decode(chunk[1])?;
        output[index] = (a << 2) | (b >> 4);
        index += 1;
        if chunk.len() >= 3 {
            let c = decode(chunk[2])?;
            output[index] = (b << 4) | (c >> 2);
            index += 1;
            if chunk.len() == 4 {
                let d = decode(chunk[3])?;
                output[index] = (c << 6) | d;
                index += 1;
            } else if c & 0x03 != 0 {
                return None;
            }
        }
    }
    (index == output.len()).then_some(output)
}
