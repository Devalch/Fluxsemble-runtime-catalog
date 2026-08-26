use catalog_core::{CatalogPayloadV1, canonical_catalog_payload, catalog_payload_sha256};

#[test]
fn canonical_payload_matches_the_frozen_consumer_digest() {
    let payload = CatalogPayloadV1::from_json(include_bytes!(
        "../../../conformance/catalog-v1/valid-payload.json"
    ))
    .unwrap();
    assert_eq!(
        hex::encode(catalog_payload_sha256(&payload).unwrap()),
        "a0eab9ad1e9741f8cf8cac9968d8d20cddcbee58e237ed7581202b2268488e5c"
    );
}

#[test]
fn canonicalization_is_stable_across_json_member_order_and_whitespace() {
    let original = include_bytes!("../../../conformance/catalog-v1/valid-payload.json");
    let value: serde_json::Value = serde_json::from_slice(original).unwrap();
    let reordered = serde_json::to_vec(&value).unwrap();
    let first = CatalogPayloadV1::from_json(original).unwrap();
    let second = CatalogPayloadV1::from_json(&reordered).unwrap();
    assert_eq!(
        canonical_catalog_payload(&first).unwrap(),
        canonical_catalog_payload(&second).unwrap()
    );
}
