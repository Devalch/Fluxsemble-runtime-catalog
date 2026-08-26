use catalog_core::{
    BundleInventoryV1, CatalogPayloadV1, MAX_BUNDLE_OBJECT_BYTES, SignedReleaseBundleManifestV1,
    VerifiedInputBundleV1, bundle_inventory_digest, canonical_catalog_payload,
    release_bundle_domain_digest, release_bundle_signing_bytes, verified_input_bundle_digest,
    verify_signed_release_inventory,
};
use serde_json::{Value, json};

const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SHA_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const SHA_D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const COMMIT_A: &str = "0123456789abcdef0123456789abcdef01234567";
const COMMIT_B: &str = "89abcdef0123456789abcdef0123456789abcdef";

fn inventory_value(kind: &str) -> Value {
    let entries = match kind {
        "verified_input" => json!([
            {
                "relative_path": format!("objects/{SHA_A}"),
                "mode": "0400",
                "size": 7,
                "sha256": SHA_A
            },
            {
                "relative_path": "verified-input-bundle-v1.json",
                "mode": "0400",
                "size": 512,
                "sha256": SHA_B
            }
        ]),
        "signed_release" => json!([
            {
                "relative_path": "catalog-v1.json",
                "mode": "0400",
                "size": 1024,
                "sha256": SHA_A
            },
            {
                "relative_path": "checksums-sha256.txt",
                "mode": "0400",
                "size": 256,
                "sha256": SHA_B
            },
            {
                "relative_path": "signed-release-bundle-manifest-v1.json",
                "mode": "0400",
                "size": 768,
                "sha256": SHA_C
            }
        ]),
        _ => unreachable!(),
    };
    json!({"schema_version": 1, "kind": kind, "entries": entries})
}

fn signed_inventory_value() -> Value {
    json!({
        "schema_version": 1,
        "kind": "signed_release",
        "entries": [
            {
                "relative_path": "catalog-v1.json",
                "mode": "0400",
                "size": 1024,
                "sha256": SHA_C
            },
            {
                "relative_path": "checksums-sha256.txt",
                "mode": "0400",
                "size": 256,
                "sha256": SHA_D
            },
            {
                "relative_path": "package-manifest-a.json",
                "mode": "0400",
                "size": 512,
                "sha256": SHA_A
            },
            {
                "relative_path": "qualification-v1.json",
                "mode": "0400",
                "size": 768,
                "sha256": SHA_B
            },
            {
                "relative_path": "signed-release-bundle-manifest-v1.json",
                "mode": "0400",
                "size": 768,
                "sha256": SHA_D
            }
        ]
    })
}

fn verified_bundle_value() -> Value {
    json!({
        "schema_version": 1,
        "source_kind": "release_intent",
        "source_sha256": SHA_A,
        "compatibility_input_sha256": SHA_B,
        "objects": [
            {
                "relative_path": format!("objects/{SHA_C}"),
                "source_url": "https://registry.npmjs.org/example/-/example-1.0.0.tgz",
                "size": 7,
                "sha256": SHA_C
            }
        ]
    })
}

fn manifest_value() -> Value {
    json!({
        "schema_version": 1,
        "source_commit": COMMIT_A,
        "source_tree_sha256": SHA_A,
        "qualification_sha256": SHA_B,
        "tag": "catalog-v1-sequence-42",
        "catalog_envelope": {
            "name": "catalog-v1.json",
            "size": 1024,
            "sha256": SHA_C
        },
        "assets": [
            {
                "name": "package-manifest-a.json",
                "size": 512,
                "sha256": SHA_A
            },
            {
                "name": "qualification-v1.json",
                "size": 768,
                "sha256": SHA_B
            }
        ],
        "signature": {
            "key_id": "catalog-test-key-v1",
            "signature": "fixture-signature"
        }
    })
}

fn parse_inventory(value: &Value) -> BundleInventoryV1 {
    BundleInventoryV1::from_json(&serde_json::to_vec(value).unwrap()).unwrap()
}

fn parse_manifest(value: &Value) -> SignedReleaseBundleManifestV1 {
    SignedReleaseBundleManifestV1::from_json(&serde_json::to_vec(value).unwrap()).unwrap()
}

#[test]
fn bundle_inventory_is_sorted_normalized_bounded_regular_file_only_and_kind_complete() {
    for kind in ["verified_input", "signed_release"] {
        let value = inventory_value(kind);
        let inventory = parse_inventory(&value);
        assert_eq!(bundle_inventory_digest(&inventory).unwrap().len(), 32);
    }

    for path in [
        "",
        "/object",
        "../object",
        "a/../object",
        "a//object",
        "a\\object",
    ] {
        let mut mutation = inventory_value("verified_input");
        mutation["entries"][0]["relative_path"] = json!(path);
        assert!(BundleInventoryV1::from_json(&serde_json::to_vec(&mutation).unwrap()).is_err());
    }

    let mut duplicate = inventory_value("verified_input");
    duplicate["entries"][1] = duplicate["entries"][0].clone();
    assert!(BundleInventoryV1::from_json(&serde_json::to_vec(&duplicate).unwrap()).is_err());

    let mut unsorted = inventory_value("verified_input");
    unsorted["entries"].as_array_mut().unwrap().reverse();
    assert!(BundleInventoryV1::from_json(&serde_json::to_vec(&unsorted).unwrap()).is_err());

    for (field, value) in [
        ("mode", json!("0644")),
        ("size", json!(0)),
        ("size", json!(MAX_BUNDLE_OBJECT_BYTES + 1)),
    ] {
        let mut mutation = inventory_value("verified_input");
        mutation["entries"][0][field] = value;
        assert!(BundleInventoryV1::from_json(&serde_json::to_vec(&mutation).unwrap()).is_err());
    }

    let mut wrong_kind = inventory_value("verified_input");
    wrong_kind["kind"] = json!("signed_release");
    assert!(BundleInventoryV1::from_json(&serde_json::to_vec(&wrong_kind).unwrap()).is_err());

    let mut mixed_verified = inventory_value("verified_input");
    mixed_verified["entries"].as_array_mut().unwrap().insert(
        0,
        json!({
            "relative_path": "catalog-v1.json",
            "mode": "0400",
            "size": 8,
            "sha256": SHA_C
        }),
    );
    assert!(BundleInventoryV1::from_json(&serde_json::to_vec(&mixed_verified).unwrap()).is_err());

    let mut extra_verified = inventory_value("verified_input");
    extra_verified["entries"].as_array_mut().unwrap().insert(
        0,
        json!({
            "relative_path": "notes.txt",
            "mode": "0400",
            "size": 8,
            "sha256": SHA_C
        }),
    );
    assert!(BundleInventoryV1::from_json(&serde_json::to_vec(&extra_verified).unwrap()).is_err());

    let mut mixed_signed = inventory_value("signed_release");
    mixed_signed["entries"].as_array_mut().unwrap().push(json!({
        "relative_path": "verified-input-bundle-v1.json",
        "mode": "0400",
        "size": 8,
        "sha256": SHA_D
    }));
    assert!(BundleInventoryV1::from_json(&serde_json::to_vec(&mixed_signed).unwrap()).is_err());

    let mut digest_object_in_signed = inventory_value("signed_release");
    digest_object_in_signed["entries"]
        .as_array_mut()
        .unwrap()
        .insert(
            2,
            json!({
                "relative_path": format!("objects/{SHA_D}"),
                "mode": "0400",
                "size": 8,
                "sha256": SHA_D
            }),
        );
    assert!(
        BundleInventoryV1::from_json(&serde_json::to_vec(&digest_object_in_signed).unwrap())
            .is_err()
    );

    let mut unknown = inventory_value("verified_input");
    unknown["root_path"] = json!("/private/input");
    assert!(BundleInventoryV1::from_json(&serde_json::to_vec(&unknown).unwrap()).is_err());
}

#[test]
fn verified_input_bundle_is_public_data_only_and_digest_bound() {
    let value = verified_bundle_value();
    let bundle = VerifiedInputBundleV1::from_json(&serde_json::to_vec(&value).unwrap()).unwrap();
    let digest = verified_input_bundle_digest(&bundle).unwrap();

    let mut changed = value.clone();
    changed["objects"][0]["sha256"] = json!(SHA_D);
    changed["objects"][0]["relative_path"] = json!(format!("objects/{SHA_D}"));
    let changed = VerifiedInputBundleV1::from_json(&serde_json::to_vec(&changed).unwrap()).unwrap();
    assert_ne!(verified_input_bundle_digest(&changed).unwrap(), digest);

    for pointer in ["/credential", "/local_path", "/command"] {
        let mut attack = value.clone();
        attack
            .as_object_mut()
            .unwrap()
            .insert(pointer.trim_start_matches('/').to_owned(), json!("secret"));
        assert!(VerifiedInputBundleV1::from_json(&serde_json::to_vec(&attack).unwrap()).is_err());
    }
}

#[test]
fn signed_inventory_is_exactly_cross_bound_to_the_manifest_asset_set() {
    let manifest = parse_manifest(&manifest_value());
    let inventory = parse_inventory(&signed_inventory_value());
    verify_signed_release_inventory(&inventory, &manifest).unwrap();

    let mut extra = signed_inventory_value();
    extra["entries"].as_array_mut().unwrap().insert(
        4,
        json!({
            "relative_path": "release-notes.txt",
            "mode": "0400",
            "size": 32,
            "sha256": SHA_C
        }),
    );
    let extra = parse_inventory(&extra);
    assert!(verify_signed_release_inventory(&extra, &manifest).is_err());

    let mut substituted = signed_inventory_value();
    substituted["entries"][2]["sha256"] = json!(SHA_D);
    let substituted = parse_inventory(&substituted);
    assert!(verify_signed_release_inventory(&substituted, &manifest).is_err());

    let mut cross_kind_asset = manifest_value();
    cross_kind_asset["assets"][1]["name"] = json!("verified-input-bundle-v1.json");
    assert!(
        SignedReleaseBundleManifestV1::from_json(&serde_json::to_vec(&cross_kind_asset).unwrap())
            .is_err()
    );
}

#[test]
fn release_bundle_domain_binds_every_public_release_input_without_crypto() {
    let value = manifest_value();
    let manifest = parse_manifest(&value);
    let bytes = release_bundle_signing_bytes(&manifest).unwrap();
    let digest = release_bundle_domain_digest(&manifest).unwrap();
    assert!(bytes.starts_with(b"fluxsemble:runtime-catalog-release-bundle:v1\0"));
    assert_eq!(release_bundle_signing_bytes(&manifest).unwrap(), bytes);
    assert_eq!(release_bundle_domain_digest(&manifest).unwrap(), digest);

    let catalog = CatalogPayloadV1::from_json(include_bytes!(
        "../../../conformance/catalog-v1/valid-payload.json"
    ))
    .unwrap();
    assert_ne!(bytes, canonical_catalog_payload(&catalog).unwrap());

    for (pointer, replacement) in [
        ("/source_commit", json!(COMMIT_B)),
        ("/source_tree_sha256", json!(SHA_D)),
        ("/qualification_sha256", json!(SHA_D)),
        ("/tag", json!("catalog-v1-sequence-43")),
        ("/assets/0/name", json!("package-manifest-b.json")),
        ("/assets/0/sha256", json!(SHA_D)),
        ("/catalog_envelope/sha256", json!(SHA_D)),
    ] {
        let mut mutation = value.clone();
        *mutation.pointer_mut(pointer).unwrap() = replacement;
        assert_ne!(
            release_bundle_domain_digest(&parse_manifest(&mutation)).unwrap(),
            digest,
            "domain failed to bind {pointer}"
        );
    }

    let mut signature_only = value;
    signature_only["signature"]["signature"] = json!("different-fixture-signature");
    assert_eq!(
        release_bundle_domain_digest(&parse_manifest(&signature_only)).unwrap(),
        digest,
        "signature must not be included in its own signing input"
    );
}
