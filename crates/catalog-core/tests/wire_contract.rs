use std::collections::BTreeSet;

use catalog_core::{
    CATALOG_SCHEMA_VERSION, CatalogPayloadV1, CoreError, MAX_CATALOG_PAYLOAD_BYTES,
};
use serde_json::{Value, json};

const VALID_PAYLOAD: &[u8] = include_bytes!("../../../conformance/catalog-v1/valid-payload.json");
const REJECTED_FIELDS: &str = include_str!("../../../conformance/catalog-v1/rejected-fields.json");

fn valid_payload() -> Value {
    serde_json::from_slice(VALID_PAYLOAD).expect("valid fixture JSON")
}

fn parses(value: &Value) -> bool {
    CatalogPayloadV1::from_json(&serde_json::to_vec(value).expect("serialize mutation")).is_ok()
}

fn at_mut<'a>(value: &'a mut Value, pointer: &str) -> &'a mut Value {
    if pointer.is_empty() {
        value
    } else {
        value.pointer_mut(pointer).expect("fixture pointer exists")
    }
}

#[test]
fn valid_payload_has_the_frozen_initial_contract_shape() {
    let bytes = include_bytes!("../../../conformance/catalog-v1/valid-payload.json");
    let payload = CatalogPayloadV1::from_json(bytes).expect("valid catalog-v1 payload");
    assert_eq!(payload.sequence().get(), 42);
    assert_eq!(payload.providers().len(), 1);
    assert_eq!(payload.providers()[0].provider_id(), "builtin:pi");
}

#[test]
fn duplicate_unknown_unbounded_and_ambiguous_values_are_rejected() {
    for bytes in hostile_catalog_payloads() {
        assert_eq!(
            CatalogPayloadV1::from_json(&bytes),
            Err(CoreError::InvalidCatalog)
        );
    }
}

fn hostile_catalog_payloads() -> Vec<Vec<u8>> {
    let valid = String::from_utf8(VALID_PAYLOAD.to_vec()).expect("fixture is UTF-8");
    vec![
        valid
            .replacen(
                "\"schema_version\": 1,",
                "\"schema_version\": 1,\n  \"schema_version\": 1,",
                1,
            )
            .into_bytes(),
        valid
            .replacen(
                "\"schema_version\": 1,",
                "\"schema_version\": 1,\n  \"unknown\": true,",
                1,
            )
            .into_bytes(),
        vec![b' '; MAX_CATALOG_PAYLOAD_BYTES + 1],
        valid
            .replacen("\"sequence\": \"42\"", "\"sequence\": \"042\"", 1)
            .into_bytes(),
    ]
}

#[test]
fn errors_are_closed_and_do_not_echo_hostile_input() {
    let marker = "do-not-echo-this-value";
    let bytes = format!("{{\"{marker}\":true}}");
    let error = CatalogPayloadV1::from_json(bytes.as_bytes()).unwrap_err();
    assert_eq!(error, CoreError::InvalidCatalog);
    assert_eq!(error.to_string(), "invalid catalog");
    assert!(!error.to_string().contains(marker));
}

#[test]
fn all_documented_authority_and_executable_fields_are_rejected() {
    let cases: Vec<Value> = serde_json::from_str(REJECTED_FIELDS).expect("rejected field vector");
    for case in cases {
        let pointer = case["path"].as_str().expect("case path");
        let field = case["field"].as_str().expect("case field");
        let mut payload = valid_payload();
        at_mut(&mut payload, pointer)
            .as_object_mut()
            .expect("case object")
            .insert(field.to_owned(), case["value"].clone());
        assert!(!parses(&payload), "accepted prohibited field {field}");
    }
}

#[test]
fn canonical_decimal_timestamps_digests_integrity_and_versions_are_strict() {
    let mutations = [
        ("/sequence", json!("0")),
        ("/sequence", json!("01")),
        ("/sequence", json!(1)),
        ("/generated_at", json!("2026-08-01T00:00:00+00:00")),
        ("/expires_at", json!("2026-08-31T00:00:00.000Z")),
        (
            "/providers/0/releases/0/components/0/artifacts/0/size_bytes",
            json!("01"),
        ),
        (
            "/providers/0/releases/0/components/0/artifacts/0/size_bytes",
            json!(0),
        ),
        (
            "/providers/0/releases/0/components/0/artifacts/0/sha256",
            json!("C0649AF18E6A24F6FE5535A3E86B341DD49A8E71117C8B68BDE973EF834F16F2"),
        ),
        ("/providers/0/releases/0/version", json!("00.83.0")),
        (
            "/providers/0/releases/0/provider_extension/metadata/registry_integrity",
            json!(
                "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB=="
            ),
        ),
    ];
    for (pointer, replacement) in mutations {
        let mut payload = valid_payload();
        *at_mut(&mut payload, pointer) = replacement;
        assert!(!parses(&payload), "accepted invalid scalar at {pointer}");
    }

    for accepted in ["0", "9007199254740992", "18446744073709551615"] {
        let mut payload = valid_payload();
        payload["providers"][0]["releases"][0]["components"][0]["artifacts"][0]["inventory"][0]["size_bytes"] =
            json!(accepted);
        assert!(parses(&payload), "rejected canonical u64 {accepted}");
    }
}

#[test]
fn urls_are_query_free_https_initial_urls_on_unique_allowlisted_origins() {
    for attack in [
        "http://nodejs.org/archive.tar.xz",
        "https://user@nodejs.org/archive.tar.xz",
        "https://nodejs.org/archive.tar.xz?token=secret",
        "https://nodejs.org/archive.tar.xz#fragment",
        "https://nodejs.org\\@evil.example/archive.tar.xz",
        " https://nodejs.org/archive.tar.xz",
        "https://nodejs.org.evil.example/archive.tar.xz",
    ] {
        let mut payload = valid_payload();
        payload["providers"][0]["releases"][0]["components"][0]["artifacts"][0]["url"] =
            json!(attack);
        assert!(!parses(&payload), "accepted URL attack {attack:?}");
    }

    let mut undeclared = valid_payload();
    undeclared["providers"][0]["releases"][0]["provider_extension"]["metadata"]["root_package_manifest"]
        ["url"] = json!("https://attacker.example/manifest.json");
    assert!(!parses(&undeclared));

    let mut reordered = valid_payload();
    reordered["providers"][0]["allowed_origins"] =
        json!(["https://registry.npmjs.org", "https://nodejs.org"]);
    assert!(parses(&reordered));

    let mut normalized_duplicate = valid_payload();
    normalized_duplicate["providers"][0]["allowed_origins"] = json!([
        "https://nodejs.org",
        "https://nodejs.org:443",
        "https://registry.npmjs.org"
    ]);
    assert!(!parses(&normalized_duplicate));
}

#[test]
fn repeated_records_are_sorted_and_unique() {
    let reversals = ["/providers/0/releases/0/components"];
    for pointer in reversals {
        let mut payload = valid_payload();
        at_mut(&mut payload, pointer)
            .as_array_mut()
            .expect("array")
            .reverse();
        assert!(!parses(&payload), "accepted unsorted records at {pointer}");
    }

    for pointer in [
        "/compatibility_ranges",
        "/providers/0/allowed_origins",
        "/providers/0/releases/0/compatibility_ranges",
        "/providers/0/releases/0/components/0/artifacts/0/inventory",
        "/providers/0/releases/0/provider_extension/metadata/shipped_shrinkwrap/locked_packages",
    ] {
        let mut payload = valid_payload();
        let duplicate = payload.pointer(pointer).unwrap()[0].clone();
        at_mut(&mut payload, pointer)
            .as_array_mut()
            .expect("array")
            .push(duplicate);
        assert!(!parses(&payload), "accepted duplicate at {pointer}");
    }
}

#[test]
fn pi_extension_relationships_and_only_initial_target_are_enforced() {
    let mutations = [
        ("/providers/0/releases/0/target", json!("linux_aarch64")),
        (
            "/providers/0/releases/0/provider_extension/metadata/approved_package/name",
            json!("attacker-package"),
        ),
        (
            "/providers/0/releases/0/provider_extension/metadata/approved_package/version",
            json!("0.84.0"),
        ),
        (
            "/providers/0/releases/0/provider_extension/metadata/component_id",
            json!("component:missing"),
        ),
        (
            "/providers/0/releases/0/provider_extension/metadata/package_artifact_id",
            json!("artifact:missing"),
        ),
        (
            "/providers/0/releases/0/provider_extension/metadata/expected_entrypoint",
            json!("dist/missing.js"),
        ),
        (
            "/providers/0/releases/0/provider_extension/metadata/shipped_shrinkwrap/lockfile_version",
            json!(2),
        ),
    ];
    for (pointer, replacement) in mutations {
        let mut payload = valid_payload();
        *at_mut(&mut payload, pointer) = replacement;
        assert!(
            !parses(&payload),
            "accepted incoherent Pi value at {pointer}"
        );
    }

    let mut none_for_pi = valid_payload();
    none_for_pi["providers"][0]["releases"][0]["provider_extension"] = json!({"kind":"none"});
    assert!(!parses(&none_for_pi));
}

#[test]
fn inventory_and_package_coordinates_are_data_only_and_path_safe() {
    for attack in [
        "",
        "/bin/node",
        "bin//node",
        "./bin/node",
        "bin/./node",
        "bin/../node",
        "bin\\node",
    ] {
        let mut payload = valid_payload();
        payload["providers"][0]["releases"][0]["components"][0]["artifacts"][0]["inventory"][0]["path"] =
            json!(attack);
        assert!(
            !parses(&payload),
            "accepted unsafe inventory path {attack:?}"
        );
    }

    let mut locator = valid_payload();
    locator["providers"][0]["releases"][0]["provider_extension"]["metadata"]["shipped_shrinkwrap"]
        ["locked_packages"][0]["locator"] = json!("chalk");
    assert!(!parses(&locator));
}

#[test]
fn normative_spec_names_every_wire_field_and_rejection_vector_is_complete() {
    let spec = include_str!("../../../spec/catalog-v1.md");
    let mut fields = BTreeSet::new();
    collect_object_fields(&valid_payload(), &mut fields);
    for field in fields {
        assert!(
            spec.contains(&format!("`{field}`")),
            "spec omits wire field {field}"
        );
    }
    for required in [
        "`command`",
        "`environment`",
        "`hook`",
        "`destination`",
        "`provider_code`",
        "`trust_key`",
    ] {
        assert!(spec.contains(required), "spec omits prohibition {required}");
    }
    assert!(spec.contains("RFC 8785"));
    assert!(spec.contains("catalog-v1-sequence-<sequence>"));
    assert_eq!(CATALOG_SCHEMA_VERSION, 1);
}

fn collect_object_fields(value: &Value, fields: &mut BTreeSet<String>) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                fields.insert(key.clone());
                collect_object_fields(child, fields);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_object_fields(child, fields);
            }
        }
        _ => {}
    }
}
