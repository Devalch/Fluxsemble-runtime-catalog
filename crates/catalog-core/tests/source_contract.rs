use catalog_core::{
    CatalogSourceV1, FluxsembleBuildBindingV1, InitialPiReleaseIntentV1, compatibility_input_digest,
};
use serde_json::{Value, json};

const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SHA_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const COMMIT_A: &str = "0123456789abcdef0123456789abcdef01234567";

fn intent_value() -> Value {
    let payload: Value = serde_json::from_slice(include_bytes!(
        "../../../conformance/catalog-v1/valid-payload.json"
    ))
    .unwrap();
    json!({
        "sequence": payload["sequence"],
        "tag": "catalog-v1-sequence-42",
        "generated_at": payload["generated_at"],
        "expires_at": payload["expires_at"],
        "fluxsemble_requirement": "=0.1.0",
        "release": {
            "provider": payload["providers"][0]["provider_id"],
            "allowed_origins": payload["providers"][0]["allowed_origins"],
            "release": payload["providers"][0]["releases"][0]
        }
    })
}

fn build_value() -> Value {
    json!({
        "implementation_commit": COMMIT_A,
        "application_sha256": SHA_A,
        "daemon_sha256": SHA_B,
        "compatibility_profile_id": "runtime-catalog-compatibility-v1",
        "compatibility_profile_sha256": SHA_C
    })
}

fn parse_intent(value: &Value) -> InitialPiReleaseIntentV1 {
    InitialPiReleaseIntentV1::from_json(&serde_json::to_vec(value).unwrap()).unwrap()
}

fn parse_build(value: &Value) -> FluxsembleBuildBindingV1 {
    FluxsembleBuildBindingV1::from_json(&serde_json::to_vec(value).unwrap()).unwrap()
}

#[test]
fn compatibility_digest_excludes_freshness_and_metadata_but_binds_build_and_tuple() {
    let intent_json = intent_value();
    let build_json = build_value();
    let intent = parse_intent(&intent_json);
    let build = parse_build(&build_json);
    let digest = compatibility_input_digest(&intent, &build).unwrap();

    let mut freshness = intent_json.clone();
    freshness["sequence"] = json!("43");
    freshness["tag"] = json!("catalog-v1-sequence-43");
    freshness["generated_at"] = json!("2026-09-01T00:00:00Z");
    freshness["expires_at"] = json!("2026-09-30T00:00:00Z");
    assert_eq!(
        compatibility_input_digest(&parse_intent(&freshness), &build).unwrap(),
        digest
    );

    let mut metadata = intent_json.clone();
    metadata["release"]["release"]["release_metadata"]["title"] = json!("Reissued title");
    metadata["release"]["release"]["release_metadata"]["notes"] = json!("Reissued notes.");
    assert_eq!(
        compatibility_input_digest(&parse_intent(&metadata), &build).unwrap(),
        digest
    );

    let mut pi_version = intent_json.clone();
    for pointer in [
        "/release/release/version",
        "/release/release/components/1/version",
        "/release/release/provider_extension/metadata/approved_package/version",
        "/release/release/provider_extension/metadata/shipped_shrinkwrap/root_package/version",
    ] {
        *pi_version.pointer_mut(pointer).unwrap() = json!("0.84.0");
    }
    assert_ne!(
        compatibility_input_digest(&parse_intent(&pi_version), &build).unwrap(),
        digest
    );

    let mut application = build_json.clone();
    application["application_sha256"] = json!(SHA_B);
    assert_ne!(
        compatibility_input_digest(&intent, &parse_build(&application)).unwrap(),
        digest
    );

    let mut profile = build_json;
    profile["compatibility_profile_sha256"] = json!(SHA_A);
    assert_ne!(
        compatibility_input_digest(&intent, &parse_build(&profile)).unwrap(),
        digest
    );
}

#[test]
fn intent_and_build_admission_is_strict_and_data_only() {
    assert!(
        InitialPiReleaseIntentV1::from_json(&serde_json::to_vec(&intent_value()).unwrap()).is_ok()
    );
    assert!(
        FluxsembleBuildBindingV1::from_json(&serde_json::to_vec(&build_value()).unwrap()).is_ok()
    );

    let mut attacks = Vec::new();
    let mut wrong_tag = intent_value();
    wrong_tag["tag"] = json!("catalog-v1-sequence-41");
    attacks.push(wrong_tag);
    let mut wrong_requirement = intent_value();
    wrong_requirement["fluxsemble_requirement"] = json!(">=0.1.0");
    attacks.push(wrong_requirement);
    let mut wrong_provider = intent_value();
    wrong_provider["release"]["provider"] = json!("builtin:codex");
    attacks.push(wrong_provider);
    let mut private_field = intent_value();
    private_field["release"]["release"]["command"] = json!(["pi"]);
    attacks.push(private_field);
    let mut local_field = intent_value();
    local_field["local_path"] = json!("/tmp/input");
    attacks.push(local_field);
    for attack in attacks {
        assert!(
            InitialPiReleaseIntentV1::from_json(&serde_json::to_vec(&attack).unwrap()).is_err(),
            "accepted hostile intent {attack}"
        );
    }

    let duplicate = serde_json::to_vec(&intent_value())
        .unwrap()
        .into_iter()
        .collect::<Vec<_>>();
    let duplicate = String::from_utf8(duplicate).unwrap().replacen(
        "\"sequence\":\"42\"",
        "\"sequence\":\"42\",\"sequence\":\"42\"",
        1,
    );
    assert!(InitialPiReleaseIntentV1::from_json(duplicate.as_bytes()).is_err());

    let mut invalid_build = build_value();
    invalid_build["implementation_commit"] = json!("ABC");
    assert!(
        FluxsembleBuildBindingV1::from_json(&serde_json::to_vec(&invalid_build).unwrap()).is_err()
    );
}

#[test]
fn only_final_source_carries_build_and_qualification_bindings() {
    let source = json!({
        "intent": intent_value(),
        "build": build_value(),
        "qualification": {
            "relative_path": "qualifications/pi-0.83.0-linux-x86_64-v1.json",
            "sha256": SHA_A
        }
    });
    let parsed = CatalogSourceV1::from_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    assert_eq!(parsed.intent.release.provider(), "builtin:pi");
    assert_eq!(parsed.intent.release.target().as_str(), "linux_x86_64");
    assert_eq!(parsed.intent.release.pi_version().as_str(), "0.83.0");
    assert_eq!(parsed.intent.release.node_version().as_str(), "22.19.0");

    let mut missing = source.clone();
    missing.as_object_mut().unwrap().remove("qualification");
    assert!(CatalogSourceV1::from_json(&serde_json::to_vec(&missing).unwrap()).is_err());

    let mut authority = source;
    authority["signing_key"] = json!("never");
    assert!(CatalogSourceV1::from_json(&serde_json::to_vec(&authority).unwrap()).is_err());
}
