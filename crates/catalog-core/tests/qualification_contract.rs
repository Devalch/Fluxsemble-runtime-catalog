use catalog_core::{
    CatalogSourceV1, CompatibilityQualificationV1, FluxsembleBuildBindingV1,
    InitialPiReleaseIntentV1, compatibility_input_digest, qualification_record_digest,
    verify_qualification,
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

fn qualification_value(compatibility_input_sha256: String) -> Value {
    json!({
        "schema_version": 1,
        "compatibility_input_sha256": compatibility_input_sha256,
        "fluxsemble": build_value(),
        "provider": "builtin:pi",
        "target": "linux_x86_64",
        "pi_version": "0.83.0",
        "node_version": "22.19.0",
        "checks": {
            "catalog_v1_conformance": "passed",
            "managed_installation": "passed",
            "node_probe": "passed",
            "pi_probe": "passed",
            "pi_rpc_readiness": "passed",
            "activation": "passed",
            "managed_resolution": "passed",
            "required_failure": "passed",
            "cancellation": "passed"
        },
        "reviewer": "release-reviewer",
        "release_owner_approved_at": "2026-08-01T12:00:00Z",
        "residual_risks": ["Initial release supports one provider and target."]
    })
}

fn bound_fixture() -> (Value, Value) {
    let intent =
        InitialPiReleaseIntentV1::from_json(&serde_json::to_vec(&intent_value()).unwrap()).unwrap();
    let build =
        FluxsembleBuildBindingV1::from_json(&serde_json::to_vec(&build_value()).unwrap()).unwrap();
    let compatibility = hex::encode(compatibility_input_digest(&intent, &build).unwrap());
    let qualification = qualification_value(compatibility);
    let record =
        CompatibilityQualificationV1::from_json(&serde_json::to_vec(&qualification).unwrap())
            .unwrap();
    let source = json!({
        "intent": intent_value(),
        "build": build_value(),
        "qualification": {
            "relative_path": "qualifications/pi-0.83.0-linux-x86_64-v1.json",
            "sha256": hex::encode(qualification_record_digest(&record).unwrap())
        }
    });
    (source, qualification)
}

fn parse_source(value: &Value) -> CatalogSourceV1 {
    CatalogSourceV1::from_json(&serde_json::to_vec(value).unwrap()).unwrap()
}

fn parse_record(value: &Value) -> CompatibilityQualificationV1 {
    CompatibilityQualificationV1::from_json(&serde_json::to_vec(value).unwrap()).unwrap()
}

#[test]
fn exact_qualification_binds_source_build_profile_tuple_and_input_digest() {
    let (source, qualification) = bound_fixture();
    verify_qualification(&parse_source(&source), &parse_record(&qualification)).unwrap();

    for (pointer, replacement) in [
        ("/compatibility_input_sha256", json!(SHA_A)),
        ("/fluxsemble/application_sha256", json!(SHA_C)),
        ("/fluxsemble/compatibility_profile_sha256", json!(SHA_A)),
        ("/provider", json!("builtin:codex")),
        ("/pi_version", json!("0.84.0")),
        ("/node_version", json!("22.20.0")),
    ] {
        let mut mutation = qualification.clone();
        *mutation.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            verify_qualification(&parse_source(&source), &parse_record(&mutation)).is_err(),
            "accepted qualification mismatch at {pointer}"
        );
    }

    let mut wrong_reference = source;
    wrong_reference["qualification"]["sha256"] = json!(SHA_A);
    assert!(
        verify_qualification(
            &parse_source(&wrong_reference),
            &parse_record(&qualification)
        )
        .is_err()
    );
}

#[test]
fn every_named_qualification_check_must_have_passed() {
    let (source, qualification) = bound_fixture();
    for check in [
        "catalog_v1_conformance",
        "managed_installation",
        "node_probe",
        "pi_probe",
        "pi_rpc_readiness",
        "activation",
        "managed_resolution",
        "required_failure",
        "cancellation",
    ] {
        let mut mutation = qualification.clone();
        mutation["checks"][check] = json!("failed");
        assert!(
            verify_qualification(&parse_source(&source), &parse_record(&mutation)).is_err(),
            "accepted failed {check} check"
        );
    }
}

#[test]
fn qualification_schema_text_and_collections_are_strict_and_bounded() {
    let (_, qualification) = bound_fixture();
    assert!(
        CompatibilityQualificationV1::from_json(&serde_json::to_vec(&qualification).unwrap())
            .is_ok()
    );

    let mut unknown = qualification.clone();
    unknown["approval_key"] = json!("not-authority");
    assert!(
        CompatibilityQualificationV1::from_json(&serde_json::to_vec(&unknown).unwrap()).is_err()
    );

    let mut wrong_schema = qualification.clone();
    wrong_schema["schema_version"] = json!(2);
    assert!(
        CompatibilityQualificationV1::from_json(&serde_json::to_vec(&wrong_schema).unwrap())
            .is_err()
    );

    let mut blank_reviewer = qualification.clone();
    blank_reviewer["reviewer"] = json!("");
    assert!(
        CompatibilityQualificationV1::from_json(&serde_json::to_vec(&blank_reviewer).unwrap())
            .is_err()
    );

    let mut too_many_risks = qualification;
    too_many_risks["residual_risks"] = json!(vec!["risk"; 33]);
    assert!(
        CompatibilityQualificationV1::from_json(&serde_json::to_vec(&too_many_risks).unwrap())
            .is_err()
    );
}
