use catalog_core::{PiReleaseProfileV1, PiReleaseQualificationV1, verify_pi_release_qualification};
use serde_json::{Value, json};

fn profile() -> Value {
    serde_json::from_slice(include_bytes!(
        "fixtures/catalog/pi-installer-v1/valid-wrapper-root.json"
    ))
    .unwrap()
}
fn qualification() -> Value {
    let mut q: Value = serde_json::from_slice(include_bytes!(
        "fixtures/catalog/pi-installer-v1/valid-qualification.json"
    ))
    .unwrap();
    let manifest = json!({"schema_version":1,"profile_id":"builtin-pi-installer-lock-contracts-v1","required_contracts":q["required_contracts"]});
    let mut bytes = serde_jcs::to_vec(&manifest).unwrap();
    bytes.push(b'\n');
    use sha2::{Digest, Sha256};
    q["verification_build"]["compatibility_profile_sha256"] =
        json!(hex::encode(Sha256::digest(&bytes)));
    q
}
fn verify(p: &Value, q: &Value) -> Result<(), catalog_core::CoreError> {
    verify_pi_release_qualification(
        &PiReleaseProfileV1::from_json(&serde_json::to_vec(p).unwrap()).unwrap(),
        &PiReleaseQualificationV1::from_json(&serde_json::to_vec(q).unwrap()).unwrap(),
    )
}

#[test]
fn qualification_binds_exact_subject_contracts_requirement_and_complete_checks() {
    let p = profile();
    let q = qualification();
    assert!(verify(&p, &q).is_ok());
    for (pointer, replacement) in [
        ("/release_subject_sha256", json!("9".repeat(64))),
        (
            "/required_contracts/resource_policy_sha256",
            json!("9".repeat(64)),
        ),
        ("/consumer_requirement", json!(">=0.2.0")),
        ("/verification_build/consumer_version", json!("0.0.1")),
        (
            "/verification_build/compatibility_profile_sha256",
            json!("9".repeat(64)),
        ),
        ("/results/installation", json!("fail")),
        ("/results/sdk_auth", json!("fail")),
        ("/results/session_resume", json!("fail")),
        ("/results/streaming_tools", json!("fail")),
        ("/results/lifecycle", json!("fail")),
    ] {
        let mut altered = q.clone();
        *altered.pointer_mut(pointer).unwrap() = replacement;
        assert!(verify(&p, &altered).is_err(), "{pointer}");
    }
    let mut changed = p.clone();
    changed["installer_lock"]["sha256"] = json!("8".repeat(64));
    assert!(verify(&changed, &q).is_err());
}

#[test]
fn qualification_for_two_pi_releases_uses_unchanged_verification_build() {
    let p = profile();
    let q = qualification();
    assert!(verify(&p, &q).is_ok());
    let mut later = p.clone();
    for pointer in [
        "/pi_package/version",
        "/locked_packages/0/version",
        "/components/1/version",
    ] {
        *later.pointer_mut(pointer).unwrap() = json!("1.3.0");
    }
    assert!(verify(&later, &q).is_err());
    let mut later_evidence = q.clone();
    later_evidence["release_subject_sha256"] = json!(hex::encode(
        catalog_core::pi_release_subject_sha256(
            &PiReleaseProfileV1::from_json(&serde_json::to_vec(&later).unwrap()).unwrap()
        )
        .unwrap()
    ));
    assert!(verify(&later, &later_evidence).is_ok());
    assert_eq!(
        q["verification_build"],
        later_evidence["verification_build"]
    );
}

#[test]
fn behavior_profile_digest_matches_independently_admitted_manifest() {
    let manifest: Value = serde_json::from_slice(include_bytes!(
        "../../catalog-acquire/tests/fixtures/pi-installer/supported-contracts-v1.json"
    ))
    .unwrap();
    let contracts = catalog_core::PiRequiredContractsV1::from_json(
        &serde_json::to_vec(&manifest["required_contracts"]).unwrap(),
    )
    .unwrap();
    assert_eq!(
        hex::encode(catalog_core::pi_required_contracts_profile_sha256(&contracts).unwrap()),
        "3fb5c10c327b14a8537b1a748961ca034d8685ac71f20132ee5039b12b315747"
    );
}

#[test]
fn historical_qualified_source_is_not_reinterpreted_as_producer_source() {
    let intent: Value = serde_json::from_slice(include_bytes!(
        "../../../conformance/pi-installer-release-v1/generated/initial-release-intent-v2.json"
    ))
    .unwrap();
    let source = json!({"schema_version":2,"intent":intent,"build":{},"qualification":{}});
    assert!(
        catalog_core::CatalogSourceV2::from_json(&serde_json::to_vec(&source).unwrap()).is_err()
    );
}
