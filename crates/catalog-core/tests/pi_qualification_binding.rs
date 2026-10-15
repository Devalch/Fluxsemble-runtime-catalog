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

fn source_value(q: &Value) -> Value {
    use sha2::{Digest, Sha256};
    let mut build = q["verification_build"].clone();
    build.as_object_mut().unwrap().remove("consumer_version");
    let mut p = profile();
    for (key, role) in [
        ("installer_manifest", "pi-installer-package"),
        ("installer_lock", "pi-installer-lock"),
        ("pi_manifest", "pi-package"),
    ] {
        p[key]["url"] = json!(format!(
            "https://github.com/Devalch/Fluxsemble-runtime-catalog/releases/download/catalog-v1-sequence-2/{role}-{}.json",
            p[key]["sha256"].as_str().unwrap()
        ));
    }
    json!({"schema_version":2,"intent":{"schema_version":2,"sequence":"2","tag":"catalog-v1-sequence-2","generated_at":"2026-10-15T00:00:00Z","expires_at":"2026-11-15T00:00:00Z","title":"Pi candidate","notes":"Synthetic evidence","profile":p},"build":build,"qualification":{"relative_path":"qualifications/current.json","sha256":hex::encode(Sha256::digest(serde_jcs::to_vec(q).unwrap()))}})
}

fn final_fixture() -> (Value, Value) {
    let mut q = qualification();
    let s = source_value(&q);
    q["release_subject_sha256"] = json!(hex::encode(
        catalog_core::pi_release_subject_sha256(
            &PiReleaseProfileV1::from_json(&serde_json::to_vec(&s["intent"]["profile"]).unwrap())
                .unwrap()
        )
        .unwrap()
    ));
    (source_value(&q), q)
}

#[test]
fn qualification_binds_subject_before_final_catalog_assembly() {
    use sha2::{Digest, Sha256};
    assert!(import_fixture("matching-existing-consumer").is_ok());
    assert!(import_fixture("same-record-other-release-subject").is_err());
    assert!(verify_bundle_fixture("qualification-asset-omitted").is_err());
    let (s, q) = final_fixture();
    let source = catalog_core::CatalogSourceV2::from_json(&serde_jcs::to_vec(&s).unwrap()).unwrap();
    let exact_record = serde_jcs::to_vec(&q).unwrap();
    let payload = source.finalize(&exact_record).unwrap();
    let catalog_core::ProviderExtensionV1::PiInstallerLock(metadata) =
        payload.providers()[0].releases()[0].provider_extension()
    else {
        panic!("wrong extension")
    };
    assert_eq!(
        metadata.qualification().sha256().as_str(),
        hex::encode(Sha256::digest(&exact_record))
    );
    assert_eq!(
        metadata.qualification().size_bytes().get(),
        exact_record.len() as u64
    );
    assert_eq!(metadata.profile(), source.intent().profile());
    assert_ne!(
        q["release_subject_sha256"].as_str().unwrap(),
        hex::encode(Sha256::digest(serde_jcs::to_vec(&payload).unwrap()))
    );
    for pointer in [
        "/build/application_sha256",
        "/build/daemon_sha256",
        "/build/compatibility_profile_sha256",
        "/qualification/sha256",
        "/intent/profile/installer_lock/sha256",
    ] {
        let mut altered = s.clone();
        *altered.pointer_mut(pointer).unwrap() = json!("9".repeat(64));
        assert!(
            catalog_core::CatalogSourceV2::from_json(&serde_jcs::to_vec(&altered).unwrap())
                .and_then(|source| source.finalize(&exact_record))
                .is_err(),
            "{pointer}"
        );
    }
    let mut changed = exact_record;
    changed.push(b'\n');
    assert!(source.finalize(&changed).is_err());
}

#[test]
fn release_bundle_requires_every_exact_installer_and_qualification_asset() {
    let (payload, manifest) = bundle_fixture();
    let verify = |v: &Value| {
        catalog_core::verify_pi_release_bundle_assets(
            &payload,
            &catalog_core::SignedReleaseBundleManifestV1::from_json(&serde_jcs::to_vec(v).unwrap())
                .unwrap(),
        )
    };
    verify(&manifest).unwrap();
    for index in 0..4 {
        let mut removed = manifest.clone();
        removed["assets"].as_array_mut().unwrap().remove(index);
        assert!(verify(&removed).is_err());
        for (key, value) in [("size", json!(999)), ("sha256", json!("9".repeat(64)))] {
            let mut replaced = manifest.clone();
            replaced["assets"][index][key] = value;
            assert!(verify(&replaced).is_err());
        }
    }
}

fn import_fixture(case: &str) -> Result<catalog_core::CatalogPayloadV1, catalog_core::CoreError> {
    let (mut source, qualification) = final_fixture();
    match case {
        "matching-existing-consumer" => {}
        "same-record-other-release-subject" => {
            for pointer in [
                "/intent/profile/pi_package/version",
                "/intent/profile/components/1/version",
                "/intent/profile/locked_packages/0/version",
            ] {
                *source.pointer_mut(pointer).unwrap() = json!("1.3.0");
            }
        }
        _ => panic!("unknown fixture case"),
    }
    catalog_core::CatalogSourceV2::from_json(&serde_jcs::to_vec(&source).unwrap())?
        .finalize(&serde_jcs::to_vec(&qualification).unwrap())
}
fn bundle_fixture() -> (catalog_core::CatalogPayloadV1, Value) {
    let (s, q) = final_fixture();
    let source = catalog_core::CatalogSourceV2::from_json(&serde_jcs::to_vec(&s).unwrap()).unwrap();
    let payload = source.finalize(&serde_jcs::to_vec(&q).unwrap()).unwrap();
    let catalog_core::ProviderExtensionV1::PiInstallerLock(metadata) =
        payload.providers()[0].releases()[0].provider_extension()
    else {
        panic!()
    };
    let mut assets = [metadata.profile().installer_manifest(), metadata.profile().installer_lock(), metadata.profile().pi_manifest(), metadata.qualification()].into_iter().map(|d| json!({"name":d.url().as_str().rsplit('/').next().unwrap(),"size":d.size_bytes().get(),"sha256":d.sha256()})).collect::<Vec<_>>();
    assets.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    let manifest = json!({"schema_version":1,"source_commit":"1".repeat(40),"source_tree_sha256":"2".repeat(64),"qualification_sha256":metadata.qualification().sha256(),"tag":"catalog-v1-sequence-2","catalog_envelope":{"name":"catalog-v1.json","size":100,"sha256":"3".repeat(64)},"assets":assets,"signature":{"key_id":"unit-bundle-identity","signature":"fixture"}});
    (payload, manifest)
}
fn verify_bundle_fixture(case: &str) -> Result<(), catalog_core::CoreError> {
    let (payload, mut manifest) = bundle_fixture();
    match case {
        "qualification-asset-omitted" => manifest["assets"]
            .as_array_mut()
            .unwrap()
            .retain(|a| !a["name"].as_str().unwrap().starts_with("qualification-")),
        _ => panic!("unknown fixture case"),
    }
    catalog_core::verify_pi_release_bundle_assets(
        &payload,
        &catalog_core::SignedReleaseBundleManifestV1::from_json(
            &serde_jcs::to_vec(&manifest).unwrap(),
        )?,
    )
}

#[test]
fn source_v2_rejects_unknown_fields_unsafe_paths_and_wrong_existing_build_identity() {
    let (s, q) = final_fixture();
    let exact = serde_jcs::to_vec(&q).unwrap();
    for (pointer, value) in [
        (
            "/qualification/relative_path",
            json!("qualifications/../other.json"),
        ),
        ("/intent/sequence", json!("02")),
        ("/intent/schema_version", json!(1)),
        ("/build/implementation_commit", json!("9".repeat(40))),
        ("/build/compatibility_profile_id", json!("other-profile")),
    ] {
        let mut changed = s.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            catalog_core::CatalogSourceV2::from_json(&serde_jcs::to_vec(&changed).unwrap())
                .and_then(|s| s.finalize(&exact))
                .is_err(),
            "{pointer}"
        );
    }
    for pointer in ["", "/intent", "/build", "/qualification", "/intent/profile"] {
        let mut changed = s.clone();
        changed
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unexpected".into(), json!(1));
        assert!(
            catalog_core::CatalogSourceV2::from_json(&serde_jcs::to_vec(&changed).unwrap())
                .is_err()
        );
    }
    let text = serde_json::to_string(&s)
        .unwrap()
        .replacen("{", "{\"schema_version\":2,", 1);
    assert!(catalog_core::CatalogSourceV2::from_json(text.as_bytes()).is_err());
}
