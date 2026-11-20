use catalog_core::{PiReleaseProfileV2, pi_release_subject_v2_sha256};
use serde_json::{Value, json};

fn profile() -> Value {
    let mut value: Value = serde_json::from_slice(include_bytes!(
        "fixtures/catalog/pi-installer-v1/valid-wrapper-root.json"
    ))
    .unwrap();
    value["schema_version"] = json!(2);
    value
        .as_object_mut()
        .unwrap()
        .remove("consumer_requirement");
    value.as_object_mut().unwrap().remove("required_contracts");
    value
}

#[test]
fn v2_profile_contains_producer_inputs_without_consumer_qualification() {
    let value = profile();
    let parse = |v: &Value| PiReleaseProfileV2::from_json(&serde_json::to_vec(v).unwrap());
    let parsed = parse(&value).unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), value);
    let subject = pi_release_subject_v2_sha256(&parsed).unwrap();
    let mut changed = value.clone();
    changed["installer_manifest"]["sha256"] = json!("9".repeat(64));
    assert_ne!(
        subject,
        pi_release_subject_v2_sha256(&parse(&changed).unwrap()).unwrap()
    );
    for field in [
        "consumer_requirement",
        "required_contracts",
        "qualification",
    ] {
        let mut changed = value.clone();
        changed[field] = json!(null);
        assert!(parse(&changed).is_err(), "{field}");
    }
}

#[test]
fn v2_profile_rejects_mismatched_or_unsafe_inputs() {
    for (pointer, replacement) in [
        ("/pi_package/version", json!("1.3.0")),
        ("/locked_packages/0/archive_sha256", json!("9".repeat(64))),
        ("/installer_manifest/url", json!("http://example.com/a")),
        ("/pi_package_locator", json!("../bad")),
    ] {
        let mut value = profile();
        *value.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            PiReleaseProfileV2::from_json(&serde_json::to_vec(&value).unwrap()).is_err(),
            "{pointer}"
        );
    }
}

#[test]
fn v2_producer_source_finalizes_without_consumer_qualification() {
    let mut profile = profile();
    for (field, role) in [
        ("installer_manifest", "pi-installer-package"),
        ("installer_lock", "pi-installer-lock"),
        ("pi_manifest", "pi-package"),
    ] {
        let digest = profile[field]["sha256"].as_str().unwrap().to_owned();
        profile[field]["url"] = json!(format!(
            "https://github.com/Devalch/Fluxsemble-runtime-catalog/releases/download/catalog-v1-sequence-8/{role}-{digest}.json"
        ));
    }
    let intent = json!({"schema_version":2,"sequence":"8","tag":"catalog-v1-sequence-8", "generated_at":"2026-11-20T16:00:00Z", "expires_at":"2026-12-20T16:00:00Z", "title":"Pi 1.2.0", "notes":"Verified Pi inputs", "profile":profile});
    let source = json!({"schema_version":2, "intent":intent});
    let parsed =
        catalog_core::CatalogSourceV2::from_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    let payload = parsed.finalize().unwrap();
    let public = serde_json::to_value(payload).unwrap();
    assert!(public.get("qualification").is_none());
    assert!(public.get("build").is_none());
    assert!(public.get("compatibility_ranges").is_none());
    assert_eq!(public["profile"], source["intent"]["profile"]);
    let mut invalid = source;
    invalid["qualification"] = json!({});
    assert!(
        catalog_core::CatalogSourceV2::from_json(&serde_json::to_vec(&invalid).unwrap()).is_err()
    );
}

#[test]
fn v2_intent_rejects_support_asset_role_substitution() {
    let mut profile = profile();
    for (field, role) in [
        ("installer_manifest", "pi-installer-package"),
        ("installer_lock", "pi-installer-lock"),
        ("pi_manifest", "pi-package"),
    ] {
        let digest = profile[field]["sha256"].as_str().unwrap().to_owned();
        profile[field]["url"] = json!(format!(
            "https://github.com/Devalch/Fluxsemble-runtime-catalog/releases/download/catalog-v1-sequence-8/{role}-{digest}.json"
        ));
    }
    let mut intent = json!({"schema_version":2,"sequence":"8","tag":"catalog-v1-sequence-8","generated_at":"2026-11-20T16:00:00Z","expires_at":"2026-12-20T16:00:00Z","title":"Pi","notes":"inputs","profile":profile});
    let digest = intent["profile"]["installer_manifest"]["sha256"]
        .as_str()
        .unwrap();
    intent["profile"]["installer_manifest"]["url"] = json!(format!(
        "https://github.com/Devalch/Fluxsemble-runtime-catalog/releases/download/catalog-v1-sequence-8/wrong-{digest}.json"
    ));
    assert!(
        catalog_core::PiReleaseIntentV2::from_json(&serde_json::to_vec(&intent).unwrap()).is_err()
    );
}

#[test]
fn v2_signed_manifest_binds_all_three_support_assets() {
    let mut profile = profile();
    let mut assets = Vec::new();
    for (field, role) in [
        ("installer_manifest", "pi-installer-package"),
        ("installer_lock", "pi-installer-lock"),
        ("pi_manifest", "pi-package"),
    ] {
        let digest = profile[field]["sha256"].as_str().unwrap().to_owned();
        let name = format!("{role}-{digest}.json");
        profile[field]["url"] = json!(format!(
            "https://github.com/Devalch/Fluxsemble-runtime-catalog/releases/download/catalog-v1-sequence-8/{name}"
        ));
        assets.push(json!({"name":name,"size":profile[field]["size_bytes"].as_str().unwrap().parse::<u64>().unwrap(),"sha256":digest}));
    }
    assets.sort_by_key(|v| v["name"].as_str().unwrap().to_owned());
    let intent = json!({"schema_version":2,"sequence":"8","tag":"catalog-v1-sequence-8","generated_at":"2026-11-20T16:00:00Z","expires_at":"2026-12-20T16:00:00Z","title":"Pi","notes":"inputs","profile":profile});
    let parsed =
        catalog_core::PiReleaseIntentV2::from_json(&serde_json::to_vec(&intent).unwrap()).unwrap();
    let mut value = json!({"schema_version":2,"source_commit":"0123456789abcdef0123456789abcdef01234567","source_tree_sha256":"1".repeat(64),"producer_input_sha256":"2".repeat(64),"tag":"catalog-v1-sequence-8","catalog_envelope":{"name":"catalog-v1.json","size":100,"sha256":"3".repeat(64)},"assets":assets,"signature":{"key_id":"test","signature":"A".repeat(86)}});
    let parse = |v: &Value| {
        catalog_core::SignedReleaseBundleManifestV2::from_json(&serde_json::to_vec(v).unwrap())
            .unwrap()
    };
    assert!(catalog_core::verify_pi_release_bundle_assets_v2(&parsed, &parse(&value)).is_ok());
    value["assets"][0]["sha256"] = json!("9".repeat(64));
    assert!(catalog_core::verify_pi_release_bundle_assets_v2(&parsed, &parse(&value)).is_err());
}
