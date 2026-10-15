use std::path::Path;

use catalog_sign::{SignError, assemble_release_intent_from_path, finalize_candidate_from_path};

#[test]
fn missing_or_unverified_inputs_fail_without_key_or_output_side_effects() {
    let missing = Path::new("/definitely/missing/runtime-catalog-transfer");
    let output = Path::new("/definitely/missing/runtime-catalog-output");
    assert_eq!(
        assemble_release_intent_from_path(missing),
        Err(SignError::TransferredBundleRejected)
    );
    assert_eq!(
        finalize_candidate_from_path(missing),
        Err(SignError::TransferredBundleRejected)
    );
    assert!(!output.exists());
}

#[test]
fn installer_finalization_rejects_fabricated_observations_without_offline_verification() {
    use catalog_acquire::{
        BundleRecord, PublicBundleObject, VerifiedBundleWriteRequest, write_verified_bundle,
    };
    use catalog_core::{CatalogSourceV2, InputSourceKind};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::{fs, os::unix::fs::PermissionsExt};
    let sha = |bytes: &[u8]| format!("{:x}", Sha256::digest(bytes));
    let mut p: Value = serde_json::from_slice(include_bytes!(
        "../../catalog-core/tests/fixtures/catalog/pi-installer-v1/valid-wrapper-root.json"
    ))
    .unwrap();
    let prefix = "https://github.com/Devalch/Fluxsemble-runtime-catalog/releases/download/catalog-v1-sequence-2";
    let mut object_bytes = Vec::new();
    for (key, role, bytes) in [
        (
            "installer_manifest",
            "pi-installer-package",
            b"installer".as_slice(),
        ),
        ("installer_lock", "pi-installer-lock", b"lock".as_slice()),
        ("pi_manifest", "pi-package", b"pi-manifest".as_slice()),
    ] {
        let url = format!("{prefix}/{role}-{}.json", sha(bytes));
        p[key] = json!({"url":url,"size_bytes":bytes.len().to_string(),"sha256":sha(bytes)});
        object_bytes.push((url, bytes.to_vec()));
    }
    for (index, bytes) in [
        (0, b"node archive".as_slice()),
        (1, b"pi archive".as_slice()),
    ] {
        p["components"][index]["artifacts"][0]["size_bytes"] = json!(bytes.len().to_string());
        p["components"][index]["artifacts"][0]["sha256"] = json!(sha(bytes));
        object_bytes.push((
            p["components"][index]["artifacts"][0]["url"]
                .as_str()
                .unwrap()
                .to_owned(),
            bytes.to_vec(),
        ));
    }
    p["locked_packages"][0]["archive_sha256"] =
        p["components"][1]["artifacts"][0]["sha256"].clone();
    let profile =
        catalog_core::PiReleaseProfileV1::from_json(&serde_jcs::to_vec(&p).unwrap()).unwrap();
    let subject = catalog_core::pi_release_subject_sha256(&profile)
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let mut q: Value = serde_json::from_slice(include_bytes!(
        "../../catalog-core/tests/fixtures/catalog/pi-installer-v1/valid-qualification.json"
    ))
    .unwrap();
    q["release_subject_sha256"] = json!(subject);
    q["verification_build"]["compatibility_profile_sha256"] = json!(
        catalog_core::pi_required_contracts_profile_sha256(profile.required_contracts())
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let qbytes = serde_jcs::to_vec(&q).unwrap();
    let mut build = q["verification_build"].clone();
    build.as_object_mut().unwrap().remove("consumer_version");
    let source=CatalogSourceV2::from_json(&serde_jcs::to_vec(&json!({"schema_version":2,"intent":{"schema_version":2,"sequence":"2","tag":"catalog-v1-sequence-2","generated_at":"2026-10-15T00:00:00Z","expires_at":"2026-11-15T00:00:00Z","title":"Synthetic","notes":"Transfer binding test only; these are not executable archives.","profile":p},"build":build,"qualification":{"relative_path":"qualifications/current.json","sha256":sha(&qbytes)}})).unwrap()).unwrap();
    let package = &p["locked_packages"][0];
    let mut inputs = json!({"schema_version":2,"release_subject_sha256":subject,"installer_manifest_source":{"url":"https://github.com/earendil-works/pi/releases/download/v1.2.0/pi-coding-agent-install-package.json","size_bytes":p["installer_manifest"]["size_bytes"],"sha256":p["installer_manifest"]["sha256"]},"installer_lock_source":{"url":"https://github.com/earendil-works/pi/releases/download/v1.2.0/pi-coding-agent-install-package-lock.json","size_bytes":p["installer_lock"]["size_bytes"],"sha256":p["installer_lock"]["sha256"]},"locked_packages":[{"locator":package["locator"],"name":package["name"],"version":package["version"],"resolved_url":package["resolved_url"],"registry_integrity":package["registry_integrity"],"archive_size":10,"archive_sha256":package["archive_sha256"],"declaration_size":11,"declaration_sha256":p["pi_manifest"]["sha256"],"archive_member_count":2,"pruned_reasons":[]}],"pre_prune_package_count":2,"applicable_package_count":1});
    let checksum_url = "https://nodejs.org/dist/v22.19.0/SHASUMS256.txt";
    let checksum_bytes = format!(
        "{}  node-v22.19.0-linux-x64.tar.xz\n",
        p["components"][0]["artifacts"][0]["sha256"]
            .as_str()
            .unwrap()
    )
    .into_bytes();
    inputs["auxiliary_inputs"] = json!([{"url":checksum_url,"size_bytes":checksum_bytes.len().to_string(),"sha256":sha(&checksum_bytes)}]);
    object_bytes.push((checksum_url.into(), checksum_bytes));
    let root = std::env::temp_dir().join(format!(
        "pi-sign-v2-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    for omit in [None, Some(0), Some(1), Some(2)] {
        let name = format!("bundle-{omit:?}");
        let mut objects = Vec::new();
        for (index, (url, bytes)) in object_bytes.iter().enumerate() {
            if omit == Some(index) {
                continue;
            }
            let path = root.join(format!("{name}-{index}"));
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
            objects.push(
                PublicBundleObject::verified_file(
                    fs::File::open(path).unwrap(),
                    url.clone(),
                    bytes.len() as u64,
                    sha(bytes),
                )
                .unwrap(),
            );
        }
        write_verified_bundle(
            VerifiedBundleWriteRequest {
                source_kind: InputSourceKind::CatalogSource,
                source_sha256: catalog_core::catalog_source_v2_digest(&source)
                    .unwrap()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect(),
                compatibility_input_sha256: subject.clone(),
                source_commit: Some("1".repeat(40)),
                source_tree_sha256: Some("2".repeat(64)),
                records: vec![
                    BundleRecord {
                        role: "catalog_source".into(),
                        bytes: serde_jcs::to_vec(&source).unwrap(),
                    },
                    BundleRecord {
                        role: "qualification".into(),
                        bytes: qbytes.clone(),
                    },
                    BundleRecord {
                        role: "package_inputs".into(),
                        bytes: serde_jcs::to_vec(&inputs).unwrap(),
                    },
                ],
                objects,
            },
            &root.join(&name),
        )
        .unwrap();
        let result = finalize_candidate_from_path(&root.join(name));
        assert!(
            result.is_err(),
            "self-issued observations must not qualify raw text archives"
        );
    }
}

#[path = "../../catalog-installer-verify/tests/support/mod.rs"]
mod installer_fixtures;

#[test]
fn production_finalization_requires_offline_graph_and_complete_auxiliary_objects() {
    use catalog_acquire::{
        BundleRecord, PublicBundleObject, VerifiedBundleWriteRequest, write_verified_bundle,
    };
    use catalog_core::{CatalogSourceV2, InputSourceKind};
    use installer_fixtures::{sha256, transferred_fixture};
    use serde_json::{Value, json};
    use std::{fs, os::unix::fs::PermissionsExt};
    let (intent, inputs, objects) = transferred_fixture();
    let subject = catalog_core::pi_release_subject_sha256(intent.profile())
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let mut q: Value = serde_json::from_slice(include_bytes!(
        "../../catalog-core/tests/fixtures/catalog/pi-installer-v1/valid-qualification.json"
    ))
    .unwrap();
    q["release_subject_sha256"] = json!(subject);
    q["required_contracts"] = serde_json::to_value(intent.profile().required_contracts()).unwrap();
    q["consumer_requirement"] = json!(intent.profile().consumer_requirement().as_str());
    q["verification_build"]["compatibility_profile_sha256"] = json!(
        catalog_core::pi_required_contracts_profile_sha256(intent.profile().required_contracts())
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let qbytes = serde_jcs::to_vec(&q).unwrap();
    let mut build = q["verification_build"].clone();
    build.as_object_mut().unwrap().remove("consumer_version");
    let source = CatalogSourceV2::from_json(&serde_jcs::to_vec(&json!({"schema_version":2,"intent":intent,"build":build,"qualification":{"relative_path":"qualifications/current.json","sha256":sha256(&qbytes)}})).unwrap()).unwrap();
    let root = std::env::temp_dir().join(format!(
        "pi-sign-owner-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let mut cases = vec!["matching".to_owned(), "false-observations".to_owned()];
    cases.extend(objects.keys().map(|url| format!("omit:{url}")));
    for (case_index, case) in cases.iter().enumerate() {
        let mut materialized = Vec::new();
        for (index, (url, bytes)) in objects.iter().enumerate() {
            if case.strip_prefix("omit:") == Some(url.as_str()) {
                continue;
            }
            let path = root.join(format!("object-{case_index}-{index}"));
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
            materialized.push(
                PublicBundleObject::verified_file(
                    fs::File::open(path).unwrap(),
                    url.clone(),
                    bytes.len() as u64,
                    sha256(bytes),
                )
                .unwrap(),
            );
        }
        let mut input_value = serde_json::to_value(&inputs).unwrap();
        if case == "false-observations" {
            input_value["locked_packages"][0]["archive_member_count"] = json!(999);
        }
        let output = root.join(format!("bundle-{case_index}"));
        write_verified_bundle(
            VerifiedBundleWriteRequest {
                source_kind: InputSourceKind::CatalogSource,
                source_sha256: catalog_core::catalog_source_v2_digest(&source)
                    .unwrap()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect(),
                compatibility_input_sha256: subject.clone(),
                source_commit: Some("1".repeat(40)),
                source_tree_sha256: Some("2".repeat(64)),
                records: vec![
                    BundleRecord {
                        role: "catalog_source".into(),
                        bytes: serde_jcs::to_vec(&source).unwrap(),
                    },
                    BundleRecord {
                        role: "qualification".into(),
                        bytes: qbytes.clone(),
                    },
                    BundleRecord {
                        role: "package_inputs".into(),
                        bytes: serde_jcs::to_vec(&input_value).unwrap(),
                    },
                ],
                objects: materialized,
            },
            &output,
        )
        .unwrap();
        let result = finalize_candidate_from_path(&output);
        if case == "matching" {
            assert_eq!(result.unwrap().support_asset_names().len(), 4);
        } else {
            assert!(result.is_err(), "accepted {case}");
        }
    }
}
