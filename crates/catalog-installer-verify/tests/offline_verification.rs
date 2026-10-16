mod support;
use catalog_installer_verify::{AcquireError, PackageInputManifestV2, verify_installer_release};
use serde_json::json;
use support::{sha256, transferred_fixture};

#[test]
fn offline_owner_replays_real_archives_and_rejects_invented_observations() {
    let (intent, inputs, objects) = transferred_fixture();
    let read = |url: &str, max: usize| {
        objects
            .get(url)
            .filter(|b| b.len() <= max)
            .cloned()
            .ok_or(AcquireError::Input)
    };
    verify_installer_release(&intent, &inputs, read).unwrap();
    let mut value = serde_json::to_value(&inputs).unwrap();
    value["locked_packages"][0]["archive_member_count"] = json!(999);
    let altered = PackageInputManifestV2::from_json(&serde_jcs::to_vec(&value).unwrap()).unwrap();
    assert!(verify_installer_release(&intent, &altered, read).is_err());
}

#[test]
fn offline_owner_requires_exact_auxiliary_evidence_and_replays_its_policy() {
    let (intent, inputs, objects) = transferred_fixture();
    assert!(inputs.auxiliary_inputs().len() >= 2);
    for (index, auxiliary) in inputs.auxiliary_inputs().iter().enumerate() {
        let mut missing = objects.clone();
        missing.remove(auxiliary.url());
        assert!(
            verify_installer_release(&intent, &inputs, |url, _| missing
                .get(url)
                .cloned()
                .ok_or(AcquireError::Input))
            .is_err()
        );
        // Even a freshly hash-bound substitution must satisfy the original metadata/checksum policy.
        let replacement = if auxiliary.url().ends_with("SHASUMS256.txt") {
            format!("{}  node-v22.19.0-linux-x64.tar.xz\n", "0".repeat(64)).into_bytes()
        } else {
            let mut value: serde_json::Value =
                serde_json::from_slice(&objects[auxiliary.url()]).unwrap();
            value["version"] = json!("9.9.9");
            serde_json::to_vec(&value).unwrap()
        };
        let mut altered_objects = objects.clone();
        altered_objects.insert(auxiliary.url().into(), replacement.clone());
        let mut altered_inputs = serde_json::to_value(&inputs).unwrap();
        altered_inputs["auxiliary_inputs"][index]["sha256"] = json!(sha256(&replacement));
        altered_inputs["auxiliary_inputs"][index]["size_bytes"] =
            json!(replacement.len().to_string());
        let altered_inputs =
            PackageInputManifestV2::from_json(&serde_jcs::to_vec(&altered_inputs).unwrap())
                .unwrap();
        assert!(
            verify_installer_release(&intent, &altered_inputs, |url, _| altered_objects
                .get(url)
                .cloned()
                .ok_or(AcquireError::Input))
            .is_err()
        );
    }
}

#[test]
fn repeated_package_identity_shares_one_exact_registry_response() {
    let mut bytes = support::fixture_bytes("two-version-graph", "1.2.0");
    let lock_url = "https://github.com/earendil-works/pi/releases/download/v1.2.0/pi-coding-agent-install-package-lock.json";
    let mut lock: serde_json::Value = serde_json::from_slice(&bytes[lock_url]).unwrap();
    lock["packages"]["node_modules/extra/node_modules/dep"] =
        lock["packages"]["node_modules/dep"].clone();
    bytes.insert(lock_url.into(), serde_json::to_vec(&lock).unwrap());
    struct Bytes(std::collections::BTreeMap<String, Vec<u8>>);
    impl catalog_installer_verify::InstallerInputs for Bytes {
        fn read(&self, url: &str, maximum: usize) -> Result<Vec<u8>, AcquireError> {
            self.0
                .get(url)
                .filter(|b| b.len() <= maximum)
                .cloned()
                .ok_or(AcquireError::Input)
        }
    }
    let result =
        catalog_installer_verify::derive_installer_release(support::request(), &Bytes(bytes))
            .unwrap();
    assert_eq!(result.inputs.auxiliary_inputs().len(), 2);
    assert_eq!(result.inputs.locked_package_count(), 4);
}

#[test]
fn immutable_public_installer_inputs_match_independent_derivation_and_replay() {
    use catalog_core::{PiReleaseIntentV2, PiRequiredContractsV1};
    use catalog_installer_verify::{
        DiscoverPiReleaseRequest, InstallerInputs, PiInstallerDiscoveryPolicy,
        derive_installer_release,
    };
    use std::{collections::BTreeMap, path::Path};
    struct Bytes(BTreeMap<String, Vec<u8>>);
    impl InstallerInputs for Bytes {
        fn read(&self, url: &str, maximum: usize) -> Result<Vec<u8>, AcquireError> {
            self.0
                .get(url)
                .filter(|b| b.len() <= maximum)
                .cloned()
                .ok_or_else(|| {
                    eprintln!("missing or oversized admitted input: {url} maximum={maximum}");
                    AcquireError::Input
                })
        }
    }
    let root =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/pi-installer-release-v1");
    let admission_bytes = std::fs::read(root.join("input-admission-v1.json")).unwrap();
    assert_eq!(admission_bytes.len(), 63555);
    assert_eq!(
        sha256(&admission_bytes),
        "20b4402e9bedbb2c92caa2b04f4ee7552740c0c2ac2eb8c331c8e3f72f87db07"
    );
    let admission: serde_json::Value = serde_json::from_slice(&admission_bytes).unwrap();
    let mut objects = BTreeMap::new();
    for record in admission["files"].as_array().unwrap() {
        let path = record["path"].as_str().unwrap();
        assert_eq!(
            path,
            format!("objects/{}", record["sha256"].as_str().unwrap())
        );
        let bytes = std::fs::read(root.join("public-inputs").join(path)).unwrap();
        assert_eq!(
            bytes.len().to_string(),
            record["size_bytes"].as_str().unwrap()
        );
        assert_eq!(sha256(&bytes), record["sha256"].as_str().unwrap());
        assert!(
            objects
                .insert(record["url"].as_str().unwrap().to_owned(), bytes)
                .is_none()
        );
    }
    let evidence: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join("generated/evidence-manifest-v2.json")).unwrap(),
    )
    .unwrap();
    for record in evidence["derived_inputs"].as_array().unwrap() {
        let bytes = std::fs::read(
            root.join("generated")
                .join(record["path"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(
            bytes.len().to_string(),
            record["size_bytes"].as_str().unwrap()
        );
        assert_eq!(sha256(&bytes), record["sha256"].as_str().unwrap());
        assert!(
            objects
                .insert(record["url"].as_str().unwrap().to_owned(), bytes)
                .is_none()
        );
    }
    let intent_bytes =
        std::fs::read(root.join("generated/initial-release-intent-v2.json")).unwrap();
    let inputs_bytes =
        std::fs::read(root.join("generated/package-input-manifest-v2.json")).unwrap();
    assert_eq!(
        sha256(&intent_bytes),
        evidence["intent_sha256"].as_str().unwrap()
    );
    assert_eq!(
        sha256(&inputs_bytes),
        evidence["package_inputs_sha256"].as_str().unwrap()
    );
    let intent = PiReleaseIntentV2::from_json(&intent_bytes).unwrap();
    let inputs = PackageInputManifestV2::from_json(&inputs_bytes).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&intent_bytes).unwrap();
    let profile = &value["profile"];
    let pi_version = profile["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["component_id"] == profile["pi_component_id"])
        .unwrap()["version"]
        .as_str()
        .unwrap();
    let request = DiscoverPiReleaseRequest {
        sequence: value["sequence"].as_str().unwrap().parse().unwrap(),
        generated_at: value["generated_at"].as_str().unwrap().into(),
        expires_at: value["expires_at"].as_str().unwrap().into(),
        title: value["title"].as_str().unwrap().into(),
        notes: value["notes"].as_str().unwrap().into(),
        pi_version: pi_version.into(),
        node_version: profile["node_version"].as_str().unwrap().into(),
        target: profile["target"].as_str().unwrap().into(),
        installer_policy: Some(PiInstallerDiscoveryPolicy {
            consumer_requirement: profile["consumer_requirement"].as_str().unwrap().into(),
            required_contracts: PiRequiredContractsV1::from_json(
                &serde_json::to_vec(&profile["required_contracts"]).unwrap(),
            )
            .unwrap(),
        }),
    };
    let mut bytes = Bytes(objects);
    let derived = derive_installer_release(request, &bytes).unwrap();
    assert_eq!(serde_json::to_value(&derived.profile).unwrap(), *profile);
    assert_eq!(
        serde_json::to_value(&derived.inputs).unwrap(),
        serde_json::to_value(&inputs).unwrap()
    );
    for (original, planned) in [
        (
            inputs.installer_manifest_source(),
            intent.profile().installer_manifest(),
        ),
        (
            inputs.installer_lock_source(),
            intent.profile().installer_lock(),
        ),
    ] {
        bytes.0.insert(
            planned.url().as_str().into(),
            bytes.0[original.url()].clone(),
        );
    }
    let pi = intent
        .profile()
        .locked_packages()
        .iter()
        .find(|p| p.locator() == intent.profile().pi_package_locator())
        .unwrap();
    let archive_bytes = &bytes.0[pi.resolved_url().as_str()];
    let mut archive = catalog_installer_verify::archive::VerifiedArchive::verify(
        std::io::Cursor::new(archive_bytes),
        pi.resolved_url().as_str().into(),
        archive_bytes.len() as u64,
        sha256(archive_bytes),
        Some(pi.registry_integrity().as_str().into()),
    )
    .unwrap();
    let declaration = catalog_installer_verify::archive::inspect_npm_archive(&mut archive, false)
        .unwrap()
        .declaration;
    bytes.0.insert(
        intent.profile().pi_manifest().url().as_str().into(),
        declaration,
    );
    verify_installer_release(&intent, &inputs, |url, maximum| bytes.read(url, maximum)).unwrap();
    let mut invented = serde_json::to_value(&inputs).unwrap();
    invented["locked_packages"][0]["archive_member_count"] = json!(999);
    let invented =
        PackageInputManifestV2::from_json(&serde_json::to_vec(&invented).unwrap()).unwrap();
    assert!(
        verify_installer_release(&intent, &invented, |url, maximum| bytes.read(url, maximum))
            .is_err()
    );
}
