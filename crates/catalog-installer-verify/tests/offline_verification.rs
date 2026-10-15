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
