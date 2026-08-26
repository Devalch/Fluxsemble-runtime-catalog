use std::path::Path;

use catalog_sign::{
    SignError, assemble_release_intent_from_path, finalize_candidate_from_path,
    sign_release_from_path,
};

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
    assert!(matches!(
        sign_release_from_path(
            missing,
            Path::new("/definitely/missing/nonproduction-key.pem"),
            output,
        ),
        Err(SignError::TransferredBundleRejected)
    ));
    assert!(!output.exists());
}
