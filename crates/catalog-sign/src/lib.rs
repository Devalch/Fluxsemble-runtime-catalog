use std::{error::Error, fmt, path::Path};

mod key;
mod signing;

#[cfg(feature = "fixture-tools")]
pub use signing::generate_fixture_envelope;

pub use signing::{
    SignReleaseRequest, SignedReleaseBundleV1, UnsignedBundleEntryV1, UnsignedReleaseCandidateV1,
    VerifiedTransferredBundle, assemble_release_intent, assemble_release_intent_from_path,
    finalize_candidate, finalize_candidate_from_path, sign_release, sign_release_from_path,
    verify_transferred_bundle,
};

/// Closed, non-echoing failures from the offline signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignError {
    ArgumentRejected,
    TransferredBundleRejected,
    CandidateRejected,
    SigningKeyRejected,
    OutputRejected,
    VerificationFailed,
}

impl fmt::Display for SignError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("catalog signing failed")
    }
}

impl Error for SignError {}

/// Compatibility wrapper retained for the workspace bootstrap smoke test.
#[must_use]
pub fn summary() -> String {
    format!("catalog-sign:{}", catalog_core::PACKAGES.join(","))
}

pub fn run_cli(args: &[String]) -> Result<String, SignError> {
    signing::run_cli(args)
}

#[must_use]
pub fn is_absolute_bounded_path(path: &Path) -> bool {
    path.is_absolute() && path.as_os_str().as_encoded_bytes().len() <= 4_096
}

#[cfg(test)]
mod tests {
    use super::summary;

    #[test]
    fn reports_workspace_summary() {
        assert!(summary().contains("catalog-sign"));
    }
}
