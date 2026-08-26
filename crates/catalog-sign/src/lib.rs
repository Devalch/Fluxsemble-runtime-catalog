use std::{error::Error, fmt, path::Path};

mod isolation;
mod key;
mod signing;

#[cfg(feature = "fixture-tools")]
pub use signing::generate_fixture_envelope;

pub use isolation::{
    IsolationAttestationV1, IsolationMode, SignerIsolation, emit_reverse_transfer_manifest,
    enter_signer_isolation,
};
pub use signing::{
    SignedReleaseBundleV1, UnsignedBundleEntryV1, UnsignedReleaseCandidateV1,
    VerifiedTransferredBundle, assemble_release_intent, assemble_release_intent_from_path,
    finalize_candidate, finalize_candidate_from_path, verify_transferred_bundle,
};

/// Closed, non-echoing failures from the offline signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignError {
    IsolationRejected,
    ArgumentRejected,
    TransferredBundleRejected,
    CandidateRejected,
    SigningKeyRejected,
    OutputRejected,
    OutputDurabilityUncertain,
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

/// Runs the closed inner CLI only with capability returned by [`enter_signer_isolation`].
///
/// Raw signing seams are intentionally not exported.
///
/// ```compile_fail
/// let _ = catalog_sign::sign_release_from_path;
/// ```
pub fn run_isolated_cli(isolation: &SignerIsolation, args: &[String]) -> Result<String, SignError> {
    let expected = match isolation.attestation().mode() {
        IsolationMode::AssembleIntent => &[
            "assemble-intent",
            "--input",
            "/input",
            "--output",
            "/output/candidate.json",
        ][..],
        IsolationMode::Finalize => &[
            "finalize",
            "--input",
            "/input",
            "--output",
            "/output/candidate.json",
        ][..],
        IsolationMode::Sign => &[
            "sign",
            "--input",
            "/input",
            "--key",
            "/key/runtime-catalog-private.pem",
            "--output",
            "/output/signed-release-bundle",
        ][..],
        IsolationMode::RecoverSign => &[
            "recover-sign",
            "--input",
            "/input",
            "--output",
            "/output/signed-release-bundle",
        ][..],
        IsolationMode::IsolationProbe => &["__isolation-probe"][..],
    };
    if args.iter().map(String::as_str).ne(expected.iter().copied()) {
        return Err(SignError::ArgumentRejected);
    }
    if isolation.attestation().mode() == IsolationMode::IsolationProbe {
        isolation::run_isolation_probe(isolation)?;
        Ok("isolation probe complete".to_owned())
    } else {
        signing::run_isolated_cli(isolation.verified_transfer(), args)
    }
}

pub fn recover_production_isolated_output(isolation: &SignerIsolation) -> Result<(), SignError> {
    if !matches!(
        isolation.attestation().mode(),
        IsolationMode::Sign | IsolationMode::RecoverSign
    ) {
        return Err(SignError::ArgumentRejected);
    }
    signing::recover_production_isolated_output(isolation.verified_transfer())
}

#[cfg(feature = "fixture-tools")]
pub fn run_fixture_isolated_cli(
    isolation: &SignerIsolation,
    args: &[String],
) -> Result<String, SignError> {
    let expected = match isolation.attestation().mode() {
        IsolationMode::Sign => &[
            "sign",
            "--input",
            "/input",
            "--key",
            "/key/runtime-catalog-private.pem",
            "--output",
            "/output/signed-release-bundle",
        ][..],
        IsolationMode::RecoverSign => &[
            "recover-sign",
            "--input",
            "/input",
            "--output",
            "/output/signed-release-bundle",
        ][..],
        _ => return Err(SignError::ArgumentRejected),
    };
    if args.iter().map(String::as_str).ne(expected.iter().copied()) {
        return Err(SignError::ArgumentRejected);
    }
    signing::run_fixture_isolated_cli(isolation.verified_transfer(), args)
}

#[cfg(feature = "fixture-tools")]
pub fn recover_fixture_isolated_output(isolation: &SignerIsolation) -> Result<(), SignError> {
    if !matches!(
        isolation.attestation().mode(),
        IsolationMode::Sign | IsolationMode::RecoverSign
    ) {
        return Err(SignError::ArgumentRejected);
    }
    signing::recover_fixture_isolated_output(isolation.verified_transfer())
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
