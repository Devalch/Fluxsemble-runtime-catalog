use std::path::Path;

use catalog_publish::{FailureOutcome, PublishOutcome};

const MAX_ARGUMENTS: usize = 7;
const MAX_ARGUMENT_BYTES: usize = 16 * 1024;

fn main() {
    match run() {
        Ok(message) => println!("{message}"),
        Err(outcome) => {
            let (message, status) = match outcome {
                FailureOutcome::Normal => ("catalog publication failed", 2),
                FailureOutcome::FailedPriorPreserved => {
                    ("catalog publication failed; prior latest preserved", 3)
                }
                FailureOutcome::OutcomeUncertain => (
                    "catalog publication outcome uncertain; recovery required",
                    4,
                ),
                FailureOutcome::RecoveryRequired => ("catalog publication recovery required", 5),
            };
            eprintln!("{message}");
            std::process::exit(status);
        }
    }
}

fn run() -> Result<String, FailureOutcome> {
    let arguments = bounded_arguments()?;
    match arguments.as_slice() {
        [command, bundle_flag, bundle] if command == "verify-bundle" => {
            require_flag(bundle_flag, "--bundle")?;
            let verified = catalog_publish::verify_transferred_signed_bundle(Path::new(bundle))
                .map_err(|error| error.outcome())?;
            Ok(format!(
                "verified sequence={} signed_transfer_sha256={}",
                verified.sequence(),
                verified.signed_transfer_sha256()
            ))
        }
        [command, bundle_flag, bundle, state_flag, state] if command == "stage-local" => {
            require_flag(bundle_flag, "--bundle")?;
            require_flag(state_flag, "--state")?;
            let verified = catalog_publish::verify_transferred_signed_bundle(Path::new(bundle))
                .map_err(|error| error.outcome())?;
            match catalog_publish::stage_local(&verified, Path::new(state))
                .map_err(|error| error.outcome())?
            {
                PublishOutcome::Staged => Ok(format!(
                    "staged sequence={} signed_transfer_sha256={}",
                    verified.sequence(),
                    verified.signed_transfer_sha256()
                )),
                _ => Err(FailureOutcome::Normal),
            }
        }
        [command, state_flag, state] if command == "recover-local" => {
            require_flag(state_flag, "--state")?;
            match catalog_publish::recover_local(Path::new(state))
                .map_err(|error| error.outcome())?
            {
                PublishOutcome::RecoveryCommitted => Ok("recovery committed".to_owned()),
                PublishOutcome::RecoveryAborted => Ok("recovery aborted".to_owned()),
                PublishOutcome::Staged => Err(FailureOutcome::Normal),
            }
        }
        [command, state_flag, state, config_flag, config] if command == "stage-remote" => {
            require_flag(state_flag, "--state")?;
            require_flag(config_flag, "--broker-config")?;
            match catalog_publish::stage_remote(Path::new(state), Path::new(config))
                .map_err(|error| error.outcome())?
            {
                catalog_publish::RemoteWorkflowOutcome::DraftStaged => {
                    Ok("remote draft staged; explicit approval required".to_owned())
                }
                _ => Err(FailureOutcome::Normal),
            }
        }
        [command, state_flag, state, digest_flag, digest] if command == "approve" => {
            require_flag(state_flag, "--state")?;
            require_flag(digest_flag, "--draft-receipt-sha256")?;
            match catalog_publish::approve_remote(Path::new(state), digest)
                .map_err(|error| error.outcome())?
            {
                catalog_publish::RemoteWorkflowOutcome::Approved => {
                    Ok("release approval recorded".to_owned())
                }
                _ => Err(FailureOutcome::Normal),
            }
        }
        [
            command,
            state_flag,
            state,
            approval_flag,
            approval,
            config_flag,
            config,
        ] if command == "publish" => {
            require_flag(state_flag, "--state")?;
            require_flag(approval_flag, "--approval")?;
            require_flag(config_flag, "--broker-config")?;
            match run_remote_future(catalog_publish::publish_remote(
                Path::new(state),
                Path::new(approval),
                Path::new(config),
            ))? {
                catalog_publish::RemoteWorkflowOutcome::PublishedAndLatestVerified => {
                    Ok("release published and latest verified".to_owned())
                }
                _ => Err(FailureOutcome::Normal),
            }
        }
        [command, state_flag, state] if command == "verify-latest" => {
            require_flag(state_flag, "--state")?;
            match run_remote_future(catalog_publish::verify_latest_remote(Path::new(state)))? {
                catalog_publish::RemoteWorkflowOutcome::LatestVerified => {
                    Ok("public latest verified".to_owned())
                }
                _ => Err(FailureOutcome::Normal),
            }
        }
        [
            command,
            state_flag,
            state,
            commit_flag,
            commit,
            config_flag,
            config,
        ] if command == "publish-transport-fixture" => {
            require_flag(state_flag, "--state")?;
            require_flag(commit_flag, "--source-commit")?;
            require_flag(config_flag, "--broker-config")?;
            match catalog_publish::publish_transport_fixture(
                Path::new(state),
                Path::new(config),
                commit,
            )
            .map_err(|error| error.outcome())?
            {
                catalog_publish::RemoteWorkflowOutcome::TransportFixturePublished => {
                    Ok("transport fixture prerelease published".to_owned())
                }
                _ => Err(FailureOutcome::Normal),
            }
        }
        _ => Err(FailureOutcome::Normal),
    }
}

fn run_remote_future(
    future: impl std::future::Future<
        Output = Result<
            catalog_publish::RemoteWorkflowOutcome,
            catalog_publish::RemoteWorkflowError,
        >,
    >,
) -> Result<catalog_publish::RemoteWorkflowOutcome, FailureOutcome> {
    // The CLI is the sole runtime owner. The public fixed-latest APIs are async and never nest or
    // block on a runtime, so library callers can safely await them inside an existing Tokio runtime.
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| FailureOutcome::Normal)?
        .block_on(future)
        .map_err(|error| error.outcome())
}

fn bounded_arguments() -> Result<Vec<String>, FailureOutcome> {
    let mut arguments = Vec::new();
    let mut total = 0_usize;
    for argument in std::env::args_os().skip(1) {
        if arguments.len() == MAX_ARGUMENTS {
            return Err(FailureOutcome::Normal);
        }
        let size = argument.as_encoded_bytes().len();
        total = total.checked_add(size).ok_or(FailureOutcome::Normal)?;
        if size > 4_096 || total > MAX_ARGUMENT_BYTES {
            return Err(FailureOutcome::Normal);
        }
        arguments.push(argument.into_string().map_err(|_| FailureOutcome::Normal)?);
    }
    Ok(arguments)
}

fn require_flag(actual: &str, expected: &str) -> Result<(), FailureOutcome> {
    (actual == expected)
        .then_some(())
        .ok_or(FailureOutcome::Normal)
}
