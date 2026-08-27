use std::path::Path;

use catalog_publish::{FailureOutcome, PublishOutcome};

const MAX_ARGUMENTS: usize = 5;
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
        _ => Err(FailureOutcome::Normal),
    }
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
