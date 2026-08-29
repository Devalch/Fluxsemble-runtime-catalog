use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandPlan {
    pub program: String,
    pub args: Vec<String>,
}

pub fn build_acquire_intent(intent: &Path, package_inputs: &Path, output: &Path) -> CommandPlan {
    plan(
        "catalog-acquire",
        [
            "acquire-intent".to_owned(),
            "--intent".to_owned(),
            path(intent),
            "--package-inputs".to_owned(),
            path(package_inputs),
            "--output".to_owned(),
            path(output),
        ],
    )
}

pub fn build_assemble_intent(config: &Path, input: &Path, output: &Path) -> CommandPlan {
    signer_plan("assemble-intent", config, input, None, output)
}

pub fn build_acquire_source(
    source: &Path,
    package_inputs: &Path,
    source_commit: &str,
    source_tree_sha256: &str,
    output: &Path,
) -> CommandPlan {
    plan(
        "catalog-acquire",
        [
            "acquire-source".to_owned(),
            "--source".to_owned(),
            path(source),
            "--package-inputs".to_owned(),
            path(package_inputs),
            "--source-commit".to_owned(),
            source_commit.to_owned(),
            "--source-tree-sha256".to_owned(),
            source_tree_sha256.to_owned(),
            "--output".to_owned(),
            path(output),
        ],
    )
}

pub fn build_finalize_candidate(config: &Path, input: &Path, output: &Path) -> CommandPlan {
    signer_plan("finalize", config, input, None, output)
}

pub fn build_sign(config: &Path, input: &Path, private_key: &Path, output: &Path) -> CommandPlan {
    signer_plan("sign", config, input, Some(private_key), output)
}

pub fn build_publish_stage_local(bundle: &Path, state: &Path) -> CommandPlan {
    plan(
        "catalog-publish",
        [
            "stage-local".to_owned(),
            "--bundle".to_owned(),
            path(bundle),
            "--state".to_owned(),
            path(state),
        ],
    )
}

pub fn build_publish_stage_remote(state: &Path, broker_config: &Path) -> CommandPlan {
    plan(
        "catalog-publish",
        [
            "stage-remote".to_owned(),
            "--state".to_owned(),
            path(state),
            "--broker-config".to_owned(),
            path(broker_config),
        ],
    )
}

pub fn build_publish_approve(state: &Path, draft_receipt_sha256: &str) -> CommandPlan {
    plan(
        "catalog-publish",
        [
            "approve".to_owned(),
            "--state".to_owned(),
            path(state),
            "--draft-receipt-sha256".to_owned(),
            draft_receipt_sha256.to_owned(),
        ],
    )
}

pub fn build_publish(state: &Path, approval: &Path, broker_config: &Path) -> CommandPlan {
    plan(
        "catalog-publish",
        [
            "publish".to_owned(),
            "--state".to_owned(),
            path(state),
            "--approval".to_owned(),
            path(approval),
            "--broker-config".to_owned(),
            path(broker_config),
        ],
    )
}

fn signer_plan(
    ceremony: &str,
    config: &Path,
    input: &Path,
    private_key: Option<&Path>,
    output: &Path,
) -> CommandPlan {
    let mut args = vec![
        ceremony.to_owned(),
        "--config".to_owned(),
        path(config),
        "--input".to_owned(),
        path(input),
    ];
    if let Some(private_key) = private_key {
        args.extend(["--key".to_owned(), path(private_key)]);
    }
    args.extend(["--output".to_owned(), path(output)]);
    plan("catalog-sign-launcher", args)
}

fn plan(program: &str, args: impl IntoIterator<Item = String>) -> CommandPlan {
    CommandPlan {
        program: program.to_owned(),
        args: args.into_iter().collect(),
    }
}

fn path(value: &Path) -> String {
    value.to_str().unwrap_or("").to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn acquire_intent_command_uses_exact_flags() {
        let plan = build_acquire_intent(
            Path::new("intent.json"),
            Path::new("package-inputs.json"),
            Path::new("transfer"),
        );
        assert_eq!(plan.program, "catalog-acquire");
        assert_eq!(
            plan.args,
            vec![
                "acquire-intent",
                "--intent",
                "intent.json",
                "--package-inputs",
                "package-inputs.json",
                "--output",
                "transfer",
            ]
        );
    }

    #[test]
    fn non_utf8_paths_fail_closed_instead_of_targeting_a_lossy_path() {
        let non_utf8 = Path::new(std::ffi::OsStr::from_bytes(b"release-\xff.key"));
        let plan = build_sign(
            Path::new("launcher.json"),
            Path::new("final-transfer"),
            non_utf8,
            Path::new("signed"),
        );
        assert_eq!(plan.args[6], "");
    }

    #[test]
    fn signer_and_final_acquisition_commands_preserve_exact_argument_boundaries() {
        assert_eq!(
            build_assemble_intent(
                Path::new("launcher.json"),
                Path::new("transfer"),
                Path::new("candidate")
            )
            .args,
            vec![
                "assemble-intent",
                "--config",
                "launcher.json",
                "--input",
                "transfer",
                "--output",
                "candidate"
            ]
        );
        let tree = "11".repeat(32);
        assert_eq!(
            build_acquire_source(
                Path::new("source.json"),
                Path::new("package-inputs.json"),
                "0123456789abcdef0123456789abcdef01234567",
                &tree,
                Path::new("final-transfer")
            )
            .args,
            vec![
                "acquire-source",
                "--source",
                "source.json",
                "--package-inputs",
                "package-inputs.json",
                "--source-commit",
                "0123456789abcdef0123456789abcdef01234567",
                "--source-tree-sha256",
                &tree,
                "--output",
                "final-transfer"
            ]
        );
        assert_eq!(
            build_finalize_candidate(
                Path::new("launcher.json"),
                Path::new("final-transfer"),
                Path::new("final-candidate")
            )
            .args,
            vec![
                "finalize",
                "--config",
                "launcher.json",
                "--input",
                "final-transfer",
                "--output",
                "final-candidate"
            ]
        );
        assert_eq!(
            build_sign(
                Path::new("launcher.json"),
                Path::new("final-transfer"),
                Path::new("release.key"),
                Path::new("signed")
            )
            .args,
            vec![
                "sign",
                "--config",
                "launcher.json",
                "--input",
                "final-transfer",
                "--key",
                "release.key",
                "--output",
                "signed"
            ]
        );
        assert_eq!(
            build_publish_stage_local(Path::new("signed"), Path::new("publish-state")).args,
            vec![
                "stage-local",
                "--bundle",
                "signed",
                "--state",
                "publish-state"
            ]
        );
        assert_eq!(
            build_publish_stage_remote(Path::new("publish-state"), Path::new("broker.json")).args,
            vec![
                "stage-remote",
                "--state",
                "publish-state",
                "--broker-config",
                "broker.json"
            ]
        );
        assert_eq!(
            build_publish_approve(Path::new("publish-state"), &"11".repeat(32)).args,
            vec![
                "approve",
                "--state",
                "publish-state",
                "--draft-receipt-sha256",
                &"11".repeat(32)
            ]
        );
        assert_eq!(
            build_publish(
                Path::new("publish-state"),
                Path::new("approval.json"),
                Path::new("broker.json")
            )
            .args,
            vec![
                "publish",
                "--state",
                "publish-state",
                "--approval",
                "approval.json",
                "--broker-config",
                "broker.json"
            ]
        );
    }
}
