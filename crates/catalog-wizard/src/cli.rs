#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Release(ReleaseOptions),
    Resume(ResumeOptions),
    RotateKey,
    TrustMachine,
    Check,
    Help(HelpTopic),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseOptions {
    pub pi: Option<String>,
    pub node: Option<String>,
    pub mode: Option<RunMode>,
    pub config: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeOptions {
    pub qualification: Option<String>,
    pub config: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RunMode {
    DryRun,
    PublishCapable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelpTopic {
    Root,
    Command(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliError {
    ConflictingMode,
    DuplicateOption(&'static str),
    MissingOptionValue(&'static str),
    UnexpectedArgument(String),
    UnknownCommand(String),
}

const ROOT_HELP: &str = "\
catalog-wizard <command> [options]

Commands:
  release        Create and optionally publish a new runtime catalog.
  resume         Continue an interrupted release.
  rotate-key     Approve a new private signing key for future releases.
  trust-machine  Approve the current machine for release operations.
  check          Check local setup without signing or publishing.
  help           Show help.

Run `catalog-wizard <command> --help` for command options.
";

const RELEASE_HELP: &str = "\
catalog-wizard release [options]

Create and optionally publish a new runtime catalog.

Options:
  --pi <version>    Preselect the Pi version to publish.
  --node <version>  Preselect the Node version to use.
  --dry-run         Force non-mutating mode.
  --publish         Allow guided publish-capable mode.
  --config <path>   Use a specific wizard config file.
  -h, --help        Show this help.
";

const RESUME_HELP: &str = "\
catalog-wizard resume [options]

Continue an interrupted release.

Options:
  --qualification <path>  Supply a returned Fluxsemble qualification handoff.
  --config <path>         Use a specific wizard config file.
  -h, --help              Show this help.
";

const ROTATE_KEY_HELP: &str = "\
catalog-wizard rotate-key

Approve a new private signing key for future releases.

Options:
  -h, --help  Show this help.
";

const TRUST_MACHINE_HELP: &str = "\
catalog-wizard trust-machine

Approve the current machine for release operations.

Options:
  -h, --help  Show this help.
";

const CHECK_HELP: &str = "\
catalog-wizard check

Check local setup without signing or publishing.

Options:
  -h, --help  Show this help.
";

const HELP_HELP: &str = "\
catalog-wizard help [command]

Show root help or help for one command.
";

pub fn root_help() -> &'static str {
    ROOT_HELP
}

pub fn command_help(command: &str) -> Option<&'static str> {
    match command {
        "release" => Some(RELEASE_HELP),
        "resume" => Some(RESUME_HELP),
        "rotate-key" => Some(ROTATE_KEY_HELP),
        "trust-machine" => Some(TRUST_MACHINE_HELP),
        "check" => Some(CHECK_HELP),
        "help" => Some(HELP_HELP),
        _ => None,
    }
}

pub fn parse_args(args: &[String]) -> Result<Command, CliError> {
    match args {
        [] => Ok(Command::Help(HelpTopic::Root)),
        [flag] if is_help_flag(flag) => Ok(Command::Help(HelpTopic::Root)),
        [command, rest @ ..] if command == "release" => parse_release(rest),
        [command, rest @ ..] if command == "resume" => parse_resume(rest),
        [command, rest @ ..] if command == "help" => parse_help(rest),
        [command, rest @ ..] if is_simple_command(command) => parse_simple_command(command, rest),
        [command, ..] => Err(CliError::UnknownCommand(command.clone())),
    }
}

fn parse_release(args: &[String]) -> Result<Command, CliError> {
    if args.iter().any(|argument| is_help_flag(argument)) {
        return Ok(Command::Help(HelpTopic::Command("release".to_owned())));
    }

    let mut options = ReleaseOptions {
        pi: None,
        node: None,
        mode: None,
        config: None,
    };
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--pi" => set_option(&mut options.pi, args, &mut index, "--pi")?,
            "--node" => set_option(&mut options.node, args, &mut index, "--node")?,
            "--config" => set_option(&mut options.config, args, &mut index, "--config")?,
            "--dry-run" => set_mode(&mut options.mode, RunMode::DryRun)?,
            "--publish" => set_mode(&mut options.mode, RunMode::PublishCapable)?,
            argument => return Err(CliError::UnexpectedArgument(argument.to_owned())),
        }
        index += 1;
    }
    Ok(Command::Release(options))
}

fn parse_resume(args: &[String]) -> Result<Command, CliError> {
    if args.iter().any(|argument| is_help_flag(argument)) {
        return Ok(Command::Help(HelpTopic::Command("resume".to_owned())));
    }

    let mut options = ResumeOptions {
        qualification: None,
        config: None,
    };
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--qualification" => set_option(
                &mut options.qualification,
                args,
                &mut index,
                "--qualification",
            )?,
            "--config" => set_option(&mut options.config, args, &mut index, "--config")?,
            argument => return Err(CliError::UnexpectedArgument(argument.to_owned())),
        }
        index += 1;
    }
    Ok(Command::Resume(options))
}

fn parse_help(args: &[String]) -> Result<Command, CliError> {
    match args {
        [] => Ok(Command::Help(HelpTopic::Root)),
        [flag] if is_help_flag(flag) => Ok(Command::Help(HelpTopic::Command("help".to_owned()))),
        [command] if command_help(command).is_some() => {
            Ok(Command::Help(HelpTopic::Command(command.clone())))
        }
        [command] => Err(CliError::UnknownCommand(command.clone())),
        [argument, ..] => Err(CliError::UnexpectedArgument(argument.clone())),
    }
}

fn parse_simple_command(command: &str, args: &[String]) -> Result<Command, CliError> {
    if args.iter().any(|argument| is_help_flag(argument)) {
        return Ok(Command::Help(HelpTopic::Command(command.to_owned())));
    }
    if let Some(argument) = args.first() {
        return Err(CliError::UnexpectedArgument(argument.clone()));
    }

    match command {
        "rotate-key" => Ok(Command::RotateKey),
        "trust-machine" => Ok(Command::TrustMachine),
        "check" => Ok(Command::Check),
        _ => unreachable!("simple commands are checked before parsing"),
    }
}

fn is_simple_command(command: &str) -> bool {
    matches!(command, "rotate-key" | "trust-machine" | "check")
}

fn is_help_flag(argument: &str) -> bool {
    matches!(argument, "-h" | "--help")
}

fn set_option(
    destination: &mut Option<String>,
    args: &[String],
    index: &mut usize,
    option: &'static str,
) -> Result<(), CliError> {
    if destination.is_some() {
        return Err(CliError::DuplicateOption(option));
    }
    *index += 1;
    let value = args
        .get(*index)
        .ok_or(CliError::MissingOptionValue(option))?;
    *destination = Some(value.clone());
    Ok(())
}

fn set_mode(mode: &mut Option<RunMode>, new_mode: RunMode) -> Result<(), CliError> {
    match mode {
        Some(existing_mode) if *existing_mode != new_mode => Err(CliError::ConflictingMode),
        Some(_) => Err(CliError::DuplicateOption(match new_mode {
            RunMode::DryRun => "--dry-run",
            RunMode::PublishCapable => "--publish",
        })),
        None => {
            *mode = Some(new_mode);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn root_help_accepts_short_and_long_flags() {
        assert!(matches!(
            parse_args(&args(&["-h"])),
            Ok(Command::Help(HelpTopic::Root))
        ));
        assert!(matches!(
            parse_args(&args(&["--help"])),
            Ok(Command::Help(HelpTopic::Root))
        ));
        assert!(root_help().contains("catalog-wizard <command>"));
        assert!(root_help().contains("release"));
    }

    #[test]
    fn release_help_accepts_short_and_long_flags() {
        assert!(
            matches!(parse_args(&args(&["release", "-h"])), Ok(Command::Help(HelpTopic::Command(name))) if name == "release")
        );
        assert!(
            matches!(parse_args(&args(&["release", "--help"])), Ok(Command::Help(HelpTopic::Command(name))) if name == "release")
        );
        assert!(command_help("release").unwrap().contains("--pi <version>"));
        assert!(
            command_help("release")
                .unwrap()
                .contains("--node <version>")
        );
    }

    #[test]
    fn every_subcommand_accepts_short_and_long_help_flags() {
        for command in [
            "release",
            "resume",
            "rotate-key",
            "trust-machine",
            "check",
            "help",
        ] {
            for flag in ["-h", "--help"] {
                assert!(matches!(
                    parse_args(&args(&[command, flag])),
                    Ok(Command::Help(HelpTopic::Command(name))) if name == command
                ));
            }
        }
    }

    #[test]
    fn release_parses_versions_and_mode() {
        let parsed = parse_args(&args(&[
            "release",
            "--pi",
            "0.84.0",
            "--node",
            "22.20.0",
            "--publish",
        ]))
        .unwrap();
        match parsed {
            Command::Release(options) => {
                assert_eq!(options.pi.as_deref(), Some("0.84.0"));
                assert_eq!(options.node.as_deref(), Some("22.20.0"));
                assert_eq!(options.mode, Some(RunMode::PublishCapable));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn resume_parses_qualification_handoff_path() {
        let parsed = parse_args(&args(&[
            "resume",
            "--qualification",
            "/safe/returned-handoff",
        ]))
        .unwrap();
        match parsed {
            Command::Resume(options) => {
                assert_eq!(
                    options.qualification.as_deref(),
                    Some("/safe/returned-handoff")
                );
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn release_rejects_dry_run_and_publish_together() {
        assert!(matches!(
            parse_args(&args(&["release", "--dry-run", "--publish"])),
            Err(CliError::ConflictingMode)
        ));
    }
}
