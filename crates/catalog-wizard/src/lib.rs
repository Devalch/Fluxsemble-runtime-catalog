pub mod cli;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WizardError {
    Cli(cli::CliError),
    Io,
    Config,
    State,
    ExternalCommand,
    UserDeclined,
}
