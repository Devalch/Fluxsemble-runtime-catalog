pub mod cli;
pub mod config;
pub mod state;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WizardError {
    Cli(cli::CliError),
    Io,
    Config,
    State,
    ExternalCommand,
    UserDeclined,
}
