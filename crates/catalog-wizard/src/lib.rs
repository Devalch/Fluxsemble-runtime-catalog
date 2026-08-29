pub mod cli;
pub mod config;
pub mod intent;
pub mod key_rotation;
pub mod npm;
pub mod prompt;
pub mod qualification;
pub mod sequence;
pub mod state;
pub mod trust;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WizardError {
    Cli(cli::CliError),
    Io,
    Config,
    State,
    ExternalCommand,
    Discovery,
    Qualification,
    UserDeclined,
}
