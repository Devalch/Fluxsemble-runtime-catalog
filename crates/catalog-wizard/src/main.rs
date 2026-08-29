use std::path::PathBuf;

use catalog_wizard::{
    cli::{self, Command, HelpTopic},
    prompt::StdioPrompter,
    trust,
};

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match cli::parse_args(&args) {
        Ok(Command::Help(HelpTopic::Root)) => println!("{}", cli::root_help()),
        Ok(Command::Help(HelpTopic::Command(command))) => {
            println!(
                "{}",
                cli::command_help(&command).unwrap_or(cli::root_help())
            )
        }
        Ok(Command::TrustMachine) => run_trust_machine(),
        Ok(command) => {
            eprintln!("Command requires the guided workflow modules: {command:?}");
            std::process::exit(2);
        }
        Err(_) => {
            eprintln!("Invalid command. Run `catalog-wizard --help`.");
            std::process::exit(2);
        }
    }
}

fn run_trust_machine() {
    let result = (|| {
        let repo = std::env::current_dir().map_err(|_| catalog_wizard::WizardError::Config)?;
        let home =
            PathBuf::from(std::env::var_os("HOME").ok_or(catalog_wizard::WizardError::Config)?);
        if !home.is_absolute() {
            return Err(catalog_wizard::WizardError::Config);
        }
        let profiles = home.join(".config/fluxsemble-runtime-catalog/trusted-machines");
        let mut prompter = StdioPrompter::new();
        trust::trust_machine(&mut prompter, &repo, &profiles)
    })();
    if result.is_err() {
        eprintln!("Trust-machine setup stopped safely.");
        std::process::exit(2);
    }
}
