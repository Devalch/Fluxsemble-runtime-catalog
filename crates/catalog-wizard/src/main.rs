use catalog_wizard::cli::{self, Command, HelpTopic};

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
