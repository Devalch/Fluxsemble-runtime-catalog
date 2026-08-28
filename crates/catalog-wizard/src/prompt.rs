use crate::WizardError;
use std::{
    collections::VecDeque,
    io::{self, Write},
};

pub trait Prompter {
    fn ask(&mut self, message: &str) -> Result<String, WizardError>;
    fn say(&mut self, message: &str) -> Result<(), WizardError>;
}

#[derive(Debug, Default)]
pub struct StdioPrompter;

impl StdioPrompter {
    pub fn new() -> Self {
        Self
    }
}

impl Prompter for StdioPrompter {
    fn ask(&mut self, message: &str) -> Result<String, WizardError> {
        let mut stdout = io::stdout().lock();
        write!(stdout, "{message}").map_err(|_| WizardError::Io)?;
        stdout.flush().map_err(|_| WizardError::Io)?;

        let mut answer = String::new();
        if io::stdin()
            .read_line(&mut answer)
            .map_err(|_| WizardError::Io)?
            == 0
        {
            return Err(WizardError::Io);
        }

        Ok(answer.trim_end_matches(['\r', '\n']).to_owned())
    }

    fn say(&mut self, message: &str) -> Result<(), WizardError> {
        let mut stdout = io::stdout().lock();
        writeln!(stdout, "{message}").map_err(|_| WizardError::Io)
    }
}

#[derive(Debug, Default)]
pub struct ScriptedPrompter {
    answers: VecDeque<String>,
}

impl ScriptedPrompter {
    pub fn new<I, S>(answers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            answers: answers.into_iter().map(Into::into).collect(),
        }
    }
}

impl Prompter for ScriptedPrompter {
    fn ask(&mut self, _: &str) -> Result<String, WizardError> {
        self.answers.pop_front().ok_or(WizardError::Io)
    }

    fn say(&mut self, _: &str) -> Result<(), WizardError> {
        Ok(())
    }
}

pub fn confirm_yes_no(
    prompter: &mut dyn Prompter,
    message: &str,
    default: bool,
) -> Result<bool, WizardError> {
    match prompter.ask(message)?.as_str() {
        "" => Ok(default),
        "yes" | "YES" => Ok(true),
        "no" | "NO" => Ok(false),
        _ => Err(WizardError::UserDeclined),
    }
}

pub fn require_phrase(
    prompter: &mut dyn Prompter,
    message: &str,
    phrase: &str,
) -> Result<(), WizardError> {
    if prompter.ask(message)? == phrase {
        Ok(())
    } else {
        Err(WizardError::UserDeclined)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yes_no_uses_default_on_empty_answer() {
        let mut prompt = ScriptedPrompter::new([""]);
        assert!(confirm_yes_no(&mut prompt, "Continue?", true).unwrap());
    }

    #[test]
    fn exact_phrase_accepts_only_exact_text() {
        let mut bad = ScriptedPrompter::new(["sign"]);
        assert!(matches!(
            require_phrase(&mut bad, "Type SIGN", "SIGN"),
            Err(WizardError::UserDeclined)
        ));

        let mut good = ScriptedPrompter::new(["SIGN"]);
        assert!(require_phrase(&mut good, "Type SIGN", "SIGN").is_ok());
    }
}
