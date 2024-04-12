use std::fmt::Display;

#[derive(Debug, PartialEq)]
pub enum Error {
    IncompleteResponse,
    InvalidResponse,
    InvalidInput,
}

#[derive(Debug, PartialEq)]
pub enum Command {
    Authenticate,
    StartTls,
    Logout,
    Capability,
    HaveSpace(String, usize),
    PutScript(String, String),
    ListScripts,
    SetActive(String),
    DeleteScript(String),
    RenameScript(String),
    CheckScript(String),
    Noop,
    UnAuthenticate,
}

impl Command {
    pub fn authenticate() -> Command {
        Command::Authenticate
    }

    pub fn start_tls() -> Command {
        Command::StartTls
    }

    pub fn logout() -> Command {
        Command::Logout
    }

    pub fn capability() -> Command {
        Command::Capability
    }

    pub fn have_space(name: &str, size: usize) -> Result<Command, Error> {
        Ok(Command::HaveSpace(to_sieve_name(name)?, size))
    }

    pub fn put_script(name: &str, script: &str) -> Result<Command, Error> {
        Ok(Command::PutScript(to_sieve_name(name)?, script.to_owned()))
    }

    pub fn list_scripts() -> Command {
        Command::ListScripts
    }

    pub fn set_active(name: &str) -> Result<Command, Error> {
        Ok(Command::SetActive(to_sieve_name(name)?))
    }

    pub fn deletescript(name: &str) -> Result<Command, Error> {
        Ok(Command::DeleteScript(to_sieve_name(name)?))
    }

    pub fn renamescript(name: &str) -> Result<Command, Error> {
        Ok(Command::RenameScript(to_sieve_name(name)?))
    }

    pub fn checkscript(name: &str) -> Result<Command, Error> {
        Ok(Command::CheckScript(to_sieve_name(name)?))
    }

    pub fn noop() -> Command {
        Command::Noop
    }

    pub fn unauthenticate() -> Command {
        Command::UnAuthenticate
    }
}

fn to_sieve_name(s: &str) -> Result<String, Error> {
    if s.chars()
        .find(|c| crate::internal::parser::is_bad_sieve_name_char(*c))
        .is_some()
    {
        return Err(Error::InvalidInput);
    }

    Ok(s.to_owned())
}

// to quotedstring
fn to_qs(s: &str) -> String {
    // TODO: escape some things in s?
    format!("\"{}\"", s)
}

fn to_lit_c2s(s: &str) -> String {
    format!("{{{}+}}\r\n{}", s.len(), s)
}

impl Display for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            Command::Authenticate => "AUTHENTICATE\r\n".into(),
            Command::StartTls => "STARTTLS\r\n".into(),
            Command::Logout => "LOGOUT\r\n".into(),
            Command::Capability => "CAPABILITY\r\n".into(),
            Command::HaveSpace(name, size) => format!("HAVESPACE {} {}\r\n", to_qs(name), size),
            Command::PutScript(name, script) => {
                format!("PUTSCRIPT {} {}\r\n", to_qs(name), to_lit_c2s(script))
            }
            Command::ListScripts => "LISTSCRIPTS\r\n".into(),
            Command::SetActive(name) => format!("SETACTIVE {}\r\n", to_qs(name)),
            Command::DeleteScript(name) => format!("DELETESCRIPT {}\r\n", to_qs(name)),
            Command::RenameScript(name) => format!("RENAMESCRIPT {}\r\n", to_qs(name)),
            Command::CheckScript(name) => format!("CHECKSCRIPT {}\r\n", to_qs(name)),
            Command::Noop => "NOOP\r\n".into(),
            Command::UnAuthenticate => "UNAUTHENTICATE\r\n".into(),
        };
        write!(f, "{}", str)
    }
}
