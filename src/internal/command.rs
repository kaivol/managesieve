#![allow(dead_code)]

use std::fmt::{Display, Formatter};

use base64::Engine;
use snafu::Snafu;

#[derive(Snafu, Debug, PartialEq)]
pub struct IllegalScriptName;

#[derive(Debug, PartialEq)]
pub enum Command<'a> {
    Authenticate {
        auth_type: SieveStr<'a>,
        message: Option<SieveStrBase64<'a>>,
    },
    StartTls,
    Logout,
    Capability,
    HaveSpace(SieveStr<'a>, u64),
    PutScript(SieveStr<'a>, SieveStr<'a>),
    ListScripts,
    SetActive(SieveStr<'a>),
    DeleteScript(SieveStr<'a>),
    RenameScript(SieveStr<'a>),
    CheckScript(SieveStr<'a>),
    Noop,
    UnAuthenticate,
}

#[derive(Debug, PartialEq)]
pub struct SieveStr<'a>(&'a str);

impl<'a> Display for SieveStr<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{{}+}}\r\n{}", self.0.len(), self.0)
    }
}

#[derive(Debug, PartialEq)]
pub struct SieveStrBase64<'a>(&'a [u8]);

impl<'a> Display for SieveStrBase64<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let base64 = base64::engine::general_purpose::STANDARD.encode(self.0);
        write!(f, "{{{}+}}\r\n{}", base64.len(), base64)
    }
}

impl<'a> Command<'a> {
    pub fn authenticate(auth_type: &'a str, message: Option<&'a [u8]>) -> Self {
        Self::Authenticate {
            auth_type: SieveStr(auth_type),
            message: message.map(SieveStrBase64),
        }
    }

    pub fn start_tls() -> Self {
        Self::StartTls
    }

    pub fn logout() -> Self {
        Self::Logout
    }

    pub fn capability() -> Self {
        Self::Capability
    }

    pub fn have_space(name: &'a str, size: u64) -> Result<Self, IllegalScriptName> {
        Ok(Self::HaveSpace(to_sieve_name(name)?, size))
    }

    pub fn put_script(name: &'a str, script: &'a str) -> Result<Self, IllegalScriptName> {
        Ok(Self::PutScript(to_sieve_name(name)?, SieveStr(script)))
    }

    pub fn list_scripts() -> Self {
        Self::ListScripts
    }

    pub fn set_active(name: &'a str) -> Result<Self, IllegalScriptName> {
        Ok(Self::SetActive(to_sieve_name(name)?))
    }

    pub fn deletescript(name: &'a str) -> Result<Self, IllegalScriptName> {
        Ok(Self::DeleteScript(to_sieve_name(name)?))
    }

    pub fn renamescript(name: &'a str) -> Result<Self, IllegalScriptName> {
        Ok(Self::RenameScript(to_sieve_name(name)?))
    }

    pub fn checkscript(name: &'a str) -> Result<Self, IllegalScriptName> {
        Ok(Self::CheckScript(to_sieve_name(name)?))
    }

    pub fn noop() -> Self {
        Self::Noop
    }

    pub fn unauthenticate() -> Self {
        Self::UnAuthenticate
    }
}

fn to_sieve_name(s: &str) -> Result<SieveStr, IllegalScriptName> {
    if s.chars().any(crate::internal::parser::is_bad_sieve_name_char) {
        return Err(IllegalScriptName);
    }

    Ok(SieveStr(s))
}

impl Display for Command<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Command::Authenticate { auth_type, message } => {
                write!(f, "AUTHENTICATE {auth_type}")?;
                if let Some(message) = message.as_ref() {
                    write!(f, " {message}")?;
                }
                write!(f, "\r\n")?;
                Ok(())
            }
            Command::StartTls => write!(f, "STARTTLS\r\n"),
            Command::Logout => write!(f, "LOGOUT\r\n"),
            Command::Capability => write!(f, "CAPABILITY\r\n"),
            Command::HaveSpace(name, size) => {
                write!(f, "HAVESPACE {name} {size}\r\n")
            }
            Command::PutScript(name, script) => {
                write!(f, "PUTSCRIPT {name} {script}\r\n")
            }
            Command::ListScripts => write!(f, "LISTSCRIPTS\r\n"),
            Command::SetActive(name) => write!(f, "SETACTIVE {name}\r\n"),
            Command::DeleteScript(name) => write!(f, "DELETESCRIPT {name}\r\n"),
            Command::RenameScript(name) => write!(f, "RENAMESCRIPT {name}\r\n"),
            Command::CheckScript(name) => write!(f, "CHECKSCRIPT {name}\r\n"),
            Command::Noop => write!(f, "NOOP\r\n"),
            Command::UnAuthenticate => write!(f, "UNAUTHENTICATE\r\n"),
        }
    }
}

#[cfg(test)]
mod test {
    use sasl::client::mechanisms::Plain;
    use sasl::client::Mechanism;

    use super::*;

    #[test]
    fn test_authenticate() {
        let mut auth = Plain::new("FOO", "BAR");
        let binding = auth.initial();
        let command = Command::authenticate("PLAIN", Some(binding.as_slice()));
        assert_eq!(
            command.to_string().as_str(),
            "AUTHENTICATE {5+}\r\nPLAIN {12+}\r\nAGZvbwBiYXI=\r\n"
        )
    }
}
