use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt::Display;
use std::io::{self, ErrorKind};
use std::string::ToString;

use nom;
use nom::IResult;
use snafu::Snafu;

use crate::internal::parser as p;
use crate::internal::parser::{Capability, ParseResult, Response, Version};

#[derive(Snafu, PartialEq, Debug)]
pub enum Error {
    ResponseTooLong,
    InvalidResponse,
    MultipleActiveScripts,
    DuplicateCapability,
    MissingCapability,
}

#[derive(Debug, PartialEq)]
pub struct Capabilities {
    implementation: String,
    sasl: Option<Vec<String>>,
    sieve: Vec<String>,
    start_tls: bool,
    max_redirects: Option<u64>,
    notify: Option<Vec<String>>,
    language: Option<String>,
    owner: Option<String>,
    version: Version,
    others: HashMap<String, Option<String>>,
}

fn response_helper<T, I>(
    input: &str,
    parse: impl Fn(&str) -> ParseResult<I>,
    transform: impl Fn(I) -> Result<T, Error>,
) -> Option<Result<T, Error>> {
    match parse(input) {
        Ok((left, _)) if !left.is_empty() => Some(Err(Error::ResponseTooLong)),
        Ok((_, response)) => Some(transform(response)),
        Err(nom::Err::Incomplete(_)) => None,
        _ => Some(Err(Error::InvalidResponse)),
    }
}

fn verify_capabilities(
    (capabilities, response): (Vec<Capability>, Response),
) -> Result<(Capabilities, Response), Error> {
    let mut implementation: Option<String> = None;
    let mut sasl: Option<Vec<String>> = None;
    let mut sieve: Option<Vec<String>> = None;
    let mut start_tls: Option<()> = None;
    let mut max_redirects: Option<u64> = None;
    let mut notify: Option<Vec<String>> = None;
    let mut language: Option<String> = None;
    let mut owner: Option<String> = None;
    let mut version: Option<Version> = None;

    let mut others: HashMap<String, Option<String>> = HashMap::new();

    fn try_set<T>(field: &mut Option<T>, value: T) -> Result<(), Error> {
        if field.replace(value).is_some() {
            Err(Error::DuplicateCapability)
        } else {
            Ok(())
        }
    }

    for capability in capabilities {
        match capability {
            Capability::Implementation(c) => try_set(&mut implementation, c)?,
            Capability::Sasl(c) => try_set(&mut sasl, c)?,
            Capability::Sieve(c) => try_set(&mut sieve, c)?,
            Capability::StartTls => try_set(&mut start_tls, ())?,
            Capability::MaxRedirects(c) => try_set(&mut max_redirects, c)?,
            Capability::Notify(c) => try_set(&mut notify, c)?,
            Capability::Language(c) => try_set(&mut language, c)?,
            Capability::Owner(c) => try_set(&mut owner, c)?,
            Capability::Version(c) => try_set(&mut version, c)?,
            Capability::Unknown(name, value) => {
                if let Entry::Vacant(v) = others.entry(name) {
                    v.insert(value);
                } else {
                    return Err(Error::DuplicateCapability);
                }
            }
        }
    }
    if let (Some(implementation), Some(sieve), Some(version)) = (implementation, sieve, version) {
        Ok((
            Capabilities {
                implementation,
                sasl,
                sieve,
                start_tls: start_tls.is_some(),
                max_redirects,
                notify,
                language,
                owner,
                version,
                others,
            },
            response,
        ))
    } else {
        Err(Error::MissingCapability)
    }
}

pub fn response_authenticate(_input: &str) -> Option<Result<Response, Error>> {
    unimplemented!()
}

/// Parses text returned from the server in response to the STARTTLS command.
/// Returns list of capabilities and optional additional strings.
pub fn response_starttls(input: &str) -> Option<Result<(Capabilities, Response), Error>> {
    response_helper(input, p::response_starttls, verify_capabilities)
}

/// Parses text returned from the server in response to the LOGOUT command.
pub fn response_logout(input: &str) -> Option<Result<Response, Error>> {
    response_helper(input, p::response_oknobye, Ok)
}

/// Parses text returned from the server in response to the CAPABILITY command.
/// Returns list of capabilities and optional additional strings.
pub fn response_capability(input: &str) -> Option<Result<(Capabilities, Response), Error>> {
    response_helper(input, p::response_capabilities, verify_capabilities)
}

/// Parses text returned from the server in response to the HAVESPACE command.
pub fn response_havespace(input: &str) -> Option<Result<Response, Error>> {
    response_helper(input, p::response_oknobye, Ok)
}

/// Parses text returned from the server in response to the PUTSCRIPT command.
pub fn response_putscript(input: &str) -> Option<Result<Response, Error>> {
    response_helper(input, p::response_oknobye, Ok)
}

/// Parses text returned from the server in response to the LISTSCRIPTS command.
/// Returns list of scripts and a bool indicating if that script is the active
/// script.
pub fn response_listscripts(input: &str) -> Option<Result<(Vec<(String, bool)>, Response), Error>> {
    response_helper(input, p::response_listscripts, |(s, resp)| {
        if s.iter().filter(|(_, is_active)| *is_active).count() > 1 {
            Err(Error::MultipleActiveScripts)
        } else {
            Ok((s, resp))
        }
    })
}

/// Parses text returned from the server in response to the GETSCRIPT command.
pub fn response_setactive(input: &str) -> Option<Result<Response, Error>> {
    response_helper(input, p::response_oknobye, Ok)
}

/// Parses text returned from the server in response to the GETSCRIPT command.
pub fn response_getscript(input: &str) -> Option<Result<(Option<String>, Response), Error>> {
    response_helper(input, p::response_getscript, Ok)
}

/// Parses text returned from the server in response to the DELETESCRIPT command.
pub fn response_deletescript(input: &str) -> Option<Result<Response, Error>> {
    response_helper(input, p::response_oknobye, Ok)
}

/// Parses text returned from the server in response to the RENAMESCRIPT command.
pub fn response_renamescript(input: &str) -> Option<Result<Response, Error>> {
    response_helper(input, p::response_oknobye, Ok)
}

/// Parses text returned from the server in response to the CHECKSCRIPT command.
pub fn response_checkscript(input: &str) -> Option<Result<Response, Error>> {
    response_helper(input, p::response_oknobye, Ok)
}

/// Parses text returned from the server in response to the NOOP command.
pub fn response_noop(input: &str) -> Option<Result<Response, Error>> {
    response_helper(input, p::response_ok, Ok)
}

/// Parses text returned from the server in response to the UNAUTHENTICATE command.
pub fn response_unauthenticate(input: &str) -> Option<Result<Response, Error>> {
    response_helper(input, p::response_oknobye, Ok)
}
