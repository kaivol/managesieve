// #![allow(dead_code)]
// #![allow(clippy::type_complexity)]
//
// use std::collections::hash_map::Entry;
// use std::collections::HashMap;
//
// use thiserror::Error;
// use winnow::combinator::{eof, terminated};
// use winnow::error::{ContextError, ErrMode};
// use winnow::{Parser, Partial};
//
// use crate::internal::parser as p;
// use crate::internal::parser::{Capability, Response, Version};
//
// #[derive(PartialEq, Debug)]
// pub enum Error {
//     ParsingFailed,
//     Recoverable(RecoverableError),
// }
//
// #[derive(PartialEq, Debug)]
// pub enum RecoverableError {
//     MultipleActiveScripts,
//     DuplicateCapability,
//     MissingCapability,
// }
//
// pub enum Status<T> {
//     Incomplete,
//     Ready(T),
// }
//
// #[derive(Debug, PartialEq)]
// pub struct Capabilities {
//     pub implementation: String,
//     pub sasl: Option<Vec<String>>,
//     pub sieve: Vec<String>,
//     pub start_tls: bool,
//     pub max_redirects: Option<u64>,
//     pub notify: Option<Vec<String>>,
//     pub language: Option<String>,
//     pub owner: Option<String>,
//     pub version: Version,
//     pub others: HashMap<String, Option<String>>,
// }
//
// fn response_helper<T, I>(
//     input: &str,
//     parse: impl for<'a> Parser<Partial<&'a str>, I, ContextError>,
//     transform: impl Fn(I) -> Result<T, RecoverableError>,
// ) -> Status<Result<T, Error>> {
//     let mut input = Partial::new(input);
//     match terminated(parse, eof).parse_next(&mut input) {
//         Ok(res) => Status::Ready(transform(res).map_err(|e| Error::Recoverable(e))),
//         Err(ErrMode::Incomplete(_)) => Status::Incomplete,
//         Err(_e) => Status::Ready(Err(Error::ParsingFailed)),
//     }
// }
//
// fn verify_capabilities(
//     (capabilities, response): (Vec<Capability>, Response),
// ) -> Result<(Capabilities, Response), RecoverableError> {
//     let mut implementation: Option<String> = None;
//     let mut sasl: Option<Vec<String>> = None;
//     let mut sieve: Option<Vec<String>> = None;
//     let mut start_tls: Option<()> = None;
//     let mut max_redirects: Option<u64> = None;
//     let mut notify: Option<Vec<String>> = None;
//     let mut language: Option<String> = None;
//     let mut owner: Option<String> = None;
//     let mut version: Option<Version> = None;
//
//     let mut others: HashMap<String, Option<String>> = HashMap::new();
//
//     fn try_set<T>(field: &mut Option<T>, value: T) -> Result<(), RecoverableError> {
//         if field.replace(value).is_some() {
//             Err(RecoverableError::DuplicateCapability)
//         } else {
//             Ok(())
//         }
//     }
//
//     for capability in capabilities {
//         match capability {
//             Capability::Implementation(c) => try_set(&mut implementation, c)?,
//             Capability::Sasl(c) => try_set(&mut sasl, c)?,
//             Capability::Sieve(c) => try_set(&mut sieve, c)?,
//             Capability::StartTls => try_set(&mut start_tls, ())?,
//             Capability::MaxRedirects(c) => try_set(&mut max_redirects, c)?,
//             Capability::Notify(c) => try_set(&mut notify, c)?,
//             Capability::Language(c) => try_set(&mut language, c)?,
//             Capability::Owner(c) => try_set(&mut owner, c)?,
//             Capability::Version(c) => try_set(&mut version, c)?,
//             Capability::Unknown(name, value) => {
//                 if let Entry::Vacant(v) = others.entry(name) {
//                     v.insert(value);
//                 } else {
//                     return Err(RecoverableError::DuplicateCapability);
//                 }
//             }
//         }
//     }
//     if let (Some(implementation), Some(sieve), Some(version)) = (implementation, sieve, version) {
//         Ok((
//             Capabilities {
//                 implementation,
//                 sasl,
//                 sieve,
//                 start_tls: start_tls.is_some(),
//                 max_redirects,
//                 notify,
//                 language,
//                 owner,
//                 version,
//                 others,
//             },
//             response,
//         ))
//     } else {
//         Err(RecoverableError::MissingCapability)
//     }
// }
//
// pub fn response_authenticate(_input: &str) -> Status<Result<Response, Error>> {
//     unimplemented!()
// }
//
// /// Parses text returned from the server in response to the STARTTLS command.
// /// Returns list of capabilities and optional additional strings.
// pub fn response_starttls(input: &str) -> Status<Result<(Capabilities, Response), Error>> {
//     response_helper(input, p::response_starttls, verify_capabilities)
// }
//
// /// Parses text returned from the server in response to the LOGOUT command.
// pub fn response_logout(input: &str) -> Status<Result<Response, Error>> {
//     response_helper(input, p::response_oknobye, Ok)
// }
//
// /// Parses text returned from the server in response to the CAPABILITY command.
// /// Returns list of capabilities and optional additional strings.
// pub fn response_capability(input: &str) -> Status<Result<(Capabilities, Response), Error>> {
//     response_helper(input, p::response_capability, verify_capabilities)
// }
//
// /// Parses text returned from the server in response to the HAVESPACE command.
// pub fn response_havespace(input: &str) -> Status<Result<Response, Error>> {
//     response_helper(input, p::response_oknobye, Ok)
// }
//
// /// Parses text returned from the server in response to the PUTSCRIPT command.
// pub fn response_putscript(input: &str) -> Status<Result<Response, Error>> {
//     response_helper(input, p::response_oknobye, Ok)
// }
//
// /// Parses text returned from the server in response to the LISTSCRIPTS command.
// /// Returns list of scripts and a bool indicating if that script is the active
// /// script.
// pub fn response_listscripts(input: &str) -> Status<Result<(Vec<(String, bool)>, Response), Error>> {
//     response_helper(input, p::response_listscripts, |(s, resp)| {
//         if s.iter().filter(|(_, is_active)| *is_active).count() > 1 {
//             Err(RecoverableError::MultipleActiveScripts)
//         } else {
//             Ok((s, resp))
//         }
//     })
// }
//
// /// Parses text returned from the server in response to the GETSCRIPT command.
// pub fn response_setactive(input: &str) -> Status<Result<Response, Error>> {
//     response_helper(input, p::response_oknobye, Ok)
// }
//
// /// Parses text returned from the server in response to the GETSCRIPT command.
// pub fn response_getscript(input: &str) -> Status<Result<(Option<String>, Response), Error>> {
//     response_helper(input, p::response_getscript, Ok)
// }
//
// /// Parses text returned from the server in response to the DELETESCRIPT command.
// pub fn response_deletescript(input: &str) -> Status<Result<Response, Error>> {
//     response_helper(input, p::response_oknobye, Ok)
// }
//
// /// Parses text returned from the server in response to the RENAMESCRIPT command.
// pub fn response_renamescript(input: &str) -> Status<Result<Response, Error>> {
//     response_helper(input, p::response_oknobye, Ok)
// }
//
// /// Parses text returned from the server in response to the CHECKSCRIPT command.
// pub fn response_checkscript(input: &str) -> Status<Result<Response, Error>> {
//     response_helper(input, p::response_oknobye, Ok)
// }
//
// /// Parses text returned from the server in response to the NOOP command.
// pub fn response_noop(input: &str) -> Status<Result<Response, Error>> {
//     response_helper(input, p::response_ok, Ok)
// }
//
// /// Parses text returned from the server in response to the UNAUTHENTICATE command.
// pub fn response_unauthenticate(input: &str) -> Status<Result<Response, Error>> {
//     response_helper(input, p::response_oknobye, Ok)
// }
