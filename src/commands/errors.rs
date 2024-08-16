use std::error::Error;
use std::io;

use thiserror::Error;

use crate::internal::parser::ReponseInfo;

pub type SieveResult<RES, ERROR> = Result<RES, SieveError<ERROR>>;

#[derive(Error, Debug)]
pub enum SieveError<I: Error> {
    #[error("encountered I/0 error: {0}")]
    Io(#[source] io::Error),
    #[error("syntax error")]
    Syntax,
    #[error("received unexpected `BYE` response")]
    Bye { info: ReponseInfo },
    // #[error("received unexpected `NO` response")]
    // UnexpectedNo {
    //     info: ReponseInfo,
    // },
    #[error("server closed connection unexpectedly")]
    UnexpectedEof,
    #[error(transparent)]
    Other(#[from] I),
}

#[derive(Error, PartialEq, Debug)]
#[error("received unexpected NO response")]
pub struct UnexpectedNo {
    pub info: ReponseInfo,
}

#[derive(Error, PartialEq, Debug)]
pub enum CapabilitiesError {
    #[error("capabilities response is missing required capability `IMPLEMENTATION`")]
    MissingImplementation,
    #[error("capabilities response is missing required capability `SIEVE`")]
    MissingSieve,
    #[error("capabilities response is missing required capability `VERSION`")]
    MissingVersion,
    #[error("received duplicate capability `{capability}`")]
    DuplicateCapability { capability: String },
}

#[macro_export]
macro_rules! bail {
    ($err:expr) => {
        return Err(core::convert::From::from($err))
    };
}
