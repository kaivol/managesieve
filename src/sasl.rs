use std::convert::Infallible;
use std::fmt;
use std::ops::Deref;
#[cfg(feature = "nightly")]
use std::ops::{Coroutine, CoroutineState};
use std::pin::Pin;

use pin_project_lite::pin_project;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SaslError<E> {
    #[error("authentication is not completed, but the server sent `OK` response")]
    UnexpectedOk,

    #[error("authentication is completed, but the server sent further messages")]
    UnexpectedServerResponse,

    #[error("internal error in the provided SASl algorithm: {0}")]
    SaslError(#[source] E),

    #[error(
        "site security policy forbids the use of the requested mechanism for the specified \
    authentication identity"
    )]
    AuthTooWeak,

    #[error(
        "site security policy requires the use of a strong encryption mechanism for the \
    specified authentication identity and mechanism"
    )]
    EncryptNeeded,

    #[error(
        "the username is valid, but the entry in the authentication database needs to be \
    updated in order to permit authentication with the specified mechanism"
    )]
    TransitionNeeded,

    #[error(fmt = fmt_other)]
    Other { message: Option<String> },
}

fn fmt_other(message: &Option<String>, formatter: &mut fmt::Formatter) -> fmt::Result {
    write!(formatter, "unspecified authentification failure")?;
    if let Some(msg) = message {
        write!(formatter, ": {msg}")?;
    }
    Ok(())
}

pub enum SaslState {
    Yielded(Vec<u8>),
    Complete,
    CompleteWithFinalResponse(Vec<u8>),
}

impl SaslState {
    pub fn has_response(&self) -> bool {
        matches!(self, SaslState::CompleteWithFinalResponse(_) | SaslState::Yielded(_))
    }

    pub fn is_finished(&self) -> bool {
        matches!(self, SaslState::CompleteWithFinalResponse(_) | SaslState::Complete)
    }

    pub fn response(self) -> Option<Vec<u8>> {
        match self {
            SaslState::Yielded(r) => Some(r),
            SaslState::Complete => None,
            SaslState::CompleteWithFinalResponse(r) => Some(r),
        }
    }
}

#[derive(Copy, Clone)]
pub enum InitialSaslState<'a> {
    None,
    Yielded(&'a [u8]),
    Complete(&'a [u8]),
}

pub trait Sasl<'a> {
    type Error;
    fn name(&self) -> &'static str;
    fn init(&self) -> InitialSaslState<'a>;
    fn resume(self: Pin<&mut Self>, arg: Vec<u8>) -> Result<SaslState, Self::Error>;
}

impl<'a, E> Sasl<'a> for Pin<Box<dyn Sasl<'a, Error = E>>> {
    type Error = E;

    fn name(&self) -> &'static str {
        self.deref().name()
    }

    fn init(&self) -> InitialSaslState<'a> {
        self.deref().init()
    }

    fn resume(self: Pin<&mut Self>, arg: Vec<u8>) -> Result<SaslState, Self::Error> {
        self.as_deref_mut().resume(arg)
    }
}

impl<'a> Sasl<'a> for (&'static str, &'a [u8]) {
    type Error = Infallible;

    fn name(&self) -> &'static str {
        self.0
    }

    fn init(&self) -> InitialSaslState<'a> {
        InitialSaslState::Complete(self.1)
    }

    fn resume(self: Pin<&mut Self>, _arg: Vec<u8>) -> Result<SaslState, Self::Error> {
        panic!()
    }
}

pin_project! {
    #[derive(Copy, Clone)]
    pub struct SaslFn<'a, F> {
        pub name: &'static str,
        pub init: Option<&'a [u8]>,
        pub f: F,
    }
}

impl<'a, F: FnMut(Vec<u8>) -> Result<SaslState, E>, E> Sasl<'a> for SaslFn<'a, F> {
    type Error = E;

    fn name(&self) -> &'static str {
        self.name
    }

    fn init(&self) -> InitialSaslState<'a> {
        match self.init {
            None => InitialSaslState::None,
            Some(i) => InitialSaslState::Yielded(i),
        }
    }

    fn resume(self: Pin<&mut Self>, arg: Vec<u8>) -> Result<SaslState, Self::Error> {
        let this = self.project();
        (this.f)(arg)
    }
}

#[cfg(feature = "nightly")]
pin_project! {
    pub struct SaslCoroutine<'a, C> {
        pub name: &'static str,
        pub init: Option<&'a [u8]>,
        #[pin] pub c: C
    }
}

#[cfg(feature = "nightly")]
impl<'a, C: Coroutine<Vec<u8>, Return = Result<Option<Vec<u8>>, E>, Yield = Vec<u8>>, E> Sasl<'a>
    for SaslCoroutine<'a, C>
{
    type Error = E;

    fn name(&self) -> &'static str {
        self.name
    }

    fn init(&self) -> InitialSaslState<'a> {
        match self.init {
            None => InitialSaslState::None,
            Some(i) => InitialSaslState::Yielded(i),
        }
    }

    fn resume(self: Pin<&mut Self>, arg: Vec<u8>) -> Result<SaslState, E> {
        let this = self.project();
        match Coroutine::resume(this.c, arg) {
            CoroutineState::Yielded(data) => Ok(SaslState::Yielded(data)),
            CoroutineState::Complete(Err(err)) => Err(err),
            CoroutineState::Complete(Ok(Some(data))) => {
                Ok(SaslState::CompleteWithFinalResponse(data))
            }
            CoroutineState::Complete(Ok(None)) => Ok(SaslState::Complete),
        }
    }
}
