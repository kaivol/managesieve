use std::convert::Infallible;
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

    #[error("internal error in the provided SASl algorithm")]
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
        "the user name is valid, but the entry in the authentication database needs to be
    updated in order to permit authentication with the specified mechanism"
    )]
    TransitionNeeded,
}

pin_project! {
    pub struct Sasl<'a, F: ?Sized> {
        pub name: &'static str,
        pub init: InitialSaslState<'a>,
        #[pin]
        pub f: F,
    }
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

pub enum InitialSaslState<'a> {
    None,
    Yielded(&'a [u8]),
    Complete(&'a [u8]),
}

pub trait SaslInner {
    type Error;
    fn resume(self: Pin<&mut Self>, arg: Vec<u8>) -> Result<SaslState, Self::Error>;
}

pub struct SaslInnerFn<F>(F);

impl<F, E> SaslInner for SaslInnerFn<F>
where
    F: FnMut(Vec<u8>) -> Result<SaslState, E>,
{
    type Error = E;

    fn resume(self: Pin<&mut Self>, arg: Vec<u8>) -> Result<SaslState, E> {
        (unsafe { &mut self.get_unchecked_mut().0 })(arg)
    }
}

impl<'a, F, E> Sasl<'a, SaslInnerFn<F>>
where
    F: FnMut(Vec<u8>) -> Result<SaslState, E>,
{
    pub fn new_fn(name: &'static str, init: InitialSaslState<'a>, f: F) -> Self {
        Self {
            name,
            init,
            f: SaslInnerFn(f),
        }
    }
}

pub struct SaslInnerDummy(());

impl SaslInner for SaslInnerDummy {
    type Error = Infallible;

    fn resume(self: Pin<&mut Self>, _arg: Vec<u8>) -> Result<SaslState, Self::Error> {
        unreachable!();
    }
}

impl<'a> Sasl<'a, SaslInnerDummy> {
    pub fn new_init(name: &'static str, init: &'a [u8]) -> Self {
        Self {
            name,
            init: InitialSaslState::Complete(init),
            f: SaslInnerDummy(()),
        }
    }
}

#[cfg(feature = "nightly")]
pub struct SaslInnerCoroutine<C>(C);

#[cfg(feature = "nightly")]
impl<C, E> SaslInner for SaslInnerCoroutine<C>
where
    C: Coroutine<Vec<u8>, Return = Result<Option<Vec<u8>>, E>, Yield = Vec<u8>>,
{
    type Error = E;

    fn resume(self: Pin<&mut Self>, arg: Vec<u8>) -> Result<SaslState, E> {
        match Coroutine::resume(unsafe { self.map_unchecked_mut(|c| &mut c.0) }, arg) {
            CoroutineState::Yielded(data) => Ok(SaslState::Yielded(data)),
            CoroutineState::Complete(Err(err)) => Err(err),
            CoroutineState::Complete(Ok(Some(data))) => {
                Ok(SaslState::CompleteWithFinalResponse(data))
            }
            CoroutineState::Complete(Ok(None)) => Ok(SaslState::Complete),
        }
    }
}

#[cfg(feature = "nightly")]
impl<'a, C, E> Sasl<'a, SaslInnerCoroutine<C>>
where
    C: Coroutine<Vec<u8>, Return = Result<Option<Vec<u8>>, E>, Yield = Vec<u8>>,
{
    pub fn new_coroutine(name: &'static str, init: InitialSaslState<'a>, c: C) -> Self {
        Self {
            name,
            init,
            f: SaslInnerCoroutine(c),
        }
    }
}
