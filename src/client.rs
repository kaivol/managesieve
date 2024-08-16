use core::str;
use std::any::type_name;
use std::collections::hash_map::{Entry, RawEntryMut};
use std::collections::HashMap;
use std::convert::Infallible;
use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use std::future::Future;
use std::hash::RandomState;
use std::io;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{ready, Poll};

use futures::{AsyncRead, AsyncWrite, AsyncWriteExt};
use futures_rustls::client::TlsStream;
use thiserror::{Error};
use tracing::info;
use winnow::combinator::{eof, terminated};
use winnow::error::ErrMode;
use winnow::{Parser, Partial};

use crate::internal::command::Command;
use crate::internal::parser::{
    tag, Bye, Capability, Input, ParseResult, ReponseInfo, Response, Tag, Version,
};

pub trait Stream: AsyncRead + AsyncWrite + Unpin {}
impl<T> Stream for T where T: AsyncRead + AsyncWrite + Unpin {}

pub type SieveResult<RES, ERROR> = Result<RES, SieveError<ERROR>>;

// pub trait OtherError: AsErrorSource + Display + 'static {}

// trait CommandError: AsErrorSource + Display + Debug {
//     type Connection;
// }

#[derive(Error, Debug)]
pub enum SieveError<I: Error> {
    #[error("encountered I/0 error: {0}")]
    Io(#[source] io::Error),
    #[error("syntax error")]
    Syntax,
    #[error("received unexpected `BYE`")]
    Bye {
        info: ReponseInfo,
    },
    #[error("server closed connection unexpectedly")]
    UnexpectedEof,
    #[error(transparent)]
    Other(#[from] I),
}

// impl<I: AsErrorSource + Display, C: 'static> Error<RecoverableError<I, C>> {
//     fn get_connection()
// }

#[derive(Error, PartialEq, Debug)]
#[error("{source}")]
pub struct RecoverableError<I: Error, C: 'static> {
    pub source: I,
    pub connection: C,
}

#[derive(Error, PartialEq, Debug)]
#[error("received unexpected NO response")]
pub struct UnexpectedNo {
    pub info: ReponseInfo,
}

pub trait AuthMode: 'static {}
pub enum Authenticated {}
impl AuthMode for Authenticated {}
pub enum Unauthenticated {}
impl AuthMode for Unauthenticated {}

pub trait TlsMode: 'static {
    type Stream<STREAM: Stream + 'static>: Stream + 'static;
}

pub enum NoTls {}
impl TlsMode for NoTls {
    type Stream<STREAM: Stream + 'static> = STREAM;
}

pub enum Tls {}
impl TlsMode for Tls {
    type Stream<STREAM: Stream + 'static> = TlsStream<STREAM>;
}

pub struct Connection<STREAM: Stream + 'static, TLS: TlsMode, MODE: AuthMode> {
    pub(crate) stream: TLS::Stream<STREAM>,
    pub(crate) capabilities: Capabilities,
    pub(crate) _p: PhantomData<MODE>,
}

#[derive(Debug, PartialEq)]
pub struct Capabilities {
    pub implementation: String,
    pub sasl: Vec<String>,
    pub sieve: Vec<String>,
    pub start_tls: bool,
    pub max_redirects: Option<u64>,
    pub notify: Option<Vec<String>>,
    pub language: Option<String>,
    pub owner: Option<String>,
    pub version: Version,
    pub others: HashMap<String, Option<String>>,
}

pub(crate) fn verify_capabilities(
    capabilities: Vec<Capability>,
) -> Result<Capabilities, CapabilitiesError> {
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

    fn try_set<T>(field: &mut Option<T>, value: T, name: &str) -> Result<(), CapabilitiesError> {
        if field.replace(value).is_some() {
            Err(CapabilitiesError::DuplicateCapability { capability: name.into() })
        } else {
            Ok(())
        }
    }

    for capability in capabilities {
        match capability {
            Capability::Implementation(c) => try_set(&mut implementation, c, "IMPLEMENTATION")?,
            Capability::Sasl(c) => try_set(&mut sasl, c, "SASL")?,
            Capability::Sieve(c) => try_set(&mut sieve, c, "SIEVE")?,
            Capability::StartTls => try_set(&mut start_tls, (), "STARTTLS")?,
            Capability::MaxRedirects(c) => try_set(&mut max_redirects, c, "MAX_REDIRECTS")?,
            Capability::Notify(c) => try_set(&mut notify, c, "NOTIFY")?,
            Capability::Language(c) => try_set(&mut language, c, "LANGUAGE")?,
            Capability::Owner(c) => try_set(&mut owner, c, "OWNER")?,
            Capability::Version(c) => try_set(&mut version, c, "VERSION")?,
            Capability::Unknown(name, value) => {
                match others.raw_entry_mut().from_key(&name) {
                    RawEntryMut::Vacant(v) => {
                        v.insert(name, value);
                    },
                    RawEntryMut::Occupied(_) => {
                        return Err(CapabilitiesError::DuplicateCapability { capability: name });
                    },
                }
                // match others.entry(name) {
                //     Entry::Vacant(v) => {
                //         v.insert(value);
                //     }
                //     Entry::Occupied(o) => {
                //         return Err(CapabilitiesError::DuplicateCapability { capability: o.key().clone() });
                //     }
                // }
            }
        }
    }
    match (implementation, sieve, version) {
        (Some(implementation), Some(sieve), Some(version)) => {
            Ok(Capabilities {
                implementation,
                sasl: sasl.unwrap_or_default(),
                sieve,
                start_tls: start_tls.is_some(),
                max_redirects,
                notify,
                language,
                owner,
                version,
                others,
            })
        }
        (None, _, _) => {
            Err(CapabilitiesError::MissingImplementation)
        }
        (_, None, _) => {
            Err(CapabilitiesError::MissingSieve)
        }
        (_, _, None) => {
            Err(CapabilitiesError::MissingVersion)
        }
    }
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
    DuplicateCapability { capability: String},
}

impl<STREAM: Stream, TLS: TlsMode, AUTH: AuthMode> Debug for Connection<STREAM, TLS, AUTH> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct(type_name::<Self>())
            .field("capabilities", &self.capabilities)
            .field("stream", &type_name::<STREAM>())
            .finish()
    }
}

impl<STREAM: Stream, TLS: TlsMode, AUTH: AuthMode> Connection<STREAM, TLS, AUTH> {
    pub fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    pub(crate) async fn send_command<T: Error>(
        &mut self,
        command: Command<'_>,
    ) -> Result<(), SieveError<T>> {
        let message = command.to_string();
        info!(command = message);
        let res = self.stream.write_all(message.as_bytes()).await;
        if res.is_err() {
            self.stream.close().await.map_err(SieveError::Io)?;
        }
        res.map_err(SieveError::Io)
    }
}

pub(crate) async fn handle_bye<
    OK: tag::Ok,
    NO: tag::No,
    STREAM: AsyncRead + AsyncWrite + Unpin,
    T: Error,
>(
    stream: &mut STREAM,
    Response { tag, info }: Response<OK, NO, Bye>,
) -> Result<Response<OK, NO, Infallible>, SieveError<T>> {
    match tag {
        Tag::Bye(_) => {
            stream.close().await.map_err(SieveError::Io)?;
            Err(SieveError::Bye { info })
        }
        Tag::Ok(ok) => Ok(Response {
            tag: Tag::Ok(ok),
            info,
        }),
        Tag::No(no) => Ok(Response {
            tag: Tag::No(no),
            info,
        }),
    }
}

pub(crate) async fn next_response<
    STREAM: AsyncRead + AsyncWrite + Unpin,
    RES: 'static,
    T: Error,
>(
    stream: &mut STREAM,
    parser: fn(Input) -> ParseResult<RES>,
) -> Result<RES, SieveError<T>> {
    let res = next_response_inner(stream, parser).await;
    if res.is_err() {
        stream.close().await.map_err(SieveError::Io)?;
    }
    res
}

pub(crate) fn next_response_inner<
    STREAM: AsyncRead + AsyncWrite + Unpin,
    RES: 'static,
    T: Error,
>(
    stream: &mut STREAM,
    parser: fn(Input) -> ParseResult<RES>,
) -> impl Future<Output = Result<RES, SieveError<T>>> + '_ {
    let mut buf = String::new();
    let mut pin = Pin::new(stream);

    std::future::poll_fn::<Result<RES, SieveError<T>>, _>(move |cx| loop {
        let mut temp = [0u8; 1024];
        let read_count = ready!(pin.as_mut().poll_read(cx, &mut temp)).map_err(SieveError::Io)?;

        if read_count == 0 {
            return Poll::Ready(Err(SieveError::UnexpectedEof));
        }

        buf.push_str(str::from_utf8(&temp[0..read_count]).unwrap());

        match terminated(parser, eof).parse_next(&mut Partial::new(buf.as_str())) {
            Err(ErrMode::Incomplete(_)) => {}
            Ok(res) => return Poll::Ready(Ok(res)),
            Err(_err) => return Poll::Ready(Err(SieveError::Syntax)),
        }
    })
}
