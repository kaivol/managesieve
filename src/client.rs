use core::str;
use std::any::type_name;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::convert::Infallible;
use std::fmt::{Debug, Display, Formatter};
use std::future::Future;
use std::io;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{ready, Poll};

use futures::{AsyncRead, AsyncWrite, AsyncWriteExt};
use futures_rustls::client::TlsStream;
use snafu::{AsErrorSource, IntoError, ResultExt, Snafu};
use winnow::combinator::{eof, terminated};
use winnow::error::ErrMode;
use winnow::{Parser, Partial};

use crate::internal::command::Command;
use crate::internal::parser::{response_capability, tag, Bye, Input, No, ParseResult, ReponseInfo, Response, Tag, Version, Capability};

pub trait Stream: AsyncRead + AsyncWrite + Unpin {}
impl<T> Stream for T where T: AsyncRead + AsyncWrite + Unpin {}

pub type SieveResult<RES, ERROR> = Result<RES, Error<ERROR>>;

// pub trait OtherError: AsErrorSource + Display + 'static {}

#[derive(Snafu, Debug)]
#[snafu(visibility(pub(crate)))]
pub enum Error<I: AsErrorSource + Display + Debug> {
    Io {
        source: io::Error,
    },
    Syntax,
    Bye {
        info: ReponseInfo,
    },
    UnexpectedEof,
    #[snafu(transparent)]
    Other {
        source: I,
    },
}

#[derive(Snafu, PartialEq, Debug)]
#[snafu(display("{source}"))]
pub struct RecoverableError<I: AsErrorSource + Display, C: 'static> {
    pub source: I,
    pub connection: C,
}
#[derive(Snafu, PartialEq, Debug)]
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
    pub sasl: Option<Vec<String>>,
    pub sieve: Vec<String>,
    pub start_tls: bool,
    pub max_redirects: Option<u64>,
    pub notify: Option<Vec<String>>,
    pub language: Option<String>,
    pub owner: Option<String>,
    pub version: Version,
    pub others: HashMap<String, Option<String>>,
}

pub(crate) fn verify_capabilities(capabilities: Vec<Capability>, ) -> Result<Capabilities, CapabilitiesError> {
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

    fn try_set<T>(field: &mut Option<T>, value: T) -> Result<(), CapabilitiesError> {
        if field.replace(value).is_some() {
            Err(CapabilitiesError::DuplicateCapability)
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
                    return Err(CapabilitiesError::DuplicateCapability);
                }
            }
        }
    }
    if let (Some(implementation), Some(sieve), Some(version)) = (implementation, sieve, version) {
        Ok(Capabilities {
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
        })
    } else {
        Err(CapabilitiesError::MissingCapability)
    }
}

#[derive(Snafu, PartialEq, Debug)]
pub enum CapabilitiesError {
    MissingCapability,
    DuplicateCapability,
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
    pub(crate) async fn send_command<T: AsErrorSource + Display + Debug>(
        &mut self,
        command: Command,
    ) -> Result<(), Error<T>> {
        let command = command.to_string();
        let res = self.stream.write_all(command.as_bytes()).await;
        if res.is_err()  {
            self.stream.close().await.context(IoSnafu)?;
        }
        res.context(IoSnafu).into()
    }
}

pub(crate) async fn handle_bye<
    OK: tag::Ok,
    NO: tag::No,
    STREAM: AsyncRead + AsyncWrite + Unpin,
    T: AsErrorSource + Display + Debug,
>(
    stream: &mut STREAM,
    Response { tag, info }: Response<OK, NO, Bye>,
) -> Result<Response<OK, NO, Infallible>, Error<T>> {
    match tag {
        Tag::Bye(_) => {
            stream.close().await.context(IoSnafu)?;
            Err(Error::Bye { info })
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
    T: AsErrorSource + Display + Debug,
>(
    stream: &mut STREAM,
    parser: fn(Input) -> ParseResult<RES>,
) -> Result<RES, Error<T>> {
    let res = next_response_inner(stream, parser).await;
    if res.is_err() {
        stream.close().await.context(IoSnafu)?;
    }
    res
}

pub(crate) fn next_response_inner<
    STREAM: AsyncRead + AsyncWrite + Unpin,
    RES: 'static,
    T: AsErrorSource + Display + Debug,
>(
    stream: &mut STREAM,
    parser: fn(Input) -> ParseResult<RES>,
) -> impl Future<Output = Result<RES, Error<T>>> + '_ {
    let mut buf = String::new();
    let mut pin = Pin::new(stream);

    std::future::poll_fn::<Result<RES, Error<T>>, _>(move |cx| loop {
        let mut temp = [0u8; 1024];
        let read_count = ready!(pin.as_mut().poll_read(cx, &mut temp)).context(IoSnafu)?;

        if read_count == 0 {
            return Poll::Ready(Err(Error::UnexpectedEof));
        }

        buf.push_str(str::from_utf8(&temp[0..read_count]).unwrap());

        match terminated(parser, eof).parse_next(&mut Partial::new(buf.as_str())) {
            Err(ErrMode::Incomplete(_)) => {}
            Ok(res) => return Poll::Ready(Ok(res)),
            Err(_err) => return Poll::Ready(Err(Error::Syntax)),
        }
    })
}
