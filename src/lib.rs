#![cfg_attr(feature = "nightly", feature(coroutine_trait))]

use std::any::type_name;
use std::fmt::{Debug, Display, Formatter};
use std::io;
use std::marker::PhantomData;

pub use capabilities::{Capabilities, CapabilitiesError, Version};
pub use futures::{AsyncRead, AsyncWrite};
pub use futures_rustls::pki_types::ServerName;
pub use sieve_name::{SieveNameError, SieveNameStr, SieveNameString};

mod capabilities;
pub mod commands;
mod parser;
pub mod sasl;
mod sieve_name;

pub mod state {
    use futures_rustls::client::TlsStream;

    use crate::{AsyncRead, AsyncWrite};

    pub trait AuthMode: 'static + private_auth_mode::Sealed {}
    pub enum Authenticated {}
    impl AuthMode for Authenticated {}
    pub enum Unauthenticated {}
    impl AuthMode for Unauthenticated {}

    mod private_auth_mode {
        pub trait Sealed {}
        impl Sealed for super::Authenticated {}
        impl Sealed for super::Unauthenticated {}
    }

    pub trait TlsMode: 'static + private_tls_mode::Sealed {
        type Stream<STREAM: AsyncRead + AsyncWrite + Unpin>: AsyncRead + AsyncWrite + Unpin;
    }

    pub enum NoTls {}
    impl TlsMode for NoTls {
        type Stream<STREAM: AsyncRead + AsyncWrite + Unpin> = STREAM;
    }

    pub enum Tls {}
    impl TlsMode for Tls {
        type Stream<STREAM: AsyncRead + AsyncWrite + Unpin> = TlsStream<STREAM>;
    }

    mod private_tls_mode {
        pub trait Sealed {}
        impl Sealed for super::Tls {}
        impl Sealed for super::NoTls {}
    }
}

pub struct Connection<
    STREAM: AsyncRead + AsyncWrite + Unpin,
    TLS: state::TlsMode,
    MODE: state::AuthMode,
> {
    pub(crate) stream: TLS::Stream<STREAM>,
    pub(crate) capabilities: Capabilities,
    pub(crate) _p: PhantomData<MODE>,
}

impl<STREAM: AsyncRead + AsyncWrite + Unpin, TLS: state::TlsMode, AUTH: state::AuthMode> Debug
    for Connection<STREAM, TLS, AUTH>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct(type_name::<Self>())
            .field("capabilities", &self.capabilities)
            .field("stream", &type_name::<STREAM>())
            .finish()
    }
}

impl<STREAM: AsyncRead + AsyncWrite + Unpin, TLS: state::TlsMode, AUTH: state::AuthMode>
    Connection<STREAM, TLS, AUTH>
{
    pub fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
}

type Result<T, E = SieveError> = core::result::Result<T, E>;

#[derive(thiserror::Error, Debug)]
pub enum SieveError {
    #[error("encountered I/0 error")]
    Io(#[from] io::Error),

    #[error("syntax error")]
    Syntax,

    #[error(transparent)]
    CapabilitiesError(#[from] CapabilitiesError),

    #[error("received an unexpected ` BYE ` response: {info}")]
    Bye { info: ResponseInfo },

    #[error("received an unexpected `NO` response: {info}")]
    UnexpectedNo { info: ResponseInfo },
}

// #[derive(thiserror::Error, Debug)]
// #[error("received an unexpected `NO` response: {info}")]
// struct UnexpectedNo {
//     info: ResponseInfo
// }

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Quota {
    Unspecified,
    MaxScripts,
    MaxSize,
}

#[derive(Debug, PartialEq, Clone)]
pub enum ResponseCode {
    AuthTooWeak,
    EncryptNeeded,
    Quota(Quota),
    Referral(String),
    Sasl(String),
    TransitionNeeded,
    TryLater,
    Active,
    Nonexistent,
    AlreadyExists,
    Warnings,
    Tag(String),
    Extension {
        name: String,
        data: Option<Vec<ExtensionItem>>,
    },
}

impl Display for ResponseCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ResponseCode::AuthTooWeak => write!(f, "AUTH-TOO-WEAK")?,
            ResponseCode::EncryptNeeded => write!(f, "ENCRYPT-NEEDED")?,
            ResponseCode::Quota(Quota::Unspecified) => write!(f, "QUOTA")?,
            ResponseCode::Quota(Quota::MaxScripts) => write!(f, "QUOTA/MAXSCRIPTS")?,
            ResponseCode::Quota(Quota::MaxSize) => write!(f, "QUOTA/MAXSIZE")?,
            ResponseCode::Referral(r) => write!(f, "REFERRAL {r}")?,
            ResponseCode::Sasl(_) => write!(f, "SASL ...")?,
            ResponseCode::TransitionNeeded => write!(f, "TRANSITION-NEEDED")?,
            ResponseCode::TryLater => write!(f, "TRYLATER")?,
            ResponseCode::Active => write!(f, "ACTIVE")?,
            ResponseCode::Nonexistent => write!(f, "NONEXISTENT")?,
            ResponseCode::AlreadyExists => write!(f, "ALREADYEXISTS")?,
            ResponseCode::Warnings => write!(f, "WARNINGS")?,
            ResponseCode::Tag(t) => write!(f, "TAG {t}")?,
            ResponseCode::Extension { name, data } => {
                write!(f, "{name} ")?;
                let mut first = true;
                for item in data.iter().flatten() {
                    if !first {
                        write!(f, " ")?;
                    }
                    first = false;
                    write!(f, "{item}")?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum ExtensionItem {
    String(String),
    Number(u64),
    ExtensionData(Vec<ExtensionItem>),
}

impl Display for ExtensionItem {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtensionItem::String(s) => write!(f, "{s}")?,
            ExtensionItem::Number(n) => write!(f, "{n}")?,
            ExtensionItem::ExtensionData(d) => {
                write!(f, "(")?;
                let mut first = true;
                for item in d {
                    if !first {
                        write!(f, " ")?;
                    }
                    first = false;
                    write!(f, "{item}")?;
                }
                write!(f, ")")?;
            }
        }
        Ok(())
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct ResponseInfo {
    pub code: Option<ResponseCode>,
    pub human: Option<String>,
}

impl Display for ResponseInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let Some(code) = &self.code {
            write!(f, "({code})")?;
        }
        if self.code.is_some() && self.human.is_some() {
            write!(f, " ")?;
        }
        if let Some(human) = &self.human {
            write!(f, "{human}")?;
        }
        Ok(())
    }
}
