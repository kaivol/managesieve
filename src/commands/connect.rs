use std::fmt::Debug;

use futures::{AsyncRead, AsyncWrite};
use thiserror::Error;

use crate::client::{handle_bye, next_response, NoTls, Unauthenticated};
use crate::commands::errors::{CapabilitiesError, SieveError, UnexpectedNo};
use crate::commands::verify_capabilities;
use crate::internal::parser::{response_capability, Response, Tag};
use crate::{bail, Connection};

#[derive(Error, Debug)]
pub enum ConnectError {
    #[error(transparent)]
    UnexpectedNo(#[from] UnexpectedNo),
    #[error(transparent)]
    InvalidCapabilities(#[from] CapabilitiesError),
    #[error(transparent)]
    Other(#[from] SieveError),
}

impl<STREAM: AsyncRead + AsyncWrite + Unpin> Connection<STREAM, NoTls, Unauthenticated> {
    pub async fn connect(mut stream: STREAM) -> Result<Self, ConnectError> {
        let (capabilities, response) = next_response(&mut stream, response_capability).await?;

        let Response { tag, info } = handle_bye(&mut stream, response).await?;

        match tag {
            Tag::Ok(_) => Ok(Connection {
                stream,
                // TODO close connection or send LOGOUT when capabilities are invalid?
                capabilities: verify_capabilities(capabilities)?,
                _p: Default::default(),
            }),
            Tag::No(_) => bail!(UnexpectedNo { info }),
        }
    }
}
