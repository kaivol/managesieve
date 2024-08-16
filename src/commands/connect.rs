use core::str;
use std::fmt::Debug;

use futures::{AsyncRead, AsyncWrite};
use thiserror::Error;

use crate::client::{handle_bye, next_response, verify_capabilities, CapabilitiesError, NoTls, Unauthenticated, UnexpectedNo, SieveError};
use crate::internal::parser::{response_capability, Response, Tag};
use crate::Connection;

#[derive(Error, PartialEq, Debug)]
pub enum ConnectError {
    #[error(transparent)]
    UnexpectedNo(UnexpectedNo),
    #[error(transparent)]
    InvalidCapabilities(CapabilitiesError),
}

impl<STREAM: AsyncRead + AsyncWrite + Unpin> Connection<STREAM, NoTls, Unauthenticated> {
    pub async fn connect(mut stream: STREAM) -> Result<Self, SieveError<ConnectError>> {
        let (capabilities, response) = next_response(&mut stream, response_capability).await?;

        let Response { tag, info } = handle_bye(&mut stream, response).await?;

        match tag {
            Tag::Ok(_) => Ok(Connection {
                stream,
                // TODO close connection or send LOGOUT when capabilities are invalid?
                capabilities: verify_capabilities(capabilities)
                    .map_err(|source| ConnectError::InvalidCapabilities(source))?,
                _p: Default::default(),
            }),
            Tag::No(_) => Err(SieveError::from(ConnectError::UnexpectedNo(UnexpectedNo { info }))),
        }
    }
}
