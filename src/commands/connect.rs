use core::str;
use std::fmt::Debug;

use futures::{AsyncRead, AsyncWrite};
use snafu::Snafu;

use crate::client::{
    handle_bye, next_response, verify_capabilities, CapabilitiesError, Error, NoTls,
    Unauthenticated, UnexpectedNo,
};
use crate::internal::parser::{response_capability, Response, Tag};
use crate::Connection;

#[derive(Snafu, PartialEq, Debug)]
pub enum ConnectError {
    #[snafu(transparent)]
    UnexpectedNo { source: UnexpectedNo },
    #[snafu(transparent)]
    InvalidCapabilities { source: CapabilitiesError },
}

impl<STREAM: AsyncRead + AsyncWrite + Unpin> Connection<STREAM, NoTls, Unauthenticated> {
    pub async fn connect(mut stream: STREAM) -> Result<Self, Error<ConnectError>> {
        let (capabilities, response) = next_response(&mut stream, response_capability).await?;

        let Response { tag, info } = handle_bye(&mut stream, response).await?;

        match tag {
            Tag::Ok(_) => Ok(Connection {
                stream,
                // TODO close connection or send LOGOUT when capabilities are invalid?
                capabilities: verify_capabilities(capabilities)
                    .map_err(|source| ConnectError::InvalidCapabilities { source })?,
                _p: Default::default(),
            }),
            Tag::No(_) => Err(Error::from(ConnectError::from(UnexpectedNo { info }))),
        }
    }
}
