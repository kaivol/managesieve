use core::str;
use std::collections::HashMap;
use std::fmt::{Debug, Display};

use futures::{AsyncRead, AsyncWrite};
use snafu::{AsErrorSource, Snafu};

use crate::client::{CapabilitiesError, Error, handle_bye, next_response, NoTls, Unauthenticated, UnexpectedNo, verify_capabilities};
use crate::Connection;
use crate::internal::parser::{
    Response, response_capability, Tag, Version,
};

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
                capabilities: verify_capabilities(capabilities).map_err(|source| ConnectError::InvalidCapabilities { source })?,
                _p: Default::default(),
            }),
            Tag::No(_) => Err(Error::from(ConnectError::from(UnexpectedNo { info }))),
        }
    }
}
