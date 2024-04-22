use std::convert::Infallible;
use std::future::poll_fn;
use std::pin::Pin;

use futures::{AsyncRead, AsyncWrite, AsyncWriteExt};
use snafu::Snafu;
use snafu::ResultExt;
use crate::client::{handle_bye, next_response, AuthMode, Error, SieveResult, TlsMode, UnexpectedNo, CapabilitiesError, IoSnafu};
use crate::internal::command::Command;
use crate::internal::parser::{response_oknobye, Response, Tag, No};
use crate::Connection;


#[derive(Snafu, PartialEq, Debug)]
pub enum ConnectError {
    #[snafu(transparent)]
    UnexpectedNo { source: UnexpectedNo },
}

impl<STREAM: AsyncRead + AsyncWrite + Unpin, TLS: TlsMode, MODE: AuthMode>
    Connection<STREAM, TLS, MODE>
{
    pub async fn logout(mut self) -> Result<(), Error<ConnectError>> {
        let command = Command::logout().to_string();
        self.stream.write_all(command.as_bytes()).await.unwrap();

        let response = next_response(&mut self.stream, response_oknobye).await?;
        let Response { tag, info } = handle_bye(&mut self.stream, response).await?;

        match tag {
            Tag::No(_) => Err(ConnectError::from(UnexpectedNo { info }).into()),
            Tag::Ok(_) => {
                self.stream.close().await.context(IoSnafu)?;
                Ok(())
            }
        }
    }
}
