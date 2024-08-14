use futures::{AsyncRead, AsyncWrite, AsyncWriteExt};
use snafu::{ResultExt, Snafu};

use crate::client::{handle_bye, next_response, AuthMode, Error, IoSnafu, TlsMode, UnexpectedNo};
use crate::internal::command::Command;
use crate::internal::parser::{response_oknobye, Response, Tag};
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
        self.send_command(Command::logout()).await?;

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
