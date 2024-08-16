use futures::{AsyncRead, AsyncWrite, AsyncWriteExt};
use thiserror::{Error};

use crate::client::{handle_bye, next_response, AuthMode, TlsMode, UnexpectedNo};
use crate::internal::command::Command;
use crate::internal::parser::{response_oknobye, Response, Tag};
use crate::{Connection, SieveError};

#[derive(Error, PartialEq, Debug)]
pub enum LogoutError {
    #[error(transparent)]
    UnexpectedNo(UnexpectedNo),
}

impl<STREAM: AsyncRead + AsyncWrite + Unpin, TLS: TlsMode, MODE: AuthMode>
    Connection<STREAM, TLS, MODE>
{
    pub async fn logout(mut self) -> Result<(), SieveError<LogoutError>> {
        self.send_command(Command::logout()).await?;

        let response = next_response(&mut self.stream, response_oknobye).await?;
        let Response { tag, info } = handle_bye(&mut self.stream, response).await?;

        match tag {
            Tag::No(_) => Err(LogoutError::UnexpectedNo(UnexpectedNo { info }).into()),
            Tag::Ok(_) => {
                self.stream.close().await.map_err(SieveError::Io)?;
                Ok(())
            }
        }
    }
}
