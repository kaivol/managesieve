use futures::AsyncWriteExt;

use crate::commands::{handle_bye, next_response};
use crate::parser::responses::response_oknobye;
use crate::parser::{Response, Tag};
use crate::state::{AuthMode, TlsMode};
use crate::{commands, AsyncRead, AsyncWrite, Connection, SieveError};

impl<STREAM: AsyncRead + AsyncWrite + Unpin, TLS: TlsMode, MODE: AuthMode>
    Connection<STREAM, TLS, MODE>
{
    pub async fn logout(mut self) -> Result<(), SieveError> {
        self.send_command(commands::definitions::logout).await?;

        let response = next_response(&mut self.stream, response_oknobye).await?;
        let Response { tag, info } = handle_bye(&mut self.stream, response).await?;

        match tag {
            Tag::No(_) => Err(SieveError::UnexpectedNo { info }),
            Tag::Ok(_) => {
                self.stream.close().await.map_err(SieveError::from)?;
                Ok(())
            }
        }
    }
}
