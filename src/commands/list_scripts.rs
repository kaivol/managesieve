use futures::{AsyncRead, AsyncWrite};
use thiserror::Error;

use crate::client::{handle_bye, next_response, Authenticated, TlsMode};
use crate::commands::errors::UnexpectedNo;
use crate::internal::command::Command;
use crate::internal::parser::{response_listscripts, Response, Tag};
use crate::{bail, Connection, SieveError};

#[derive(Error, Debug)]
pub enum ListScriptError {
    #[error(transparent)]
    UnexpectedNo(#[from] UnexpectedNo),
    #[error(transparent)]
    Other(#[from] SieveError),
}

impl<STREAM: AsyncRead + AsyncWrite + Unpin, TLS: TlsMode> Connection<STREAM, TLS, Authenticated> {
    pub async fn list_scripts(mut self) -> Result<(Self, Vec<(String, bool)>), ListScriptError> {
        self.send_command(Command::list_scripts()).await?;

        let (scripts, response) = next_response(&mut self.stream, response_listscripts).await?;
        let Response { tag, info } = handle_bye(&mut self.stream, response).await?;

        if matches!(tag, Tag::No(_)) {
            bail!(UnexpectedNo { info });
        }

        Ok((self, scripts))
    }
}
