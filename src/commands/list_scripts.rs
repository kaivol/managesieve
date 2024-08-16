use futures::{AsyncRead, AsyncWrite};

use crate::client::{handle_bye, next_response, Authenticated, TlsMode};
use crate::commands::errors::{SieveResult, UnexpectedNo};
use crate::internal::command::Command;
use crate::internal::parser::{response_listscripts, Response, Tag};
use crate::{bail, Connection};

impl<STREAM: AsyncRead + AsyncWrite + Unpin, TLS: TlsMode> Connection<STREAM, TLS, Authenticated> {
    pub async fn list_scripts(mut self) -> SieveResult<(Self, Vec<(String, bool)>), UnexpectedNo> {
        self.send_command(Command::list_scripts()).await?;

        let (scripts, response) = next_response(&mut self.stream, response_listscripts).await?;
        let Response { tag, info } = handle_bye(&mut self.stream, response).await?;

        if matches!(tag, Tag::No(_)) {
            bail!(UnexpectedNo { info });
        }

        Ok((self, scripts))
    }
}
