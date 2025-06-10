use crate::commands::{handle_bye, next_response};
use crate::parser::responses::response_listscripts;
use crate::parser::Response;
use crate::state::{Authenticated, TlsMode};
use crate::{commands, AsyncRead, AsyncWrite, Connection, SieveError};

impl<STREAM: AsyncRead + AsyncWrite + Unpin, TLS: TlsMode> Connection<STREAM, TLS, Authenticated> {
    pub async fn list_scripts(mut self) -> Result<(Self, Vec<(String, bool)>), SieveError> {
        self.send_command(commands::definitions::list_scripts).await?;

        let (scripts, response) = next_response(&mut self.stream, response_listscripts).await?;
        let Response { tag, info } = handle_bye(&mut self.stream, response).await?;

        if tag.is_no() {
            return Err(SieveError::UnexpectedNo { info });
        }

        Ok((self, scripts))
    }
}
