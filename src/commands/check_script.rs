use tracing::warn;

use crate::commands::{handle_bye, next_response};
use crate::parser::responses::response_oknobye;
use crate::parser::{Response, Tag};
use crate::state::{Authenticated, TlsMode};
use crate::{commands, AsyncRead, AsyncWrite, Connection, ResponseCode, ResponseInfo, SieveError};

#[derive(Debug)]
pub enum CheckScript {
    Ok { warnings: Option<String> },
    InvalidScript { error: Option<String> },
}

impl<STREAM: AsyncRead + AsyncWrite + Unpin, TLS: TlsMode> Connection<STREAM, TLS, Authenticated> {
    pub async fn check_script(mut self, script: &str) -> Result<(Self, CheckScript), SieveError> {
        self.send_command(commands::definitions::check_script(script)).await?;

        let response = next_response(&mut self.stream, response_oknobye).await?;
        let Response {
            tag,
            info: ResponseInfo { code, human },
        } = handle_bye(&mut self.stream, response).await?;

        let res = match tag {
            Tag::Ok(_) => {
                let warnings = if code == Some(ResponseCode::Warnings) {
                    human
                } else {
                    None
                };
                CheckScript::Ok { warnings }
            }
            Tag::No(_) => {
                if let Some(code) = code {
                    warn!(
                        "unexpected response code `{code}` in `NO` reply from `HAVESPACE` command"
                    );
                }
                CheckScript::InvalidScript { error: human }
            }
        };

        Ok((self, res))
    }
}
