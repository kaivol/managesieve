use tracing::warn;

use crate::commands::{handle_bye, next_response};
use crate::parser::responses::response_oknobye;
use crate::parser::{Response, Tag};
use crate::state::{Authenticated, TlsMode};
use crate::{
    commands, AsyncRead, AsyncWrite, Connection, Quota, ResponseCode, ResponseInfo, SieveError,
    SieveNameStr,
};

#[derive(Debug)]
pub enum PutScript {
    Ok {
        warnings: Option<String>,
    },
    InvalidScript {
        error: Option<String>,
    },
    InsufficientQuota {
        quota: Quota,
        message: Option<String>,
    },
}

impl<STREAM: AsyncRead + AsyncWrite + Unpin, TLS: TlsMode> Connection<STREAM, TLS, Authenticated> {
    pub async fn put_scripts(
        mut self,
        name: &SieveNameStr,
        script: &str,
    ) -> Result<(Self, PutScript), SieveError> {
        self.send_command(commands::definitions::put_script(name, script)).await?;

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
                PutScript::Ok { warnings }
            }
            Tag::No(_) => match code {
                Some(ResponseCode::Quota(variant)) => PutScript::InsufficientQuota {
                    quota: variant,
                    message: human,
                },
                code => {
                    if let Some(code) = code {
                        warn!("unexpected response code `{code}` in `NO` reply from `HAVESPACE` command");
                    }
                    PutScript::InvalidScript { error: human }
                }
            },
        };

        Ok((self, res))
    }
}
