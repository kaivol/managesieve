use std::fmt::Debug;

use tracing::warn;

use crate::commands::{handle_bye, next_response};
use crate::parser::responses::response_oknobye;
use crate::parser::{Response, Tag};
use crate::state::{Authenticated, TlsMode};
use crate::{
    commands, AsyncRead, AsyncWrite, Connection, Quota, ResponseCode, Result, SieveError,
    SieveNameStr,
};

#[derive(Debug)]
pub enum HaveSpace {
    Ok,
    InsufficientQuota {
        quota: Quota,
        message: Option<String>,
    },
}

impl<STREAM: AsyncRead + AsyncWrite + Unpin, TLS: TlsMode> Connection<STREAM, TLS, Authenticated> {
    pub async fn have_space(
        mut self,
        name: &SieveNameStr,
        size: u32,
    ) -> Result<(Self, HaveSpace), SieveError> {
        self.send_command(commands::definitions::have_space(name, size)).await?;

        let response = next_response(&mut self.stream, response_oknobye).await?;
        let Response { tag, info } = handle_bye(&mut self.stream, response).await?;

        let res = match tag {
            Tag::Ok(_) => HaveSpace::Ok,
            Tag::No(_) => {
                let quota = match info.code {
                    Some(ResponseCode::Quota(variant)) => variant,
                    None => Quota::Unspecified,
                    Some(code) => {
                        // according to spec, unknown response codes must be ignored
                        warn!("unexpected response code `{code}` in `NO` reply from `HAVESPACE` command");
                        Quota::Unspecified
                    }
                };
                HaveSpace::InsufficientQuota {
                    quota,
                    message: info.human,
                }
            }
        };

        Ok((self, res))
    }
}
