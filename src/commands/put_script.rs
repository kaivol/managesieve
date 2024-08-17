use futures::{AsyncRead, AsyncWrite};

use crate::client::{handle_bye, next_response, Authenticated, TlsMode};
use crate::internal::command::Command;
use crate::internal::parser::{response_oknobye, QuotaVariant, Response, ResponseCode, Tag};
use crate::{Connection, SieveError};

#[derive(Debug)]
pub enum PutScript {
    Ok {
        warnings: Option<String>,
    },
    InvalidScript {
        error: Option<String>,
    },
    Quota {
        variant: QuotaVariant,
        message: Option<String>,
    },
    No {
        code: Option<ResponseCode>,
        human: Option<String>,
    },
}

impl<STREAM: AsyncRead + AsyncWrite + Unpin, TLS: TlsMode> Connection<STREAM, TLS, Authenticated> {
    pub async fn put_scripts(mut self) -> Result<(Self, PutScript), SieveError> {
        self.send_command(Command::list_scripts()).await?;

        let response = next_response(&mut self.stream, response_oknobye).await?;
        let Response { tag, info } = handle_bye(&mut self.stream, response).await?;

        let res = match tag {
            Tag::Ok(_) => PutScript::Ok {
                warnings: matches!(info.code, Some(ResponseCode::Warnings))
                    .then_some(info.human)
                    .flatten(),
            },
            Tag::No(_) => match info.code {
                None => PutScript::InvalidScript { error: info.human },
                Some(ResponseCode::Quota(variant)) => PutScript::Quota {
                    variant,
                    message: info.human,
                },
                code => PutScript::No {
                    code,
                    human: info.human,
                },
            },
        };

        Ok((self, res))
    }
}
