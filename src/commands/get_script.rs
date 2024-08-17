
use either::Either;
use futures::{AsyncRead, AsyncWrite};

use crate::client::{handle_bye, next_response, Authenticated, TlsMode};
use crate::internal::command::Command;
use crate::internal::parser::{
    response_getscript, Response, ResponseCode,
};
use crate::{Connection, SieveError};
use crate::commands::ScriptName;

#[derive(Debug)]
pub enum GetScript {
    Ok {
        script: String,
    },
    NonExistent,
    No {
        code: Option<ResponseCode>,
        human: Option<String>,
    },
}

impl<STREAM: AsyncRead + AsyncWrite + Unpin, TLS: TlsMode> Connection<STREAM, TLS, Authenticated> {
    pub async fn get_script(mut self, name: &ScriptName) -> Result<(Self, GetScript), SieveError> {
        self.send_command(Command::getscript(name)).await?;

        let response = next_response(&mut self.stream, response_getscript).await?;

        let res = match response {
            Either::Left((script, _)) => GetScript::Ok { script },
            Either::Right(response) => {
                let Response { info, .. } = handle_bye(&mut self.stream, response).await?;
                match info.code {
                    Some(ResponseCode::Nonexistent) => GetScript::NonExistent,
                    code => GetScript::No {
                        code,
                        human: info.human,
                    },
                }
            }
        };

        Ok((self, res))
    }
}
