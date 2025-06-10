use either::Either;
use tracing::warn;

use crate::commands::{handle_bye, next_response};
use crate::parser::responses::response_getscript;
use crate::parser::Response;
use crate::state::{Authenticated, TlsMode};
use crate::{commands, AsyncRead, AsyncWrite, Connection, ResponseCode, Result, SieveNameStr};

// #[derive(Debug)]
// pub enum GetScript {
//     Ok {
//         script: String,
//     },
//     NonExistent,
//     No {
//         info: ResponseInfo
//     },
// }

impl<STREAM: AsyncRead + AsyncWrite + Unpin, TLS: TlsMode> Connection<STREAM, TLS, Authenticated> {
    pub async fn get_script(mut self, name: &SieveNameStr) -> Result<(Self, Option<String>)> {
        self.send_command(commands::definitions::get_script(name)).await?;

        let response = next_response(&mut self.stream, response_getscript).await?;

        let res = match response {
            Either::Left((script, _)) => Some(script),
            Either::Right(response) => {
                let Response { info, .. } = handle_bye(&mut self.stream, response).await?;

                if info.code != Some(ResponseCode::Nonexistent) {
                    warn!("`NO` reply from `GETSCRIPT` command is missing `NONEXISTENT` response code");
                }

                None
            }
        };

        Ok((self, res))
    }
}
