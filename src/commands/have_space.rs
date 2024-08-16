use std::fmt::Debug;

use futures::{AsyncRead, AsyncWrite};

use crate::client::{handle_bye, next_response, Authenticated, TlsMode};
use crate::commands::ScriptName;
use crate::internal::command::Command;
use crate::internal::parser::{response_oknobye, Response, ResponseCode, Tag};
use crate::{Connection, SieveError};

#[derive(Debug)]
pub enum HaveSpace {
    Yes,
    No(Option<ResponseCode>, Option<String>),
}

impl<STREAM: AsyncRead + AsyncWrite + Unpin, TLS: TlsMode> Connection<STREAM, TLS, Authenticated> {
    pub async fn have_space(
        mut self,
        name: &ScriptName,
        size: u64,
    ) -> Result<(Self, HaveSpace), SieveError> {
        self.send_command(Command::have_space(name, size)).await?;

        let response = next_response(&mut self.stream, response_oknobye).await?;
        let Response { tag, info } = handle_bye(&mut self.stream, response).await?;

        let res = match tag {
            Tag::Ok(_) => HaveSpace::Yes,
            Tag::No(_) => HaveSpace::No(info.code, info.human),
        };

        Ok((self, res))
    }
}
