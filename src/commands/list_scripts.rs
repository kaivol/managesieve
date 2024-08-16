use core::str;
use std::fmt::Debug;

use futures::{AsyncRead, AsyncWrite};
use thiserror::Error;

use crate::client::{
    handle_bye, next_response, Authenticated, RecoverableError, SieveResult, TlsMode, UnexpectedNo,
};
use crate::internal::command::Command;
use crate::internal::parser::{response_listscripts, Response, Tag};
use crate::Connection;

#[derive(Error, PartialEq, Debug)]
pub enum ListScriptsError {
    #[error(transparent)]
    UnexpectedNo(UnexpectedNo),
}

impl<STREAM: AsyncRead + AsyncWrite + Unpin, TLS: TlsMode> Connection<STREAM, TLS, Authenticated> {
    pub async fn list_scripts(
        mut self,
    ) -> SieveResult<(Self, Vec<(String, bool)>), RecoverableError<ListScriptsError, Self>> {
        self.send_command(Command::list_scripts()).await?;

        let (scripts, response) = next_response(&mut self.stream, response_listscripts).await?;
        let Response { tag, info } = handle_bye(&mut self.stream, response).await?;

        if matches!(tag, Tag::No(_)) {
            return Err(From::from(RecoverableError {
                connection: self,
                source: ListScriptsError::UnexpectedNo(UnexpectedNo { info }),
            }));
        }

        Ok((self, scripts))
    }
}
