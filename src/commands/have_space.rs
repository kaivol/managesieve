use core::str;
use std::fmt::Debug;

use futures::{AsyncRead, AsyncWrite};
use thiserror::Error;

use crate::client::{
    handle_bye, next_response, Authenticated, RecoverableError, SieveResult, TlsMode, UnexpectedNo,
};
use crate::internal::command::{Command, IllegalScriptName};
use crate::internal::parser::ResponseCode::Quota;
use crate::internal::parser::{response_oknobye, QuotaVariant, Response, Tag};
use crate::{bail, Connection};

#[derive(Debug)]
pub enum HaveSpace {
    Yes,
    No(QuotaVariant, Option<String>),
}

#[derive(Error, PartialEq, Debug)]
pub enum HaveSpaceError {
    #[error(transparent)]
    IllegalScriptName(IllegalScriptName),
    #[error(transparent)]
    UnexpectedNo(UnexpectedNo),
}

impl<STREAM: AsyncRead + AsyncWrite + Unpin, TLS: TlsMode> Connection<STREAM, TLS, Authenticated> {
    pub async fn have_space(
        mut self,
        name: &str,
        size: u64,
    ) -> SieveResult<(Self, HaveSpace), RecoverableError<HaveSpaceError, Self>> {
        let command = match Command::have_space(name, size) {
            Ok(c) => c,
            Err(e) => {
                bail!(RecoverableError {
                    connection: self,
                    source: HaveSpaceError::IllegalScriptName(e),
                })
            }
        };
        self.send_command(command).await?;

        let response = next_response(&mut self.stream, response_oknobye).await?;
        let Response { tag, info } = handle_bye(&mut self.stream, response).await?;

        let res = match tag {
            Tag::Ok(_) => HaveSpace::Yes,
            Tag::No(_) => match info.code {
                Some(Quota(q)) => HaveSpace::No(q, info.human),
                _ => {
                    bail!(RecoverableError {
                        connection: self,
                        source: HaveSpaceError::UnexpectedNo(UnexpectedNo { info }),
                    })
                }
            },
        };

        Ok((self, res))
    }
}
