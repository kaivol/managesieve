use core::str;
use std::fmt::{Debug};

use futures::{AsyncRead, AsyncWrite};
use snafu::{Snafu};

use crate::client::{
    Authenticated, handle_bye, next_response, RecoverableError, SieveResult, TlsMode,
};
use crate::Connection;
use crate::internal::command::{Command, IllegalScriptName};
use crate::internal::parser::{QuotaVariant, ReponseInfo, Response, response_oknobye, Tag};
use crate::internal::parser::ResponseCode::Quota;

pub enum HaveSpace {
    Yes,
    No(QuotaVariant, Option<String>),
}

#[derive(Snafu, PartialEq, Debug)]
pub enum HaveSpaceError {
    #[snafu(transparent)]
    IllegalScriptName {
        source: IllegalScriptName,
    },
    UnexpectedNoResponseCode {
        info: ReponseInfo,
    },
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
                return Err(From::from(RecoverableError {
                    source: e.into(),
                    connection: self,
                }))
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
                    return Err(From::from(RecoverableError {
                        connection: self,
                        source: HaveSpaceError::UnexpectedNoResponseCode { info },
                    }))
                }
            },
        };

        Ok((self, res))
    }
}
