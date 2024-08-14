use core::str;
use std::fmt::Debug;

use futures::{AsyncRead, AsyncWrite};
use sasl::client::Mechanism;
use snafu::Snafu;

use crate::client::{
    handle_bye, next_response, verify_capabilities, Authenticated, CapabilitiesError, SieveResult,
    TlsMode, Unauthenticated, UnexpectedNo,
};
use crate::internal::command::Command;
use crate::internal::parser::{response_capability, response_oknobye, Response, ResponseCode, Tag};
use crate::Connection;

#[derive(Snafu, PartialEq, Debug)]
pub enum AuthenticateError {
    Unsupported,
    AuthenticationFailed {
        code: AuthenticationErrorCode,
        reason: Option<String>,
    },
    #[snafu(transparent)]
    UnexpectedNo {
        source: UnexpectedNo,
    },
    #[snafu(transparent)]
    InvalidCapabilities {
        source: CapabilitiesError,
    },
}

#[derive(Debug, PartialEq)]
pub enum AuthenticationErrorCode {
    None,
    AuthTooWeak,
    EncryptNeeded,
    TransitionNeeded,
    Other(ResponseCode),
}

impl<STREAM: AsyncRead + AsyncWrite + Unpin, TLS: TlsMode>
    Connection<STREAM, TLS, Unauthenticated>
{
    pub async fn authenticate(
        mut self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> SieveResult<Connection<STREAM, TLS, Authenticated>, AuthenticateError> {
        // Abort immediately if the server does not support STARTTLS
        if !self.capabilities.sasl.iter().any(|sasl| sasl.as_str() == "PLAIN") {
            return Err(AuthenticateError::Unsupported.into());
        }

        let mut plain = sasl::client::mechanisms::Plain::new(username, password);
        let initial = plain.initial();
        self.send_command(Command::authenticate("PLAIN", Some(initial.as_slice())))
            .await?;

        let response = next_response(&mut self.stream, response_oknobye).await?;
        let Response { tag, info } = handle_bye(&mut self.stream, response).await?;

        if matches!(tag, Tag::No(_)) {
            return Err(AuthenticateError::AuthenticationFailed {
                code: match info.code {
                    None => AuthenticationErrorCode::None,
                    Some(ResponseCode::AuthTooWeak) => AuthenticationErrorCode::AuthTooWeak,
                    Some(ResponseCode::EncryptNeeded) => AuthenticationErrorCode::EncryptNeeded,
                    Some(ResponseCode::TransitionNeeded) => {
                        AuthenticationErrorCode::TransitionNeeded
                    }
                    Some(code) => AuthenticationErrorCode::Other(code),
                },
                reason: info.human,
            }
            .into());
        }

        let capabilities = {
            self.send_command(Command::capability()).await?;
            let (capabilities, response) =
                next_response(&mut self.stream, response_capability).await?;
            let Response { tag, info } = handle_bye(&mut self.stream, response).await?;
            if matches!(tag, Tag::No(_)) {
                return Err(AuthenticateError::from(UnexpectedNo { info }).into());
            }
            verify_capabilities(capabilities).unwrap()
        };

        Ok(Connection {
            stream: self.stream,
            capabilities,
            _p: Default::default(),
        })
    }
}
