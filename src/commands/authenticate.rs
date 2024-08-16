use core::str;
use std::fmt::Debug;
use futures::{AsyncRead, AsyncWrite};
use sasl::client::Mechanism;
use thiserror::Error;

use crate::client::{
    handle_bye, next_response, verify_capabilities, Authenticated, CapabilitiesError, SieveResult,
    TlsMode, Unauthenticated, UnexpectedNo,
};
use crate::internal::command::Command;
use crate::internal::parser::{response_capability, response_oknobye, Response, ResponseCode, Tag};
use crate::{bail, Connection};

#[derive(Error, PartialEq, Debug)]
pub enum AuthenticateError {
    #[error("server does not support `PLAIN` authentication")]
    Unsupported,
    #[error("authentication failed with error code `{code:?}`{}{}",
        if .reason.is_some() { ". Reason: " } else { "" },
        match .reason {
            Some(s) => s.as_str(),
            None => "",
        }
    )]
    AuthenticationFailed {
        code: AuthenticationErrorCode,
        reason: Option<String>,
    },
    #[error(transparent)]
    UnexpectedNo(UnexpectedNo),
    #[error(transparent)]
    InvalidCapabilities(CapabilitiesError),
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn auth_failed() {
        let error = AuthenticateError::AuthenticationFailed {
            code: AuthenticationErrorCode::EncryptNeeded,
            reason: Some("Shit happens".into()),
        };
        assert_eq!(
            error.to_string(),
            "authentication failed with error code `EncryptNeeded`. Reason: Shit happens",
        );
    }
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
            bail!(AuthenticateError::Unsupported);
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
                bail!(AuthenticateError::UnexpectedNo(UnexpectedNo { info }));
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
