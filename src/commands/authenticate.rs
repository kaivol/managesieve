use std::fmt::Debug;
use std::pin::Pin;

use base64::{engine, Engine};
use commands::definitions;
use either::Either;
use engine::general_purpose;
use general_purpose::STANDARD;

use crate::capabilities::verify_capabilities;
use crate::commands::{handle_bye, next_response};
use crate::parser::responses::{response_authenticate, response_capability, response_nobye};
use crate::parser::{Response, Tag};
use crate::sasl::{InitialSaslState, Sasl, SaslError, SaslInner};
use crate::state::{Authenticated, TlsMode, Unauthenticated};
use crate::{commands, AsyncRead, AsyncWrite, Connection, ResponseCode, SieveError};

#[derive(Debug)]
pub enum Authenticate<E, STREAM: AsyncRead + AsyncWrite + Unpin, TLS: TlsMode> {
    Ok {
        connection: Connection<STREAM, TLS, Authenticated>,
    },
    Error {
        connection: Option<Connection<STREAM, TLS, Unauthenticated>>,
        error: SaslError<E>,
    },
}

impl<STREAM: AsyncRead + AsyncWrite + Unpin, TLS: TlsMode>
    Connection<STREAM, TLS, Unauthenticated>
{
    pub async fn authenticate<E>(
        mut self,
        mut sasl: Pin<&mut Sasl<'_, impl SaslInner<Error = E>>>,
    ) -> Result<Authenticate<E, STREAM, TLS>, SieveError> {
        let (initial, mut client_finished) = match sasl.init {
            InitialSaslState::None => (None, false),
            InitialSaslState::Yielded(i) => (Some(i), false),
            InitialSaslState::Complete(i) => (Some(i), true),
        };

        self.send_command(definitions::authenticate(
            sasl.name,
            initial.map(|s| STANDARD.encode(s)).as_deref(),
        ))
        .await?;
        // TODO handle NO response specifically if initial message

        loop {
            match next_response(&mut self.stream, response_authenticate).await? {
                Either::Left(server_response) => {
                    // got SASL string

                    if client_finished {
                        // SASL is already finished, server should not send further challenge
                        return Ok(Authenticate::Error {
                            connection: Some(self),
                            error: SaslError::UnexpectedServerResponse,
                        });
                    }

                    let server_challenge = STANDARD.decode(server_response).unwrap();
                    let client_response = sasl.as_mut().project().f.resume(server_challenge);

                    let client_response = match client_response {
                        Ok(client_response) => client_response,
                        Err(sasl_error) => {
                            // error in SASL, cancel
                            self.send_command(definitions::sasl_string("*")).await?;

                            let response = next_response(&mut self.stream, response_nobye).await?;
                            let Response { .. } = handle_bye(&mut self.stream, response).await?;

                            return Ok(Authenticate::Error {
                                connection: Some(self),
                                error: SaslError::SaslError(sasl_error),
                            });
                        }
                    };

                    client_finished = client_response.is_finished();
                    let client_response = client_response.response().unwrap_or(vec![]);

                    self.send_command(definitions::sasl_string(&STANDARD.encode(client_response)))
                        .await?;
                }
                Either::Right(response) => {
                    // got managesieve response
                    let Response { tag, info } = handle_bye(&mut self.stream, response).await?;
                    match (tag, &info.code) {
                        (Tag::Ok(_), Some(ResponseCode::Sasl(server_challenge))) => {
                            // additional data in final message from server

                            if client_finished {
                                // SASL is already finished, server should not send further challenge
                                return Ok(Authenticate::Error {
                                    connection: Some(self),
                                    error: SaslError::UnexpectedServerResponse,
                                });
                            }

                            let server_challenge = STANDARD.decode(server_challenge).unwrap();
                            let client_response =
                                sasl.as_mut().project().f.resume(server_challenge);

                            let client_response = match client_response {
                                Ok(client_response) => client_response,
                                Err(sasl_error) => {
                                    return Ok(Authenticate::Error {
                                        connection: Some(self),
                                        error: SaslError::SaslError(sasl_error),
                                    });
                                }
                            };

                            if !client_response.has_response() {
                                break;
                            } else {
                                return Ok(Authenticate::Error {
                                    connection: Some(self),
                                    error: SaslError::UnexpectedOk,
                                });
                            }
                        }
                        (Tag::Ok(_), _) => {
                            // no additional data in final message from server

                            if client_finished {
                                break;
                            } else {
                                // SASL is not considered completed
                                return Ok(Authenticate::Error {
                                    connection: None,
                                    error: SaslError::UnexpectedOk,
                                });
                            }
                        }
                        (Tag::No(_), code) => {
                            // Got an unexpected NO response

                            let error = match code {
                                Some(ResponseCode::AuthTooWeak) => SaslError::AuthTooWeak,
                                Some(ResponseCode::EncryptNeeded) => SaslError::EncryptNeeded,
                                Some(ResponseCode::TransitionNeeded) => SaslError::TransitionNeeded,
                                _ => return Err(SieveError::UnexpectedNo { info }),
                            };
                            return Ok(Authenticate::Error {
                                connection: Some(self),
                                error,
                            });
                        }
                    }
                }
            }
        }

        self.send_command(definitions::capability).await?;
        let (capabilities, response) = next_response(&mut self.stream, response_capability).await?;
        let Response { tag, info } = handle_bye(&mut self.stream, response).await?;
        if tag.is_no() {
            return Err(SieveError::UnexpectedNo { info });
        }

        Ok(Authenticate::Ok {
            connection: Connection {
                stream: self.stream,
                capabilities: verify_capabilities(capabilities)?,
                _p: Default::default(),
            },
        })
    }

    // pub async fn authenticate_oauthbearer(
    //     mut self,
    //     username: &str,
    //     host: &str,
    //     port: u32,
    //     token: &str,
    // ) -> Result<Connection<STREAM, TLS, Authenticated>, AuthenticateError> {
    //     // Abort immediately if the server does not support STARTTLS
    //     if !self.capabilities.sasl.iter().any(|sasl| sasl.as_str() == "OAUTHBEARER") {
    //         bail!(AuthenticateError::Unsupported);
    //     }
    //
    //     let mut authzid = String::new();
    //     if !username.is_empty() {
    //         authzid = format!("a={}", username);
    //     }
    //     let mut str = format!("n,{},", authzid);
    //
    //     if !host.is_empty() {
    //         str = format!("{str}\x01host={}", host);
    //     }
    //
    //     if port != 0 {
    //         str = format!("{str}\x01port={}", port);
    //     }
    //     str = format!("{str}\x01auth=Bearer {}\x01\x01", token);
    //
    //     self.send_command(command::authenticate("OAUTHBEARER", Some(str.as_bytes())))
    //         .await?;
    //
    //     let response = next_response(&mut self.stream, string_or_response_oknobye).await?;
    //     let response = match response {
    //         Either::Left(sasl) => {
    //             let json = base64::engine::general_purpose::STANDARD.decode(&sasl).unwrap();
    //             let error = serde_json::from_slice::<Value>(&json).unwrap();
    //             warn!(?error);
    //             self.send_command(command::sasl_string("".as_bytes())).await?;
    //             next_response(&mut self.stream, response_oknobye).await?
    //         }
    //         Either::Right(response) => response,
    //     };
    //     let Response { tag, info } = handle_bye(&mut self.stream, response).await?;
    //
    //     if matches!(tag, Tag::No(_)) {
    //         bail!(AuthenticateError::AuthenticationFailed {
    //             code: info.code.into(),
    //             reason: info.human,
    //         });
    //     }
    //
    //     let capabilities = {
    //         self.send_command(command::capability).await?;
    //         let (capabilities, response) =
    //             next_response(&mut self.stream, response_capability).await?;
    //         let Response { tag, info } = handle_bye(&mut self.stream, response).await?;
    //         if matches!(tag, Tag::No(_)) {
    //             bail!(AuthenticateError::UnexpectedNo(UnexpectedNo { info }));
    //         }
    //         verify_capabilities(capabilities).map_err(AuthenticateError::InvalidCapabilities)?
    //     };
    //
    //     Ok(Connection {
    //         stream: self.stream,
    //         capabilities,
    //         _p: Default::default(),
    //     })
    // }
}

// #[cfg(test)]
// mod test {
//     use super::*;
//
//     #[test]
//     fn auth_failed() {
//         let error = AuthenticateError::AuthenticationFailed {
//             code: AuthenticateErrorCode::EncryptNeeded,
//             reason: Some("Shit happens".into()),
//         };
//         assert_eq!(
//             error.to_string(),
//             "authentication failed with error code `EncryptNeeded`. Reason: Shit happens",
//         );
//     }
// }
