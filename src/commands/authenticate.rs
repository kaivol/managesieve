use std::fmt::Debug;
use std::pin::pin;

use base64::{engine, Engine};
use commands::definitions;
use either::Either;
use engine::general_purpose;
use general_purpose::STANDARD;

use crate::capabilities::verify_capabilities;
use crate::commands::{handle_bye, next_response};
use crate::parser::responses::{response_authenticate, response_capability, response_nobye};
use crate::parser::{Response, Tag};
use crate::sasl::{InitialSaslState, Sasl, SaslError};
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
        sasl: impl Sasl<'_, Error = E>,
    ) -> Result<Authenticate<E, STREAM, TLS>, SieveError> {
        let mut sasl = pin!(sasl);
        let (initial, mut client_finished) = match sasl.init() {
            InitialSaslState::None => (None, false),
            InitialSaslState::Yielded(i) => (Some(i), false),
            InitialSaslState::Complete(i) => (Some(i), true),
        };

        self.send_command(definitions::authenticate(
            sasl.name(),
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
                    let client_response = sasl.as_mut().resume(server_challenge);

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
                            let client_response = sasl.resume(server_challenge);

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
                                _ => SaslError::Other {
                                    message: info.human,
                                },
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
}
