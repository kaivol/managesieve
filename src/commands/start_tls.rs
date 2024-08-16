use std::fmt::Debug;
use std::sync::Arc;

use futures::{AsyncRead, AsyncWrite};
use futures_rustls::pki_types::ServerName;
use futures_rustls::rustls::{ClientConfig, RootCertStore};
use futures_rustls::TlsConnector;
use thiserror::Error;

use crate::client::{handle_bye, next_response, NoTls, Tls, Unauthenticated};
use crate::commands::errors::{CapabilitiesError, SieveError, SieveResult, UnexpectedNo};
use crate::commands::verify_capabilities;
use crate::internal::command::Command;
use crate::internal::parser::{response_capability, response_ok, Response, Tag};
use crate::Connection;

#[derive(Error, PartialEq, Debug)]
pub enum StartTlsError {
    #[error("STARTTLS is not supported")]
    Unsupported,
    #[error(transparent)]
    UnexpectedNo(UnexpectedNo),
    #[error(transparent)]
    InvalidCapabilities(CapabilitiesError),
}

impl<STREAM: AsyncRead + AsyncWrite + Unpin> Connection<STREAM, NoTls, Unauthenticated> {
    pub async fn start_tls(
        mut self,
        server_name: ServerName<'static>,
    ) -> SieveResult<Connection<STREAM, Tls, Unauthenticated>, StartTlsError> {
        // Abort immediately if the server does not support STARTTLS
        if !self.capabilities.start_tls {
            return Err(StartTlsError::Unsupported.into());
        }

        self.send_command(Command::start_tls()).await?;

        let Response {
            tag: Tag::Ok(_),
            info: _info,
        } = next_response(&mut self.stream, response_ok).await?;

        let root_store = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect::<RootCertStore>();
        #[rustfmt::skip] let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let config = TlsConnector::from(Arc::new(config));

        let mut stream = config.connect(server_name, self.stream).await.map_err(SieveError::Io)?;

        let (capabilities, response) = next_response(&mut stream, response_capability).await?;
        let Response { tag, info } = handle_bye(&mut stream, response).await?;

        match tag {
            Tag::Ok(_) => Ok(Connection {
                stream,
                // TODO close connection or send LOGOUT when capabilities are invalid?
                capabilities: verify_capabilities(capabilities)
                    .map_err(StartTlsError::InvalidCapabilities)?,
                _p: Default::default(),
            }),
            Tag::No(_) => Err(SieveError::from(StartTlsError::UnexpectedNo(UnexpectedNo { info }))),
        }
    }
}
