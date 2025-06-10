use std::io;
use std::sync::Arc;

use futures_rustls::pki_types::ServerName;
use futures_rustls::rustls::ClientConfig;
use futures_rustls::TlsConnector;
use rustls_platform_verifier::ConfigVerifierExt;
use tracing::warn;

use crate::capabilities::verify_capabilities;
use crate::commands::{handle_bye, next_response};
use crate::parser::responses::{response_capability, response_oknobye};
use crate::parser::Response;
use crate::state::{NoTls, Tls, Unauthenticated};
use crate::{commands, AsyncRead, AsyncWrite, Connection, SieveError};

impl<STREAM: AsyncRead + AsyncWrite + Unpin> Connection<STREAM, NoTls, Unauthenticated> {
    pub async fn start_tls(
        mut self,
        server_name: ServerName<'static>,
    ) -> Result<Connection<STREAM, Tls, Unauthenticated>, SieveError> {
        if !self.capabilities.start_tls {
            warn!("server does not support TLS");
        }

        self.send_command(commands::definitions::start_tls).await?;

        let response = next_response(&mut self.stream, response_oknobye).await?;
        let Response { tag, info } = handle_bye(&mut self.stream, response).await?;
        if tag.is_no() {
            return Err(SieveError::UnexpectedNo { info });
        }

        let config = ClientConfig::with_platform_verifier().map_err(io::Error::other)?;
        let config = TlsConnector::from(Arc::new(config));

        let mut stream =
            config.connect(server_name, self.stream).await.map_err(SieveError::from)?;

        let (capabilities, response) = next_response(&mut stream, response_capability).await?;
        let Response { tag, info } = handle_bye(&mut stream, response).await?;
        if tag.is_no() {
            return Err(SieveError::UnexpectedNo { info });
        }

        Ok(Connection {
            stream,
            capabilities: verify_capabilities(capabilities)?,
            _p: Default::default(),
        })
    }
}
