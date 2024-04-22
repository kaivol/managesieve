use snafu::ResultExt;
use core::str;
use std::convert::Infallible;
use std::fmt::{Debug};
use std::sync::Arc;

use futures::{AsyncRead, AsyncWrite};
use futures_rustls::rustls::{ClientConfig, RootCertStore};
use futures_rustls::{pki_types, TlsConnector};
use futures_rustls::pki_types::ServerName;
use snafu::{Snafu};

use crate::client::{Authenticated, CapabilitiesError, Error, handle_bye, IoSnafu, next_response, NoTls, RecoverableError, SieveResult, Tls, TlsMode, Unauthenticated, UnexpectedNo, verify_capabilities};
use crate::{client, Connection};
use crate::commands::connect::ConnectError;
use crate::internal::command::{Command, IllegalScriptName};
use crate::internal::parser::{QuotaVariant, ReponseInfo, Response, response_capability, response_ok, response_oknobye, Tag, tag};
use crate::internal::parser::ResponseCode::Quota;


#[derive(Snafu, PartialEq, Debug)]
pub enum StartTlsError {
    Unsupported,
    #[snafu(transparent)]
    UnexpectedNo { source: UnexpectedNo },
    #[snafu(transparent)]
    InvalidCapabilities { source: CapabilitiesError },
}

impl<STREAM: AsyncRead + AsyncWrite + Unpin> Connection<STREAM, NoTls, Unauthenticated> {
    pub async fn start_tls(mut self, server_name: ServerName<'static>) -> SieveResult<Connection<STREAM, Tls, Unauthenticated>, StartTlsError> {
        // Abort immediately if the server does not support STARTTLS
        if !self.capabilities.start_tls {
            return Err(StartTlsError::Unsupported.into());
        }

        self.send_command(Command::start_tls()).await?;

        let Response { tag: Tag::Ok(_), info } = next_response(&mut self.stream, response_ok).await?;

        let root_store = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect::<RootCertStore>();
        let config: ClientConfig = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let config = TlsConnector::from(Arc::new(config));

        let mut stream = config.connect(server_name, self.stream).await.context(IoSnafu)?;

        let (capabilities, response) = next_response(&mut stream, response_capability).await?;
        let Response { tag, info } = handle_bye(&mut stream, response).await?;

        match tag {
            Tag::Ok(_) => Ok(Connection {
                stream,
                // TODO close connection or send LOGOUT when capabilities are invalid?
                capabilities: verify_capabilities(capabilities).map_err(|source| StartTlsError::InvalidCapabilities { source })?,
                _p: Default::default(),
            }),
            Tag::No(_) => Err(Error::from(StartTlsError::from(UnexpectedNo { info }))),
        }
    }
}
