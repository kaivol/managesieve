use crate::capabilities::verify_capabilities;
use crate::commands::{handle_bye, next_response};
use crate::parser::responses::response_capability;
use crate::parser::Response;
use crate::state::{NoTls, Unauthenticated};
use crate::{AsyncRead, AsyncWrite, Connection, SieveError};

impl<STREAM: AsyncRead + AsyncWrite + Unpin> Connection<STREAM, NoTls, Unauthenticated> {
    pub async fn connect(mut stream: STREAM) -> Result<Self, SieveError> {
        let (capabilities, response) = next_response(&mut stream, response_capability).await?;

        // TODO close connection or send LOGOUT on error?
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
