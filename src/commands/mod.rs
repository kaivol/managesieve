mod authenticate;
mod check_script;
mod connect;
mod definitions;
mod get_script;
mod have_space;
mod list_scripts;
mod logout;
mod put_script;
mod start_tls;

use std::convert::Infallible;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::task::{ready, Poll};
use std::{io, str};

use definitions::{Command, SieveWriter};
use futures::AsyncWriteExt;
use tracing::{debug, warn};
use winnow::combinator::{eof, terminated};
use winnow::error::ErrMode;
use winnow::{ModalResult as PResult, Parser, Partial};

pub use self::authenticate::*;
pub use self::check_script::*;
pub use self::have_space::*;
pub use self::put_script::*;
use crate::parser::responses::Input;
use crate::parser::{tag, tag_trait, Response, Tag};
use crate::state::{AuthMode, TlsMode};
use crate::{AsyncRead, AsyncWrite, Connection, SieveError};

impl<STREAM: AsyncRead + AsyncWrite + Unpin, TLS: TlsMode, AUTH: AuthMode>
    Connection<STREAM, TLS, AUTH>
{
    #[tracing::instrument(skip_all)]
    pub(crate) async fn send_command(
        &mut self,
        command: impl Command<'_, <TLS as TlsMode>::Stream<STREAM>>,
    ) -> Result<(), SieveError> {
        let res: Result<(), SieveError> = async {
            let writer = SieveWriter(&mut self.stream);
            command(writer).await?;
            self.stream.flush().await?;
            Ok(())
        }
        .await;

        if let Err(err) = res {
            self.stream.close().await?;
            Err(err)
        } else {
            Ok(())
        }
    }
}

pub(crate) async fn handle_bye<OK: tag_trait::Ok, NO: tag_trait::No, STREAM: AsyncWrite + Unpin>(
    stream: &mut STREAM,
    Response { tag, info }: Response<OK, NO, tag::Bye>,
) -> Result<Response<OK, NO, Infallible>, SieveError> {
    match tag {
        Tag::Bye(_) => {
            stream.close().await?;
            Err(SieveError::Bye { info })
        }
        Tag::Ok(ok) => Ok(Response {
            tag: Tag::Ok(ok),
            info,
        }),
        Tag::No(no) => Ok(Response {
            tag: Tag::No(no),
            info,
        }),
    }
}

pub(crate) async fn next_response<STREAM: AsyncRead + AsyncWrite + Unpin, RES: 'static + Debug>(
    stream: &mut STREAM,
    parser: fn(Input) -> PResult<RES>,
) -> Result<RES, SieveError> {
    let res = next_response_inner(stream, parser).await;
    debug!(?res);
    if res.is_err() {
        stream.close().await?;
    }
    res
}

pub(crate) fn next_response_inner<STREAM: AsyncRead + Unpin, RES: 'static>(
    stream: &mut STREAM,
    parser: fn(Input) -> PResult<RES>,
) -> impl Future<Output = Result<RES, SieveError>> + '_ {
    let mut buf = String::new();
    let mut pin = Pin::new(stream);

    std::future::poll_fn::<Result<RES, SieveError>, _>(move |cx| loop {
        let mut temp = [0u8; 1024];
        let read_count = ready!(pin.as_mut().poll_read(cx, &mut temp))?;

        if read_count == 0 {
            return Poll::Ready(Err(SieveError::Io(io::Error::from(io::ErrorKind::UnexpectedEof))));
        }

        let Ok(str) = str::from_utf8(&temp[0..read_count]) else {
            return Poll::Ready(Err(SieveError::Io(io::Error::from(io::ErrorKind::InvalidData))));
        };
        buf.push_str(str);

        match terminated(parser, eof).parse_next(&mut Partial::new(buf.as_str())) {
            Err(ErrMode::Incomplete(_)) => continue,
            Ok(res) => return Poll::Ready(Ok(res)),
            Err(err) => {
                warn!(?err, buf);
                // TODO improve parser error handling
                return Poll::Ready(Err(SieveError::Syntax));
            }
        }
    })
}
