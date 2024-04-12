use core::str;
use std::future::Future;
use std::io::ErrorKind;
use std::marker::PhantomData;
use std::pin::{pin, Pin};
use std::task::{ready, Poll};

use futures::io::{BufReader, Lines};
use futures::{
    pin_mut, stream, AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite,
    AsyncWriteExt, StreamExt,
};

use crate::internal::response::response_capability;

trait Mode {}
pub struct Authenticated {}
impl Mode for Authenticated {}
pub struct Unauthenticated {}
impl Mode for Unauthenticated {}

pub struct Connection<STREAM, MODE> {
    stream: BufReader<STREAM>,
    _p: PhantomData<MODE>,
}

impl<STREAM: AsyncRead + AsyncWrite + Unpin> Connection<STREAM, Unauthenticated> {
    pub async fn new(stream: STREAM) -> Self {
        let stream = BufReader::new(stream);

        let (stream, res) = next_response(response_capability, stream).await;
        dbg!(res);

        Self {
            stream,
            _p: PhantomData,
        }
    }
}

impl<STREAM: AsyncRead + AsyncWrite + Unpin, MODE: Mode> Connection<STREAM, MODE> {
    pub async fn capabilities(&mut self) -> Result<Vec<u8>, ()> {
        let command = crate::internal::command::Command::capability().to_string();
        // self.stream.write_all(command.as_bytes()).await?;
        // let mut buf = vec![];
        // let res = self.inner.read_to_end(&mut buf).await?;
        Ok(vec![])
    }
}

fn next_response<T: AsyncRead + AsyncWrite + Unpin, RES>(
    f: impl Fn(&str) -> Option<RES>,
    stream: T,
) -> impl Future<Output = (T, RES)> {
    let mut buf = String::new();
    let mut stream = Some(stream);
    std::future::poll_fn(move |cx| loop {
        let mut temp = [0u8; 1024];
        let read_count =
            ready!(Pin::new(stream.as_mut().unwrap()).poll_read(cx, &mut temp)).unwrap();
        buf.push_str(str::from_utf8(&temp[0..read_count]).unwrap());

        if let Some(res) = f(&buf) {
            return Poll::Ready((stream.take().unwrap(), res));
        }
    })
}
