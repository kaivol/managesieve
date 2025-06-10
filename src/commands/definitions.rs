#![allow(unused)]

use std::future::Future;
use std::{io, str};

use futures::AsyncWriteExt;

use crate::{AsyncRead, AsyncWrite, SieveNameStr};

pub(crate) struct SieveWriter<'a, STREAM: AsyncRead + AsyncWrite + Unpin>(
    pub(crate) &'a mut STREAM,
);

impl<STREAM: AsyncRead + AsyncWrite + Unpin> SieveWriter<'_, STREAM> {
    fn literal<'a>(&'a mut self, s: &'a str) -> impl Future<Output = io::Result<()>> + 'a {
        self.0.write_all(s.as_bytes())
    }

    fn space(&mut self) -> impl Future<Output = io::Result<()>> + '_ {
        self.0.write_all(b" ")
    }

    fn crlf(&mut self) -> impl Future<Output = io::Result<()>> + '_ {
        self.0.write_all(b"\r\n")
    }

    async fn string(&mut self, string: impl AsRef<str>) -> io::Result<()> {
        let string = string.as_ref();

        self.0.write_all(b"{").await?;
        self.number(string.len().try_into().unwrap()).await?;
        self.0.write_all(b"}").await?;
        self.crlf().await?;
        self.0.write_all(string.as_bytes()).await?;

        Ok(())
    }

    async fn number(&mut self, number: u32) -> io::Result<()> {
        let mut buffer = itoa::Buffer::new();
        self.0.write_all(buffer.format(number).as_bytes()).await?;
        Ok(())
    }
}

pub(crate) trait Command<'a, STREAM: AsyncRead + AsyncWrite + Unpin>:
    AsyncFn(SieveWriter<STREAM>) -> io::Result<()> + 'a
{
}

impl<'a, STREAM: AsyncRead + AsyncWrite + Unpin, T: 'a> Command<'a, STREAM> for T where
    T: AsyncFn(SieveWriter<STREAM>) -> io::Result<()>
{
}

pub(crate) fn authenticate<'a, STREAM: AsyncRead + AsyncWrite + Unpin>(
    auth_type: &'a str,
    data: Option<&'a str>,
) -> impl Command<'a, STREAM> {
    async move |mut write: SieveWriter<STREAM>| {
        write.literal("AUTHENTICATE").await?;
        write.space().await?;
        write.string(auth_type).await?;
        if let Some(data) = data {
            write.space().await?;
            write.string(data).await?;
        }
        write.crlf().await?;
        Ok(())
    }
}

pub(crate) fn sasl_string<STREAM: AsyncRead + AsyncWrite + Unpin>(
    sasl: &str,
) -> impl Command<STREAM> {
    async move |mut write: SieveWriter<STREAM>| {
        write.string(sasl).await?;
        write.crlf().await?;
        Ok(())
    }
}

pub(crate) async fn start_tls<STREAM: AsyncRead + AsyncWrite + Unpin>(
    mut write: SieveWriter<'_, STREAM>,
) -> io::Result<()> {
    write.literal("STARTTLS").await?;
    write.crlf().await?;
    Ok(())
}

pub(crate) async fn logout<STREAM: AsyncRead + AsyncWrite + Unpin>(
    mut write: SieveWriter<'_, STREAM>,
) -> io::Result<()> {
    write.literal("LOGOUT").await?;
    write.crlf().await?;
    Ok(())
}

pub(crate) async fn capability<STREAM: AsyncRead + AsyncWrite + Unpin>(
    mut write: SieveWriter<'_, STREAM>,
) -> io::Result<()> {
    write.literal("CAPABILITY").await?;
    write.crlf().await?;
    Ok(())
}

pub(crate) fn have_space<STREAM: AsyncRead + AsyncWrite + Unpin>(
    name: &SieveNameStr,
    size: u32,
) -> impl Command<STREAM> {
    async move |mut write: SieveWriter<STREAM>| {
        write.literal("HAVESPACE").await?;
        write.space().await?;
        write.string(name).await?;
        write.space().await?;
        write.number(size).await?;
        write.crlf().await?;
        Ok(())
    }
}

pub(crate) fn put_script<'a, STREAM: AsyncRead + AsyncWrite + Unpin>(
    name: &'a SieveNameStr,
    script: &'a str,
) -> impl Command<'a, STREAM> {
    async move |mut write: SieveWriter<STREAM>| {
        write.literal("PUTSCRIPT").await?;
        write.space().await?;
        write.string(name).await?;
        write.space().await?;
        write.string(script).await?;
        write.crlf().await?;
        Ok(())
    }
}

pub(crate) async fn list_scripts<STREAM: AsyncRead + AsyncWrite + Unpin>(
    mut write: SieveWriter<'_, STREAM>,
) -> io::Result<()> {
    write.literal("LISTSCRIPTS").await?;
    write.crlf().await?;
    Ok(())
}

pub(crate) fn set_active<STREAM: AsyncRead + AsyncWrite + Unpin>(
    name: &SieveNameStr,
) -> impl Command<STREAM> {
    async move |mut write: SieveWriter<STREAM>| {
        write.literal("SETACTIVE").await?;
        write.space().await?;
        write.string(name).await?;
        write.crlf().await?;
        Ok(())
    }
}

pub(crate) fn get_script<STREAM: AsyncRead + AsyncWrite + Unpin>(
    name: &SieveNameStr,
) -> impl Command<STREAM> {
    async move |mut write: SieveWriter<STREAM>| {
        write.literal("GETSCRIPT").await?;
        write.space().await?;
        write.string(name).await?;
        write.crlf().await?;
        Ok(())
    }
}

pub(crate) fn delete_script<STREAM: AsyncRead + AsyncWrite + Unpin>(
    name: &SieveNameStr,
) -> impl Command<STREAM> {
    async move |mut write: SieveWriter<STREAM>| {
        write.literal("DELETESCRIPT").await?;
        write.space().await?;
        write.string(name).await?;
        write.crlf().await?;
        Ok(())
    }
}

pub(crate) fn rename_script<'a, STREAM: AsyncRead + AsyncWrite + Unpin>(
    old_name: &'a SieveNameStr,
    new_name: &'a SieveNameStr,
) -> impl Command<'a, STREAM> {
    async move |mut write: SieveWriter<STREAM>| {
        write.literal("RENAMESCRIPT").await?;
        write.space().await?;
        write.string(old_name).await?;
        write.space().await?;
        write.string(new_name).await?;
        write.crlf().await?;
        Ok(())
    }
}

pub(crate) fn check_script<STREAM: AsyncRead + AsyncWrite + Unpin>(
    script: &str,
) -> impl Command<STREAM> {
    async move |mut write: SieveWriter<STREAM>| {
        write.literal("CHECKSCRIPT").await?;
        write.space().await?;
        write.string(script).await?;
        write.crlf().await?;
        Ok(())
    }
}

pub(crate) async fn noop<STREAM: AsyncRead + AsyncWrite + Unpin>(
    mut write: SieveWriter<'_, STREAM>,
) -> io::Result<()> {
    write.literal("NOOP").await?;
    write.crlf().await?;
    Ok(())
}

pub(crate) async fn unauthenticate<STREAM: AsyncRead + AsyncWrite + Unpin>(
    mut write: SieveWriter<'_, STREAM>,
) -> io::Result<()> {
    write.literal("UNAUTHENTICATE").await?;
    write.crlf().await?;
    Ok(())
}
