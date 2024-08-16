#![allow(unused)]

use std::error::{Error};
use std::pin::{pin, Pin};
use std::task::{Context, Poll};

use clap::{arg, Parser};
use futures::{pin_mut, AsyncRead, AsyncWrite};
use futures_rustls::pki_types::ServerName;
use managesieve::commands::have_space::HaveSpaceError;
use managesieve::{Connection, SieveError, RecoverableError};
use tokio::net::TcpStream;
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};
use tracing::Level;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long, short)]
    address: String,

    #[arg(long, short, default_value_t = 4190)]
    port: u16,

    #[arg(long, env = "SIEVE_USERNAME")]
    username: String,

    #[arg(long, env = "SIEVE_PASSWORD")]
    password: String,
}

#[tokio::main]
pub async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    let args = Args::parse();

    let tcp = TcpStream::connect((args.address.as_str(), args.port)).await?;
    let tcp = tcp.compat();

    let sieve = Connection::connect(tcp).await?;

    let sieve = sieve.start_tls(ServerName::try_from(args.address)?).await?;

    let sieve = sieve.authenticate(args.username, args.password).await?;

    let (sieve, scripts) = sieve.list_scripts().await?;
    println!("result={:#?}", scripts);

    let (sieve, have_space) = sieve.have_space("foo", 1024 * 1024).await?;
    println!("{have_space:#?}");

    let res = sieve.have_space("foo", 2 * 1024 * 1024).await;
    let sieve = match res {
        Ok((sieve, space)) => sieve,
        Err(SieveError::Other(RecoverableError { source, connection: sieve })) => sieve,
        Err(e) => return Err(e.into())
    };

    sieve.logout().await?;

    Ok(())
}
