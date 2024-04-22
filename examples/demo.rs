#![allow(unused)]

use std::pin::{pin, Pin};
use std::task::{Context, Poll};

use clap::{arg, Parser};
use futures::{pin_mut, AsyncRead, AsyncWrite};
use futures_rustls::pki_types::ServerName;
use managesieve::Connection;
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncReadCompatExt;

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
    let args = Args::parse();

    let tcp = TcpStream::connect((args.address.as_str(), args.port)).await?;
    let tcp = tcp.compat();
    let sieve = Connection::connect(tcp).await?;

    let sieve = sieve.start_tls(ServerName::try_from(args.address).unwrap()).await.unwrap();
    // sieve.logout().await.unwrap();
    // let caps = sieve.capabilities().await?;
    println!("result={sieve:#?}");

    Ok(())
}
