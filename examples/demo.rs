use clap::{arg, Parser};
use managesieve::Connection;
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncReadCompatExt;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
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

    let tcp = TcpStream::connect((args.address, args.port)).await?;
    let _sieve = Connection::new(tcp.compat()).await;

    // let caps = sieve.capabilities().await?;
    // println!("result={}", String::from_utf8_lossy(&caps));

    Ok(())
}
