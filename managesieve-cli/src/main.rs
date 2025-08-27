#![allow(unused)]

use std::convert::Infallible;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::pin::{Pin, pin};

use clap::{Args, Command, Parser, Subcommand, arg};
use color_eyre::eyre;
use color_eyre::eyre::{WrapErr, bail, eyre};
use managesieve::commands::{Authenticate};
use managesieve::sasl::{InitialSaslState, Sasl, SaslError, SaslState};
use managesieve::state::{Authenticated, Tls, TlsMode, Unauthenticated};
use managesieve::{AsyncRead, AsyncWrite, Connection, ServerName, SieveNameStr, SieveNameString};
use tokio::net::TcpStream;
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};
use tracing::{Level, debug, info};
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Arguments {
    /// Address of the sieve server
    #[arg(required = true)]
    address: String,

    #[arg(long, short, default_value_t = 4190)]
    port: u16,

    #[arg(long)]
    no_tls: bool,

    #[arg(long, short, required = false)]
    user: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command()]
    Info,

    #[command()]
    List,

    #[command()]
    Get {
        #[arg(required = true)]
        name: SieveNameString,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[tokio::main(flavor = "current_thread")]
pub async fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let args = Arguments::parse();

    let tcp = TcpStream::connect((args.address.as_str(), args.port))
        .await
        .context("failed to resolve address")?;
    let tcp = tcp.compat();

    let sieve = Connection::connect(tcp).await?;

    if args.no_tls {
        continue_tls(args.user, args.command, sieve).await?;
    } else {
        let server_name =
            ServerName::try_from(args.address).context("failed to parse server name")?;
        let sieve = sieve.start_tls(server_name).await?;
        continue_tls(args.user, args.command, sieve).await?;
    }

    async fn continue_tls<STREAM: AsyncWrite + AsyncRead + Unpin, TLS: TlsMode>(
        user: Option<String>,
        commands: Commands,
        sieve: Connection<STREAM, TLS, Unauthenticated>,
    ) -> eyre::Result<()> {
        if let Some(user) = user {
            let password = rpassword::prompt_password(format!("password for {user}:"))?;
            let init = format!("\0{}\0{}", user, password);
            let sasl = Sasl::new_init("PLAIN", init.as_bytes());
            let sasl = pin!(sasl);
            let sieve = match sieve.authenticate(sasl).await? {
                Authenticate::Ok { connection } => connection,
                Authenticate::Error { error, .. } => return Err(error.into()),
            };

            match commands {
                Commands::Info => println!("{:#?}", sieve.capabilities()),
                Commands::List => list_scripts(sieve).await?,
                Commands::Get { name, output } => {
                    get_script(sieve, &name, output.as_deref()).await?;
                }
            }
        } else {
            match commands {
                Commands::Info => println!("{:#?}", sieve.capabilities()),
                _ => bail!("command requires login information"),
            }
        }
        Ok(())
    }

    Ok(())
}

async fn list_scripts<STREAM: AsyncWrite + AsyncRead + Unpin, TLS: TlsMode>(
    sieve: Connection<STREAM, TLS, Authenticated>,
) -> eyre::Result<()> {
    let (_, scripts) = sieve.list_scripts().await?;
    println!("Scripts:");
    println!("active name");

    for (script, active) in scripts {
        if active {
            println!("   *   {script}");
        } else {
            println!("       {script}");
        }
    }

    Ok(())
}

async fn get_script<STREAM: AsyncWrite + AsyncRead + Unpin, TLS: TlsMode>(
    sieve: Connection<STREAM, TLS, Authenticated>,
    name: &SieveNameStr,
    output: Option<&Path>,
) -> eyre::Result<()> {
    let (_, script) = sieve.get_script(name).await?;

    if let Some(script) = script {
        if let Some(output) = output { 
            let mut file = File::create_new(output)?;
            file.write_all(script.as_bytes())?;
        } else {
            println!("{}", script);
        }
    } else {
        bail!("script `{name}` does not exist");
    }

    Ok(())
}

// let f: impl for<'a> Fn(&'a [u8]) -> CoroutineState<Vec<u8>, Result<Option<Vec<u8>>, SaslError>> =
//     |_input| return CoroutineState::Complete(Err(SaslError::UnexpectedServerResponse));

// let sasl = Sasl::new_fn("PLAIN", InitialSaslState::Complete(b""), |a| panic!());
// let c: impl for <'a> Coroutine<&'a [u8], Return=Result<Option<Vec<u8>>, SaslError>, Yield=Vec<u8>> =
//     #[coroutine] |a: &[u8]| {
//         panic!()
// } ;
// struct State {
//     count: u32,
// }
// let mut state = State { count: 0 };
// let init = format!("\0{}\0{}", args.username, args.password);
// let mut sasl = Sasl::new_init("PLAIN", init.as_bytes());
// let sasl = pin!(sasl);
// let sieve = match sieve.authenticate(sasl).await? {
//     Authenticate::Ok { connection } => connection,
//     Authenticate::Error { error, .. } => match error {
//         SaslError::UnexpectedOk => panic!(),
//         SaslError::UnexpectedServerResponse => panic!(),
//         SaslError::AuthTooWeak => panic!(),
//         SaslError::EncryptNeeded => panic!(),
//         SaslError::TransitionNeeded => panic!(),
//     },
//     // Authenticate::Error { error, .. } => panic!("{:?}", error),
// };

// info!("{:#?}", sieve.capabilities());
//
// let (sieve, scripts) = sieve.list_scripts().await?;
// info!("result={:#?}", scripts);

// let script = &scripts.first().unwrap().0;
// let (sieve, script) = sieve.get_script(SieveName::new(script)?).await?;
// let GetScript::Ok { script } = script else {
//     panic!()
// };
// info!("=== SCRIPT ===\n{}", script);

// let script_foo = ScriptName::new("foo")?;
// let (sieve, have_space) = sieve.have_space(script_foo, 1024 * 1024).await?;
// println!("{have_space:#?}");

// let res = sieve.have_space(script_foo, 2 * 1024 * 1024).await;
// let sieve = match res {
//     Ok((sieve, space)) => sieve,
//     Err(SieveError::Other(RecoverableError { source, connection: sieve })) => sieve,
//     Err(e) => return Err(e.into())
// };

// sieve.logout().await?;
