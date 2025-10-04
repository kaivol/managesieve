#![allow(unused)]

use std::convert::Infallible;
use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::pin::{Pin, pin};
use std::{mem, num};

use clap::{Args, Command, Parser, Subcommand, arg};
use color_eyre::eyre;
use color_eyre::eyre::{WrapErr, bail, eyre};
use managesieve::commands::{Authenticate, CheckScript, HaveSpace, PutScript};
use managesieve::sasl::{InitialSaslState, Sasl, SaslError, SaslFn, SaslState};
use managesieve::state::{Authenticated, Tls, TlsMode, Unauthenticated};
use managesieve::{
    AsyncRead, AsyncWrite, Connection, Quota, ServerName, SieveNameStr, SieveNameString,
};
use tokio::fs;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
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

    /// Sieve port
    #[arg(long, short, default_value_t = 4190)]
    port: u16,

    /// Don't use STARTLS
    #[arg(long, default_value_t = false)]
    no_tls: bool,

    /// Sieve user name
    #[arg(long, short, required = false)]
    user: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show information about the server
    #[command()]
    Info,

    /// List scripts the user has on the server
    #[command()]
    List,

    /// Gets the contents of the specified script
    #[command()]
    Get {
        /// Script name
        #[arg()]
        name: SieveNameString,
        /// Output to file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Verify Sieve script validity
    #[command()]
    Check {
        /// Script to validate
        #[arg()]
        path: PathBuf,
    },

    /// Submit a Sieve script to the server.
    #[command()]
    Put {
        /// Script name
        #[arg()]
        name: SieveNameString,
        /// Script to upload
        #[arg()]
        path: PathBuf,
        /// Overwrite the script
        #[arg(long, default_value_t = false)]
        overwrite: bool,
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
            let password = rpassword::prompt_password(format!("password for `{user}`:"))?;
            let init = format!("\0{}\0{}", user, password);
            let sasl = ("PLAIN", init.as_bytes());
            let sieve = match sieve.authenticate(sasl).await? {
                Authenticate::Ok { connection } => connection,
                Authenticate::Error { error, .. } => return Err(error.into()),
            };

            match commands {
                Commands::Info => println!("{:#?}", sieve.capabilities()),
                Commands::List => list_scripts(sieve).await?,
                Commands::Get { name, output } => {
                    get_script(sieve, name, output).await?;
                }
                Commands::Check { path } => check_script(sieve, path).await?,
                Commands::Put {
                    name,
                    path,
                    overwrite,
                } => put_script(sieve, name, path, overwrite).await?,
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
    mut sieve: Connection<STREAM, TLS, Authenticated>,
    name: SieveNameString,
    output: Option<PathBuf>,
) -> eyre::Result<()> {
    let (_, script) = sieve.get_script(&name).await?;

    if let Some(script) = script {
        if let Some(output) = output {
            let mut file = File::create_new(output).await?;
            file.write_all(script.as_bytes()).await?;
        } else {
            println!("{}", script);
        }
    } else {
        println!("Script `{name}` does not exist");
    }

    Ok(())
}

async fn check_script<STREAM: AsyncWrite + AsyncRead + Unpin, TLS: TlsMode>(
    mut sieve: Connection<STREAM, TLS, Authenticated>,
    input: PathBuf,
) -> eyre::Result<()> {
    let script = fs::read_to_string(input).await?;

    let (_, result) = sieve.check_script(&script).await?;

    match result {
        CheckScript::Ok { warnings } => {
            println!("Script is valid.");
            if let Some(warnings) = warnings {
                println!("\nWARNINGS:\n{warnings}");
            }
        }
        CheckScript::InvalidScript { error } => {
            println!("Script is invalid.");
            if let Some(error) = error {
                println!("\nERRORS:\n{error}");
            }
        }
    }

    Ok(())
}

async fn put_script<STREAM: AsyncWrite + AsyncRead + Unpin, TLS: TlsMode>(
    mut sieve: Connection<STREAM, TLS, Authenticated>,
    name: SieveNameString,
    input: PathBuf,
    overwrite: bool,
) -> eyre::Result<()> {
    fn handle_quota(quota: Quota, message: Option<String>) {
        print!("Cannot upload script.");
        match quota {
            Quota::MaxScripts => println!("Maximum number of scripts exceeded."),
            Quota::MaxSize => println!("Maximum script size exceeded."),
            Quota::Unspecified => println!("Site-defined quotas exceeded."),
        }
        if let Some(message) = message {
            println!("{message}");
        }
    }

    let script = fs::read_to_string(input).await?;

    if !overwrite {
        let (s, scripts) = sieve.list_scripts().await?;
        sieve = s;
        if scripts.into_iter().any(|(n, _)| name == n) {
            println!("Cannot upload script. Script `{name}` already exists");
            return Ok(());
        }
    }

    let (sieve, havespace) = sieve.have_space(&name, script.len().try_into()?).await?;
    if let HaveSpace::InsufficientQuota { quota, message } = havespace {
        handle_quota(quota, message);
        return Ok(());
    }

    let (sieve, result) = sieve.put_scripts(&name, &script).await?;
    match result {
        PutScript::Ok { warnings } => {
            println!("Successfully uploaded script.");
            if let Some(warnings) = warnings {
                println!("\nWARNINGS:\n{warnings}");
            }
        }
        PutScript::InvalidScript { error } => {
            println!("Could not upload script. Script is invalid.");
            if let Some(error) = error {
                println!("\nERRORS:\n{error}");
            }
        }
        PutScript::InsufficientQuota { quota, message } => {
            handle_quota(quota, message);
        }
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
