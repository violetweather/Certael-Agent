use anyhow::{bail, Context, Result};
use certael_agent_platform::{inspect_executable, validate_game_path};
use certael_agent_protocol::{AgentHelloV1, PROTOCOL_VERSION};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use std::path::PathBuf;
#[cfg(unix)]
use std::process::{Command, Stdio};

mod runtime;
mod trust;
mod ui;
#[cfg(windows)]
mod windows_launch;

#[derive(Parser)]
#[command(
    name = "certael-agent",
    about = "Certael user-mode integrity agent (pre-1.0)"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Inspect {
        #[arg(long)]
        game: PathBuf,
    },
    Launch {
        #[arg(long)]
        game: PathBuf,
        #[arg(long)]
        trust_store: PathBuf,
        #[arg(last = true)]
        args: Vec<String>,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Some(Commands::Inspect { game }) => println!(
            "{}",
            serde_json::to_string_pretty(&inspect_executable(&game)?)?
        ),
        Some(Commands::Launch {
            game,
            trust_store,
            args,
        }) => launch(game, trust_store, args)?,
        None => ui::run()?,
    }
    Ok(())
}

fn launch(game: PathBuf, trust_store: PathBuf, args: Vec<String>) -> Result<()> {
    let game = validate_game_path(&game)?;
    let snapshot = inspect_executable(&game)?;
    let key = SigningKey::generate(&mut OsRng);
    let hello = AgentHelloV1 {
        protocol_version: PROTOCOL_VERSION,
        agent_version: env!("CARGO_PKG_VERSION").into(),
        agent_public_key: key.verifying_key().as_bytes().to_vec(),
        build_id: snapshot.executable_sha256.clone(),
        executable_sha256: hex_to_32(&snapshot.executable_sha256)?,
    };
    let state = runtime::RuntimeState {
        trust: trust::load(&trust_store)?,
        game: game.clone(),
        game_process_id: 0,
        key,
        hello,
    };

    #[cfg(unix)]
    return launch_unix(game, args, state);
    #[cfg(not(unix))]
    {
        windows_launch::launch(game, args, state)
    }
}

#[cfg(unix)]
fn launch_unix(game: PathBuf, args: Vec<String>, mut state: runtime::RuntimeState) -> Result<()> {
    use std::os::fd::{FromRawFd, RawFd};
    let mut fds: [RawFd; 2] = [-1, -1];
    let result = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if result != 0 {
        bail!(
            "failed to create private Agent socketpair: {}",
            std::io::Error::last_os_error()
        );
    }
    // The game receives only its channel endpoint. Prevent the Agent endpoint
    // from surviving exec in the child and keeping the channel artificially open.
    if unsafe { libc::fcntl(fds[0], libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        bail!(
            "failed to secure private Agent socketpair: {}",
            std::io::Error::last_os_error()
        );
    }
    let child_fd = fds[1];
    let mut child = Command::new(game)
        .args(args)
        .env("CERTAEL_AGENT_FD", child_fd.to_string())
        .stdin(Stdio::null())
        .spawn()
        .context("failed to launch game")?;
    state.game_process_id = child.id();
    unsafe {
        libc::close(child_fd);
    }
    let mut channel = unsafe { std::fs::File::from_raw_fd(fds[0]) };
    let mut writer = channel
        .try_clone()
        .context("failed to clone private Agent channel")?;
    runtime::serve(&mut channel, &mut writer, &state)?;
    drop(writer);
    drop(channel);
    let status = child.wait()?;
    if !status.success() {
        bail!("game exited unsuccessfully: {status}");
    }
    Ok(())
}

fn hex_to_32(value: &str) -> Result<Vec<u8>> {
    if value.len() != 64 {
        bail!("invalid SHA-256 digest");
    }
    (0..32)
        .map(|index| {
            u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                .context("invalid SHA-256 digest")
        })
        .collect()
}
