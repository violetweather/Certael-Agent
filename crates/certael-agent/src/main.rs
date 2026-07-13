use anyhow::{bail, Context, Result};
use certael_agent_platform::{inspect_executable, validate_game_path};
use certael_agent_protocol::{AgentHelloV1, PROTOCOL_VERSION};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use prost::Message;
use rand_core::OsRng;
use std::path::PathBuf;
#[cfg(unix)]
use std::process::{Command, Stdio};

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
        Some(Commands::Launch { game, args }) => launch(game, args)?,
        None => ui::run()?,
    }
    Ok(())
}

fn launch(game: PathBuf, args: Vec<String>) -> Result<()> {
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

    #[cfg(unix)]
    return launch_unix(game, args, hello.encode_to_vec());
    #[cfg(not(unix))]
    {
        windows_launch::launch(game, args, hello.encode_to_vec())
    }
}

#[cfg(unix)]
fn launch_unix(game: PathBuf, args: Vec<String>, hello: Vec<u8>) -> Result<()> {
    use certael_agent_ipc::{write_frame, Frame, MessageType};
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
    unsafe {
        libc::close(child_fd);
    }
    let mut channel = unsafe { std::fs::File::from_raw_fd(fds[0]) };
    write_frame(
        &mut channel,
        &Frame {
            message_type: MessageType::AgentHello,
            payload: hello,
        },
    )?;
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
