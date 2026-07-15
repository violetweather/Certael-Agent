use anyhow::{bail, Context, Result};
use certael_agent_platform::{inspect_executable, validate_game_path};
use certael_agent_protocol::{AgentHelloV1, PROTOCOL_VERSION};
use certael_agent_updater::{
    activate_pending, read_activation_state, recover, register_existing_version, rollback,
    verify_stage_and_install, verify_stage_and_install_automatic, InstallConfig, UpdateConfig,
};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use std::path::PathBuf;
#[cfg(unix)]
use std::process::{Command, Stdio};

mod hardening;
mod registry;
mod runtime;
mod status;
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
#[allow(clippy::large_enum_variant)]
enum Commands {
    Inspect {
        #[arg(long)]
        game: PathBuf,
    },
    ValidateTrustStore {
        #[arg(long)]
        trust_store: PathBuf,
    },
    Launch {
        #[arg(long)]
        game: PathBuf,
        #[arg(long)]
        trust_store: PathBuf,
        #[arg(last = true)]
        args: Vec<String>,
    },
    RegisterGame {
        #[arg(long)]
        registration: PathBuf,
        #[arg(long)]
        publisher_trust_store: PathBuf,
        #[arg(long)]
        update_root: PathBuf,
        #[arg(long)]
        game_root: PathBuf,
        #[arg(long)]
        registry_root: Option<PathBuf>,
    },
    UpdateGameRegistration {
        #[arg(long)]
        registration: PathBuf,
        #[arg(long)]
        publisher_trust_store: PathBuf,
        #[arg(long)]
        update_root: PathBuf,
        #[arg(long)]
        game_root: PathBuf,
        #[arg(long)]
        registry_root: Option<PathBuf>,
    },
    ListGames {
        #[arg(long)]
        registry_root: Option<PathBuf>,
    },
    LaunchGame {
        #[arg(long)]
        registration_id: String,
        #[arg(long)]
        registry_root: Option<PathBuf>,
        #[arg(last = true)]
        args: Vec<String>,
    },
    UpdateRegisteredGame {
        #[arg(long)]
        registration_id: String,
        #[arg(long)]
        registry_root: Option<PathBuf>,
        #[arg(long)]
        install_root: Option<PathBuf>,
        #[arg(long)]
        activate: bool,
    },
    Update {
        #[arg(long)]
        trusted_root: PathBuf,
        #[arg(long)]
        metadata_url: String,
        #[arg(long)]
        targets_url: String,
        #[arg(long)]
        datastore: PathBuf,
        #[arg(long)]
        staging: PathBuf,
        #[arg(long)]
        install_root: PathBuf,
        #[arg(long)]
        version: String,
        #[arg(long)]
        target_name: String,
        #[arg(long, default_value = platform_agent_name())]
        installed_name: String,
    },
    ActivateUpdate {
        #[arg(long)]
        install_root: PathBuf,
    },
    RollbackUpdate {
        #[arg(long)]
        install_root: PathBuf,
    },
    RecoverUpdate {
        #[arg(long)]
        install_root: PathBuf,
    },
    UpdateStatus {
        #[arg(long)]
        install_root: PathBuf,
    },
    #[command(hide = true)]
    RegisterInstalledVersion {
        #[arg(long)]
        install_root: PathBuf,
        #[arg(long)]
        version: String,
        #[arg(long, default_value = platform_agent_name())]
        installed_name: String,
        #[arg(long)]
        activate: bool,
    },
}

fn main() -> Result<()> {
    hardening::apply()?;
    match Cli::parse().command {
        Some(Commands::Inspect { game }) => println!(
            "{}",
            serde_json::to_string_pretty(&inspect_executable(&game)?)?
        ),
        Some(Commands::ValidateTrustStore { trust_store }) => {
            trust::load(&trust_store)?;
            println!("Agent trust store is valid");
        }
        Some(Commands::Launch {
            game,
            trust_store,
            args,
        }) => launch(game, trust_store, args)?,
        Some(Commands::RegisterGame {
            registration,
            publisher_trust_store,
            update_root,
            game_root,
            registry_root,
        }) => {
            let claims = registry::register(
                &registry_root.unwrap_or_else(registry::default_root),
                &registration,
                &publisher_trust_store,
                &update_root,
                &game_root,
            )?;
            println!("registered {} ({})", claims.game_id, claims.registration_id);
        }
        Some(Commands::UpdateGameRegistration {
            registration,
            publisher_trust_store,
            update_root,
            game_root,
            registry_root,
        }) => {
            let claims = registry::update(
                &registry_root.unwrap_or_else(registry::default_root),
                &registration,
                &publisher_trust_store,
                &update_root,
                &game_root,
            )?;
            println!("updated {} ({})", claims.game_id, claims.registration_id);
        }
        Some(Commands::ListGames { registry_root }) => {
            for game in registry::list(&registry_root.unwrap_or_else(registry::default_root))? {
                println!("{game}");
            }
        }
        Some(Commands::LaunchGame {
            registration_id,
            registry_root,
            args,
        }) => {
            let registered = registry::load(
                &registry_root.unwrap_or_else(registry::default_root),
                &registration_id,
            )?;
            launch_registered(registered, args)?;
        }
        Some(Commands::UpdateRegisteredGame {
            registration_id,
            registry_root,
            install_root,
            activate,
        }) => {
            let registered = registry::load(
                &registry_root.unwrap_or_else(registry::default_root),
                &registration_id,
            )?;
            let install_root = install_root.unwrap_or_else(default_install_root);
            let update_state = registered.state_root.join("update");
            let target_name = format!(
                "certael-agent/{}/{}",
                registered.claims.update_channel,
                target_platform()
            );
            let runtime = tokio::runtime::Runtime::new()?;
            let installed = runtime.block_on(verify_stage_and_install_automatic(
                &UpdateConfig {
                    trusted_root: registered.update_root,
                    metadata_base_url: url::Url::parse(&registered.claims.update_metadata_url)?,
                    targets_base_url: url::Url::parse(&registered.claims.update_targets_url)?,
                    datastore: update_state.join("metadata"),
                    staging_directory: update_state.join("staging"),
                    target_name,
                },
                &install_root,
                platform_agent_name(),
                &registered.claims.update_channel,
                target_platform(),
            ))?;
            if activate {
                activate_pending(&install_root)?;
            }
            println!("verified Agent update staged at {}", installed.display());
        }
        Some(Commands::Update {
            trusted_root,
            metadata_url,
            targets_url,
            datastore,
            staging,
            install_root,
            version,
            target_name,
            installed_name,
        }) => {
            let runtime = tokio::runtime::Runtime::new()?;
            let installed = runtime.block_on(verify_stage_and_install(
                &UpdateConfig {
                    trusted_root,
                    metadata_base_url: url::Url::parse(&metadata_url)
                        .context("invalid metadata URL")?,
                    targets_base_url: url::Url::parse(&targets_url)
                        .context("invalid targets URL")?,
                    datastore,
                    staging_directory: staging,
                    target_name,
                },
                &InstallConfig {
                    install_root,
                    version,
                    installed_name,
                },
            ))?;
            println!("verified update staged at {}", installed.display());
        }
        Some(Commands::ActivateUpdate { install_root }) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&activate_pending(&install_root)?)?
            );
        }
        Some(Commands::RollbackUpdate { install_root }) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&rollback(&install_root)?)?
            );
        }
        Some(Commands::RecoverUpdate { install_root }) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&recover(&install_root)?)?
            );
        }
        Some(Commands::UpdateStatus { install_root }) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&read_activation_state(&install_root)?)?
            );
        }
        Some(Commands::RegisterInstalledVersion {
            install_root,
            version,
            installed_name,
            activate,
        }) => {
            register_existing_version(&install_root, &version, &installed_name, activate)?;
        }
        None => ui::run()?,
    }
    Ok(())
}

const fn platform_agent_name() -> &'static str {
    if cfg!(windows) {
        "certael-agent.exe"
    } else {
        "certael-agent"
    }
}

const fn target_platform() -> &'static str {
    if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        "x86_64-pc-windows-msvc"
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "x86_64-unknown-linux-gnu"
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "aarch64-apple-darwin"
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        "x86_64-apple-darwin"
    } else {
        "unsupported"
    }
}

fn default_install_root() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var_os("ProgramFiles")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"))
            .join("Certael")
    }
    #[cfg(not(windows))]
    PathBuf::from("/usr/local/lib/certael-agent")
}

fn launch(game: PathBuf, trust_store: PathBuf, args: Vec<String>) -> Result<()> {
    launch_with_registration(game, trust_store, args, None)
}

fn launch_registered(registered: registry::RegisteredGame, args: Vec<String>) -> Result<()> {
    let binding = runtime::RegistrationBinding {
        registration_id: registered.claims.registration_id.clone(),
        tenant_id: registered.claims.tenant_id,
        game_id: registered.claims.game_id,
        environment_id: registered.claims.environment_id,
        status_path: registered.status_path,
    };
    launch_with_root(
        registered.game,
        registered.game_root,
        registered.trust_store,
        args,
        Some(binding),
    )
}

fn launch_with_registration(
    game: PathBuf,
    trust_store: PathBuf,
    args: Vec<String>,
    registration: Option<runtime::RegistrationBinding>,
) -> Result<()> {
    let game = validate_game_path(&game)?;
    let game_root = game
        .parent()
        .context("game has no installation root")?
        .to_path_buf();
    launch_with_root(game, game_root, trust_store, args, registration)
}

fn launch_with_root(
    game: PathBuf,
    game_root: PathBuf,
    trust_store: PathBuf,
    args: Vec<String>,
    registration: Option<runtime::RegistrationBinding>,
) -> Result<()> {
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
        game_root,
        game_process_id: 0,
        game_process_identity: None,
        key,
        hello,
        registration,
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
    state.game_process_identity = certael_agent_platform::process_identity(child.id());
    unsafe {
        libc::close(child_fd);
    }
    let channel = unsafe { std::fs::File::from_raw_fd(fds[0]) };
    let mut writer = channel
        .try_clone()
        .context("failed to clone private Agent channel")?;
    runtime::serve(channel, &mut writer, &state)?;
    drop(writer);
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

#[cfg(test)]
mod tests {
    use super::*;
    use certael_agent_ipc::IPC_VERSION;
    use certael_agent_probe::CERTAEL_PROBE_ABI_VERSION;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct CompatibilityManifest {
        schema_version: u32,
        product: String,
        product_version: String,
        agent_protocol_version: u32,
        local_ipc_version: u8,
        probe_abi_version: u32,
        compatible_core_agent_protocol_versions: Vec<u32>,
        supported_player_targets: Vec<String>,
    }

    #[test]
    fn release_compatibility_manifest_matches_the_implementation() {
        let manifest: CompatibilityManifest = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../release/compatibility-v1.json"
        )))
        .expect("compatibility-v1.json must be valid JSON");

        assert_eq!(manifest.schema_version, 1);
        assert_eq!(manifest.product, "certael-agent");
        assert_eq!(manifest.product_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(manifest.agent_protocol_version, PROTOCOL_VERSION);
        assert_eq!(manifest.local_ipc_version, IPC_VERSION);
        assert_eq!(manifest.probe_abi_version, CERTAEL_PROBE_ABI_VERSION);
        assert!(manifest
            .compatible_core_agent_protocol_versions
            .contains(&PROTOCOL_VERSION));
        assert_eq!(
            manifest.supported_player_targets,
            [
                "x86_64-pc-windows-msvc",
                "x86_64-unknown-linux-gnu",
                "aarch64-apple-darwin",
                "x86_64-apple-darwin",
            ]
        );
    }
}
