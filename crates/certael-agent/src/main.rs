use anyhow::{bail, Context, Result};
use certael_agent_platform::{
    inspect_executable, validate_game_path, verify_build_manifest, ProtectedBuildFile,
    ProtectedBuildManifest,
};
use certael_agent_protocol::{
    evaluate_compatibility, verify_compatibility_manifest, AgentHelloV1, CertaelProductV1,
    SignedCompatibilityManifestV1, PROTOCOL_VERSION,
};
use certael_agent_updater::{
    activate_pending, active_target, read_activation_state, recover, register_existing_version,
    rollback, verify_stage_and_install, verify_stage_and_install_automatic, InstallConfig,
    UpdateConfig,
};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use prost::Message;
use rand_core::OsRng;
use std::path::PathBuf;
use std::process::{Command, Stdio};

mod branding;
mod hardening;
mod registry;
mod runtime;
mod status;
mod trust;
mod ui;
#[cfg(any(windows, test))]
mod windows_environment;
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
    CompatibilityCheck {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        trust_store: PathBuf,
        #[arg(long)]
        product: String,
        #[arg(long)]
        version: String,
        #[arg(long)]
        protocol: u32,
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
        #[arg(long, requires = "branding_root")]
        branding_manifest: Option<PathBuf>,
        #[arg(long, requires = "branding_manifest")]
        branding_root: Option<PathBuf>,
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
        #[arg(long, requires = "branding_root")]
        branding_manifest: Option<PathBuf>,
        #[arg(long, requires = "branding_manifest")]
        branding_root: Option<PathBuf>,
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
    #[command(hide = true)]
    LaunchSplash {
        #[arg(long)]
        registration_id: String,
        #[arg(long)]
        launch_attempt_id: String,
        #[arg(long)]
        registry_root: Option<PathBuf>,
    },
    #[command(hide = true)]
    RepairGame {
        #[arg(long)]
        registration_id: String,
        #[arg(long)]
        registry_root: Option<PathBuf>,
    },
    #[command(hide = true)]
    LaunchOfflineGame {
        #[arg(long)]
        registration_id: String,
        #[arg(long)]
        registry_root: Option<PathBuf>,
    },
    #[cfg(debug_assertions)]
    #[command(hide = true)]
    PreviewLaunchSplash {
        #[arg(long)]
        hero: PathBuf,
        #[arg(long)]
        icon: PathBuf,
        #[arg(long, default_value = "awaiting_server_admission")]
        state: String,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long)]
        screenshot: PathBuf,
        #[arg(long, default_value_t = 1040.0)]
        width: f32,
        #[arg(long, default_value_t = 800.0)]
        height: f32,
        #[arg(long, default_value_t = 1.0)]
        zoom: f32,
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
        Some(Commands::CompatibilityCheck {
            manifest,
            trust_store,
            product,
            version,
            protocol,
        }) => {
            let bytes = std::fs::read(manifest)?;
            let signed = SignedCompatibilityManifestV1::decode(bytes.as_slice())
                .context("signed compatibility manifest is malformed")?;
            if signed.encode_to_vec() != bytes {
                bail!("signed compatibility manifest is not canonical");
            }
            let claims =
                verify_compatibility_manifest(&signed, &trust::load(&trust_store)?, now_unix()?)?;
            let product = parse_product(&product)?;
            let decision =
                evaluate_compatibility(Some(&claims), product, &version, protocol, now_unix()?);
            println!(
                "state={:?} reason={} recommended={} revision={}",
                decision.state,
                decision.public_reason,
                decision.recommended_version.as_deref().unwrap_or("none"),
                decision.manifest_revision
            );
            if !decision.allows_new_protected_session() {
                bail!("this Certael component cannot start a new protected session");
            }
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
            branding_manifest,
            branding_root,
        }) => {
            let claims = registry::register(
                &registry_root.unwrap_or_else(registry::default_root),
                &registration,
                &publisher_trust_store,
                &update_root,
                &game_root,
                branding_manifest.as_deref(),
                branding_root.as_deref(),
            )?;
            println!("registered {} ({})", claims.game_id, claims.registration_id);
        }
        Some(Commands::UpdateGameRegistration {
            registration,
            publisher_trust_store,
            update_root,
            game_root,
            registry_root,
            branding_manifest,
            branding_root,
        }) => {
            let claims = registry::update(
                &registry_root.unwrap_or_else(registry::default_root),
                &registration,
                &publisher_trust_store,
                &update_root,
                &game_root,
                branding_manifest.as_deref(),
                branding_root.as_deref(),
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
            let registry_root = registry_root.unwrap_or_else(registry::default_root);
            let registered = registry::load(&registry_root, &registration_id)?;
            let launch_attempt_id = uuid::Uuid::new_v4().to_string();
            spawn_launch_splash(&registration_id, &launch_attempt_id, &registry_root)?;
            launch_registered(registered, args, launch_attempt_id)?;
        }
        Some(Commands::LaunchSplash {
            registration_id,
            launch_attempt_id,
            registry_root,
        }) => {
            let registered = registry::load(
                &registry_root.unwrap_or_else(registry::default_root),
                &registration_id,
            )?;
            ui::run_splash(registered, launch_attempt_id)?;
        }
        Some(Commands::RepairGame {
            registration_id,
            registry_root,
        }) => {
            let registered = registry::load(
                &registry_root.unwrap_or_else(registry::default_root),
                &registration_id,
            )?;
            run_registered_repair(&registered)?;
        }
        Some(Commands::LaunchOfflineGame {
            registration_id,
            registry_root,
        }) => {
            let registered = registry::load(
                &registry_root.unwrap_or_else(registry::default_root),
                &registration_id,
            )?;
            launch_registered_offline(&registered)?;
        }
        #[cfg(debug_assertions)]
        Some(Commands::PreviewLaunchSplash {
            hero,
            icon,
            state,
            reason,
            screenshot,
            width,
            height,
            zoom,
        }) => preview_launch_splash(SplashPreviewArgs {
            hero,
            icon,
            state,
            reason,
            screenshot,
            width,
            height,
            zoom,
        })?,
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

fn parse_product(value: &str) -> Result<CertaelProductV1> {
    match value.to_ascii_lowercase().as_str() {
        "core" => Ok(CertaelProductV1::Core),
        "agent" => Ok(CertaelProductV1::Agent),
        "godot" | "godot-adapter" => Ok(CertaelProductV1::GodotAdapter),
        "unity" | "unity-adapter" => Ok(CertaelProductV1::UnityAdapter),
        "unreal" | "unreal-adapter" => Ok(CertaelProductV1::UnrealAdapter),
        "dotnet-server-sdk" => Ok(CertaelProductV1::DotNetServerSdk),
        "native-server-sdk" => Ok(CertaelProductV1::NativeServerSdk),
        _ => bail!("unknown Certael product"),
    }
}

fn now_unix() -> Result<i64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs()
        .try_into()?)
}

#[cfg(debug_assertions)]
struct SplashPreviewArgs {
    hero: PathBuf,
    icon: PathBuf,
    state: String,
    reason: Option<String>,
    screenshot: PathBuf,
    width: f32,
    height: f32,
    zoom: f32,
}

#[cfg(debug_assertions)]
fn preview_launch_splash(args: SplashPreviewArgs) -> Result<()> {
    let SplashPreviewArgs {
        hero,
        icon,
        state,
        reason,
        screenshot,
        width,
        height,
        zoom,
    } = args;
    if !(720.0..=3840.0).contains(&width)
        || !(560.0..=2160.0).contains(&height)
        || !(1.0..=2.0).contains(&zoom)
    {
        bail!("preview viewport or zoom is outside the supported QA range");
    }
    branding::decode_icon_rgba(&icon)?;
    branding::decode_hero_rgba(&hero)?;
    let preview_root =
        std::env::temp_dir().join(format!("certael-splash-preview-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&preview_root)?;
    let status_path = preview_root.join("preview-status.json");
    status::publish(
        &status_path,
        &status::RuntimeStatus {
            format_version: 2,
            registration_id: "preview-production".into(),
            game_id: "hollowstar".into(),
            state,
            public_reason: reason,
            updated_at_unix: now_unix()?,
            launch_attempt_id: Some("preview-attempt".into()),
            milestone_index: Some(6),
            milestone_total: Some(8),
        },
    )?;
    let executable = std::env::current_exe()?;
    let game_root = executable
        .parent()
        .context("preview executable has no parent")?
        .to_path_buf();
    let result = ui::run_splash_preview(
        registry::RegisteredGame {
            claims: certael_agent_protocol::GameRegistrationClaimsV1 {
                protocol_version: PROTOCOL_VERSION,
                registration_id: "preview-production".into(),
                publisher_id: "northline-games".into(),
                tenant_id: "preview".into(),
                game_id: "hollowstar".into(),
                environment_id: "preview".into(),
                executable_relative_path: "preview-game".into(),
                trust_store_sha256: vec![0; 32],
                update_root_sha256: vec![0; 32],
                update_metadata_url: "https://updates.example/metadata/".into(),
                update_targets_url: "https://updates.example/targets/".into(),
                update_channel: "stable".into(),
                not_before_unix: 1,
                expires_at_unix: i64::MAX,
                registered_files: vec![],
                repair_executable_relative_path: "repair.exe".into(),
                repair_arguments: vec![],
                offline_play_allowed: true,
                offline_arguments: vec![],
            },
            game: executable.clone(),
            game_root,
            trust_store: executable.clone(),
            update_root: executable,
            state_root: preview_root.clone(),
            status_path,
            branding: Some(branding::VerifiedBranding {
                claims: certael_agent_protocol::BrandingManifestClaimsV1 {
                    protocol_version: PROTOCOL_VERSION,
                    registration_id: "preview-production".into(),
                    game_id: "hollowstar".into(),
                    display_name: "Hollowstar".into(),
                    publisher_name: "Northline Games".into(),
                    icon_relative_path: "icon.png".into(),
                    icon_sha256: vec![0; 32],
                    not_before_unix: 1,
                    expires_at_unix: i64::MAX,
                    hero_relative_path: "hero.png".into(),
                    hero_sha256: vec![0; 32],
                },
                icon: branding::VerifiedBrandingImage { path: icon },
                hero: Some(branding::VerifiedBrandingImage { path: hero }),
            }),
        },
        "preview-attempt".into(),
        screenshot,
        [width, height],
        zoom,
    );
    let _ = std::fs::remove_dir_all(preview_root);
    result
}

fn launch(game: PathBuf, trust_store: PathBuf, args: Vec<String>) -> Result<()> {
    launch_with_registration(game, trust_store, args, None)
}

fn spawn_launch_splash(
    registration_id: &str,
    launch_attempt_id: &str,
    registry_root: &std::path::Path,
) -> Result<()> {
    let executable =
        std::env::current_exe().context("cannot locate the Certael Agent launch window")?;
    Command::new(executable)
        .arg("launch-splash")
        .arg("--registration-id")
        .arg(registration_id)
        .arg("--launch-attempt-id")
        .arg(launch_attempt_id)
        .arg("--registry-root")
        .arg(registry_root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to start the Certael Agent launch window")?;
    Ok(())
}

fn run_registered_repair(registered: &registry::RegisteredGame) -> Result<()> {
    if registered.claims.repair_executable_relative_path.is_empty() {
        bail!("this game did not register a repair action");
    }
    let repair = registered
        .game_root
        .join(&registered.claims.repair_executable_relative_path);
    verify_registered_file(
        registered,
        &registered.claims.repair_executable_relative_path,
    )?;
    Command::new(repair)
        .args(&registered.claims.repair_arguments)
        .stdin(Stdio::null())
        .spawn()
        .context("failed to start the registered game repair action")?;
    Ok(())
}

fn launch_registered_offline(registered: &registry::RegisteredGame) -> Result<()> {
    if !registered.claims.offline_play_allowed {
        bail!("this game does not allow offline launch from Certael Agent");
    }
    if registered.claims.registered_files.iter().any(|file| {
        file.relative_path
            .eq_ignore_ascii_case(&registered.claims.executable_relative_path)
    }) {
        verify_registered_file(registered, &registered.claims.executable_relative_path)?;
    } else {
        inspect_executable(&registered.game)
            .context("offline game executable could not be verified")?;
    }
    Command::new(&registered.game)
        .args(&registered.claims.offline_arguments)
        .env_remove("CERTAEL_AGENT_FD")
        .env_remove("CERTAEL_AGENT_READ_HANDLE")
        .env_remove("CERTAEL_AGENT_WRITE_HANDLE")
        .stdin(Stdio::null())
        .spawn()
        .context("failed to launch the registered offline game")?;
    Ok(())
}

fn verify_registered_file(
    registered: &registry::RegisteredGame,
    relative_path: &str,
) -> Result<()> {
    let file = registered
        .claims
        .registered_files
        .iter()
        .find(|file| file.relative_path.eq_ignore_ascii_case(relative_path))
        .context("registered recovery executable has no signed file binding")?;
    let manifest = ProtectedBuildManifest {
        build_id: format!("registration:{}", registered.claims.registration_id),
        files: vec![ProtectedBuildFile {
            path: file.relative_path.clone(),
            size: file.size,
            sha256: hex::encode(&file.sha256),
        }],
    };
    let mismatches = verify_build_manifest(&registered.game_root, &manifest)
        .context("registered recovery executable could not be verified")?;
    if !mismatches.is_empty() {
        bail!("registered recovery executable does not match its signed digest");
    }
    Ok(())
}

fn launch_registered(
    registered: registry::RegisteredGame,
    args: Vec<String>,
    launch_attempt_id: String,
) -> Result<()> {
    let update_state = registered
        .status_path
        .parent()
        .context("registered game has no user update-state directory")?
        .join("updates")
        .join(&registered.claims.registration_id);
    let binding = runtime::RegistrationBinding {
        registration_id: registered.claims.registration_id.clone(),
        tenant_id: registered.claims.tenant_id,
        game_id: registered.claims.game_id,
        environment_id: registered.claims.environment_id,
        status_path: registered.status_path,
        launch_attempt_id,
    };
    runtime::publish_binding(&binding, "verifying_agent_version", None);
    if let Err(error) = verify_selected_agent() {
        runtime::publish_binding(&binding, "launch_failed", Some("AGENT_VERSION_UNVERIFIED"));
        return Err(error);
    }
    runtime::publish_binding(&binding, "loading_signed_registration", None);
    runtime::publish_binding(&binding, "hashing_registered_game_files", None);
    if !registered.claims.registered_files.is_empty() {
        let manifest = ProtectedBuildManifest {
            build_id: format!("registration:{}", registered.claims.registration_id),
            files: registered
                .claims
                .registered_files
                .iter()
                .map(|file| ProtectedBuildFile {
                    path: file.relative_path.clone(),
                    size: file.size,
                    sha256: hex::encode(&file.sha256),
                })
                .collect(),
        };
        let mismatches = match verify_build_manifest(&registered.game_root, &manifest) {
            Ok(value) => value,
            Err(error) => {
                runtime::publish_binding(
                    &binding,
                    "launch_failed",
                    Some("REGISTERED_GAME_FILES_UNREADABLE"),
                );
                return Err(error).context("registered game files could not be hashed");
            }
        };
        if !mismatches.is_empty() {
            runtime::publish_binding(
                &binding,
                "launch_failed",
                Some("REGISTERED_GAME_FILES_MISMATCH"),
            );
            bail!("registered game files do not match their signed registration");
        }
    } else {
        inspect_executable(&registered.game)
            .context("registered game executable could not be hashed")?;
    }
    let update = runtime::AutomaticUpdateBinding {
        trusted_root: registered.update_root,
        metadata_url: registered.claims.update_metadata_url.clone(),
        targets_url: registered.claims.update_targets_url.clone(),
        state_root: update_state,
        install_root: default_install_root(),
        channel: registered.claims.update_channel.clone(),
        platform: target_platform().to_owned(),
        target_name: format!(
            "certael-agent/{}/{}",
            registered.claims.update_channel,
            target_platform()
        ),
        installed_name: platform_agent_name().to_owned(),
    };
    let failure_binding = binding.clone();
    let result = launch_with_root(
        registered.game,
        registered.game_root,
        registered.trust_store,
        args,
        Some(binding),
        Some(update),
    );
    if result.is_err() {
        let already_published = crate::status::read(&failure_binding.status_path)
            .ok()
            .is_some_and(|status| {
                status.launch_attempt_id.as_deref()
                    == Some(failure_binding.launch_attempt_id.as_str())
                    && matches!(
                        status.state.as_str(),
                        "launch_failed" | "update_failed" | "update_ready"
                    )
            });
        if !already_published {
            runtime::publish_binding(
                &failure_binding,
                "launch_failed",
                Some("PROTECTED_LAUNCH_FAILED"),
            );
        }
    }
    result
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
    launch_with_root(game, game_root, trust_store, args, registration, None)
}

fn launch_with_root(
    game: PathBuf,
    game_root: PathBuf,
    trust_store: PathBuf,
    args: Vec<String>,
    registration: Option<runtime::RegistrationBinding>,
    automatic_update: Option<runtime::AutomaticUpdateBinding>,
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
        automatic_update,
    };
    runtime::publish_runtime(&state, "starting_game", None);

    #[cfg(unix)]
    return launch_unix(game, args, state);
    #[cfg(not(unix))]
    {
        windows_launch::launch(game, args, state)
    }
}

fn verify_selected_agent() -> Result<()> {
    let selected_agent = std::env::current_exe()
        .context("cannot locate selected Certael Agent version")?
        .canonicalize()
        .context("cannot resolve selected Certael Agent version")?;
    if !selected_agent.is_file() {
        bail!("selected Certael Agent version is unavailable");
    }
    let launcher_verified = std::env::var("CERTAEL_AGENT_LAUNCHER_VERIFIED").as_deref() == Ok("1")
        && std::env::var("CERTAEL_AGENT_SELECTED_VERSION").as_deref()
            == Ok(env!("CARGO_PKG_VERSION"))
        && std::env::var_os("CERTAEL_AGENT_SELECTED_TARGET")
            .and_then(|path| PathBuf::from(path).canonicalize().ok())
            .as_ref()
            == Some(&selected_agent);
    if launcher_verified {
        return Ok(());
    }
    if active_target(&default_install_root())
        .ok()
        .and_then(|path| path.canonicalize().ok())
        .as_ref()
        == Some(&selected_agent)
    {
        return Ok(());
    }
    #[cfg(debug_assertions)]
    return Ok(());
    #[cfg(not(debug_assertions))]
    bail!("selected Certael Agent was not verified by the stable launcher");
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
    if let Err(error) = runtime::serve(channel, &mut writer, &state) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
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
