use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use tough::{ExpirationEnforcement, Limits, Prefix, RepositoryLoader, TargetName};
use url::Url;

const MAX_TRUSTED_ROOT_BYTES: u64 = 1024 * 1024;
const MAX_ACTIVATION_STATE_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone)]
pub struct UpdateConfig {
    pub trusted_root: PathBuf,
    pub metadata_base_url: Url,
    pub targets_base_url: Url,
    pub datastore: PathBuf,
    pub staging_directory: PathBuf,
    pub target_name: String,
}

#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("update configuration is invalid")]
    InvalidConfiguration,
    #[error("trusted root cannot be read")]
    TrustedRoot,
    #[error("TUF metadata or target verification failed")]
    Verification,
    #[error("update target is not present")]
    TargetMissing,
    #[error("update installation failed")]
    Installation,
    #[error("update activation state is invalid")]
    InvalidActivationState,
    #[error("no valid update is pending")]
    NoPendingUpdate,
    #[error("no valid previous update is available")]
    NoRollback,
}

#[derive(Debug, Clone)]
pub struct InstallConfig {
    pub install_root: PathBuf,
    pub version: String,
    pub installed_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedReleaseTarget {
    pub path: PathBuf,
    pub version: String,
    pub channel: String,
    pub platform: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActivationSlot {
    pub version: String,
    pub relative_path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActivationState {
    pub format_version: u32,
    pub active: Option<ActivationSlot>,
    pub previous: Option<ActivationSlot>,
    pub pending: Option<ActivationSlot>,
}

impl Default for ActivationState {
    fn default() -> Self {
        Self {
            format_version: 1,
            active: None,
            previous: None,
            pending: None,
        }
    }
}

/// Verifies TUF root rotation, timestamp/snapshot/targets signatures,
/// expiration, rollback state, target length, and target hashes before staging.
/// This function never replaces a running executable.
pub async fn verify_and_stage(config: &UpdateConfig) -> Result<PathBuf, UpdateError> {
    Ok(verify_and_stage_release(config).await?.path)
}

/// Stages a target and returns its signed release identity from TUF custom
/// metadata. Version, channel, and platform are never accepted from an
/// unsigned command-line value.
pub async fn verify_and_stage_release(
    config: &UpdateConfig,
) -> Result<VerifiedReleaseTarget, UpdateError> {
    validate(config)?;
    let metadata = tokio::fs::metadata(&config.trusted_root)
        .await
        .map_err(|_| UpdateError::TrustedRoot)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_TRUSTED_ROOT_BYTES {
        return Err(UpdateError::TrustedRoot);
    }
    let trusted_root = tokio::fs::read(&config.trusted_root)
        .await
        .map_err(|_| UpdateError::TrustedRoot)?;
    tokio::fs::create_dir_all(&config.datastore)
        .await
        .map_err(|_| UpdateError::InvalidConfiguration)?;
    tokio::fs::create_dir_all(&config.staging_directory)
        .await
        .map_err(|_| UpdateError::InvalidConfiguration)?;
    let limits = Limits {
        max_root_size: MAX_TRUSTED_ROOT_BYTES,
        max_timestamp_size: 1024 * 1024,
        max_snapshot_size: 1024 * 1024,
        max_targets_size: 4 * 1024 * 1024,
        max_root_updates: 64,
    };
    let repository = RepositoryLoader::new(
        &trusted_root,
        config.metadata_base_url.clone(),
        config.targets_base_url.clone(),
    )
    .datastore(config.datastore.clone())
    .limits(limits)
    .expiration_enforcement(ExpirationEnforcement::Safe)
    .load()
    .await
    .map_err(|_| UpdateError::Verification)?;
    let target =
        TargetName::new(&config.target_name).map_err(|_| UpdateError::InvalidConfiguration)?;
    let metadata = repository
        .all_targets()
        .find_map(|(candidate, metadata)| (candidate == &target).then_some(metadata))
        .ok_or(UpdateError::TargetMissing)?;
    let custom_string = |name: &str| {
        metadata
            .custom
            .get(name)
            .and_then(serde_json::Value::as_str)
            .filter(|value| safe_component(value))
            .map(str::to_owned)
            .ok_or(UpdateError::Verification)
    };
    let version = custom_string("version")?;
    let channel = custom_string("channel")?;
    let platform = custom_string("platform")?;
    repository
        .save_target(&target, &config.staging_directory, Prefix::None)
        .await
        .map_err(|_| UpdateError::Verification)?;
    Ok(VerifiedReleaseTarget {
        path: config.staging_directory.join(target.resolved()),
        version,
        channel,
        platform,
    })
}

pub async fn verify_stage_and_install_automatic(
    update: &UpdateConfig,
    install_root: &Path,
    installed_name: &str,
    expected_channel: &str,
    expected_platform: &str,
) -> Result<PathBuf, UpdateError> {
    let release = verify_and_stage_release(update).await?;
    if release.channel != expected_channel || release.platform != expected_platform {
        return Err(UpdateError::Verification);
    }
    let expected_sha256 = hash_file(&release.path)?;
    install_verified_target(
        &release.path,
        &InstallConfig {
            install_root: install_root.to_path_buf(),
            version: release.version,
            installed_name: installed_name.to_owned(),
        },
        &expected_sha256,
    )
}

/// Verifies a TUF target, copies it into an immutable version directory, and
/// records it as pending. The running executable is never overwritten.
pub async fn verify_stage_and_install(
    update: &UpdateConfig,
    install: &InstallConfig,
) -> Result<PathBuf, UpdateError> {
    let staged = verify_and_stage(update).await?;
    let expected_sha256 = hash_file(&staged)?;
    install_verified_target(&staged, install, &expected_sha256)
}

fn install_verified_target(
    staged_target: &Path,
    config: &InstallConfig,
    expected_sha256: &str,
) -> Result<PathBuf, UpdateError> {
    validate_install(config, expected_sha256)?;
    let staged_metadata =
        std::fs::symlink_metadata(staged_target).map_err(|_| UpdateError::Installation)?;
    if staged_metadata.file_type().is_symlink() || !staged_metadata.is_file() {
        return Err(UpdateError::Installation);
    }
    std::fs::create_dir_all(&config.install_root).map_err(|_| UpdateError::Installation)?;
    let root_metadata =
        std::fs::symlink_metadata(&config.install_root).map_err(|_| UpdateError::Installation)?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(UpdateError::Installation);
    }
    let root = config
        .install_root
        .canonicalize()
        .map_err(|_| UpdateError::Installation)?;
    let versions = root.join("versions");
    std::fs::create_dir_all(&versions).map_err(|_| UpdateError::Installation)?;
    let versions_metadata =
        std::fs::symlink_metadata(&versions).map_err(|_| UpdateError::Installation)?;
    if versions_metadata.file_type().is_symlink() || !versions_metadata.is_dir() {
        return Err(UpdateError::Installation);
    }
    let final_directory = versions.join(&config.version);
    let final_target = final_directory.join(&config.installed_name);
    let slot = ActivationSlot {
        version: config.version.clone(),
        relative_path: format!("versions/{}/{}", config.version, config.installed_name),
        sha256: expected_sha256.to_ascii_lowercase(),
    };

    if final_target.exists() {
        if hash_file(&final_target)? != slot.sha256 {
            return Err(UpdateError::Installation);
        }
    } else {
        let temporary = versions.join(format!(
            ".install-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| UpdateError::Installation)?
                .as_nanos()
        ));
        std::fs::create_dir(&temporary).map_err(|_| UpdateError::Installation)?;
        let temporary_target = temporary.join(&config.installed_name);
        let result =
            copy_and_verify(staged_target, &temporary_target, &slot.sha256).and_then(|_| {
                sync_directory(&temporary)?;
                std::fs::rename(&temporary, &final_directory)
                    .map_err(|_| UpdateError::Installation)?;
                sync_directory(&versions)
            });
        if result.is_err() {
            let _ = std::fs::remove_dir_all(&temporary);
        }
        result?;
    }

    verify_slot(&root, &slot)?;

    let mut state = read_activation_state(&root)?;
    state.pending = Some(slot);
    write_activation_state(&root, &state)?;
    Ok(final_target)
}

/// Makes the complete pending version active with one atomic state-file swap.
pub fn activate_pending(install_root: &Path) -> Result<ActivationState, UpdateError> {
    let root = canonical_install_root(install_root)?;
    let mut state = read_activation_state(&root)?;
    let pending = state.pending.clone().ok_or(UpdateError::NoPendingUpdate)?;
    verify_slot(&root, &pending)?;
    state.previous = state.active.take();
    state.active = Some(pending);
    state.pending = None;
    write_activation_state(&root, &state)?;
    Ok(state)
}

/// Atomically selects the previously active immutable version.
pub fn rollback(install_root: &Path) -> Result<ActivationState, UpdateError> {
    let root = canonical_install_root(install_root)?;
    let mut state = read_activation_state(&root)?;
    let previous = state.previous.clone().ok_or(UpdateError::NoRollback)?;
    verify_slot(&root, &previous)?;
    let active = state.active.replace(previous);
    state.previous = active;
    state.pending = None;
    write_activation_state(&root, &state)?;
    Ok(state)
}

/// Repairs an interrupted state transition without executing unverified bytes.
pub fn recover(install_root: &Path) -> Result<ActivationState, UpdateError> {
    let root = canonical_install_root(install_root)?;
    let mut state = read_activation_state(&root)?;
    if state
        .pending
        .as_ref()
        .is_some_and(|slot| verify_slot(&root, slot).is_err())
    {
        state.pending = None;
    }
    if state
        .active
        .as_ref()
        .is_some_and(|slot| verify_slot(&root, slot).is_err())
    {
        let previous = state
            .previous
            .clone()
            .ok_or(UpdateError::InvalidActivationState)?;
        verify_slot(&root, &previous)?;
        state.active = Some(previous);
        state.previous = None;
    } else if state
        .previous
        .as_ref()
        .is_some_and(|slot| verify_slot(&root, slot).is_err())
    {
        state.previous = None;
    }
    write_activation_state(&root, &state)?;
    Ok(state)
}

pub fn read_activation_state(install_root: &Path) -> Result<ActivationState, UpdateError> {
    let root = canonical_install_root(install_root)?;
    read_activation_state_canonical(&root)
}

/// Registers a version that was placed by a privileged offline installer.
/// Existing active state is preserved until `activate` is explicitly requested.
pub fn register_existing_version(
    install_root: &Path,
    version: &str,
    installed_name: &str,
    activate: bool,
) -> Result<ActivationState, UpdateError> {
    let root = canonical_install_root(install_root)?;
    if !safe_component(version) || !safe_component(installed_name) {
        return Err(UpdateError::InvalidConfiguration);
    }
    let relative_path = format!("versions/{version}/{installed_name}");
    let target = root.join(&relative_path);
    let slot = ActivationSlot {
        version: version.to_owned(),
        relative_path,
        sha256: hash_file(&target)?,
    };
    verify_slot(&root, &slot)?;
    let mut state = read_activation_state_canonical(&root)?;
    if state.active.is_none() {
        state.active = Some(slot);
    } else if state.active.as_ref() != Some(&slot) {
        state.pending = Some(slot);
        if activate {
            let pending = state.pending.take().ok_or(UpdateError::NoPendingUpdate)?;
            state.previous = state.active.replace(pending);
        }
    }
    write_activation_state(&root, &state)?;
    Ok(state)
}

/// Resolves and re-verifies the executable selected by the atomic activation
/// state. Launchers must call this on every start, never trust a stale path.
pub fn active_target(install_root: &Path) -> Result<PathBuf, UpdateError> {
    let root = canonical_install_root(install_root)?;
    let state = recover(&root)?;
    let active = state.active.ok_or(UpdateError::InvalidActivationState)?;
    verify_slot(&root, &active)?;
    let target = root.join(active.relative_path);
    target
        .canonicalize()
        .map_err(|_| UpdateError::InvalidActivationState)
}

fn read_activation_state_canonical(install_root: &Path) -> Result<ActivationState, UpdateError> {
    let path = install_root.join("activation.json");
    if !path.exists() {
        return Ok(ActivationState::default());
    }
    let metadata =
        std::fs::symlink_metadata(&path).map_err(|_| UpdateError::InvalidActivationState)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_ACTIVATION_STATE_BYTES
    {
        return Err(UpdateError::InvalidActivationState);
    }
    let bytes = std::fs::read(path).map_err(|_| UpdateError::InvalidActivationState)?;
    let state: ActivationState =
        serde_json::from_slice(&bytes).map_err(|_| UpdateError::InvalidActivationState)?;
    validate_state(&state)?;
    Ok(state)
}

fn write_activation_state(root: &Path, state: &ActivationState) -> Result<(), UpdateError> {
    validate_state(state)?;
    let bytes = serde_json::to_vec(state).map_err(|_| UpdateError::Installation)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_ACTIVATION_STATE_BYTES {
        return Err(UpdateError::Installation);
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| UpdateError::Installation)?
        .as_nanos();
    let temporary = root.join(format!(".activation-{}-{nonce}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|_| UpdateError::Installation)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|_| UpdateError::Installation)?;
    }
    let result = file
        .write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| UpdateError::Installation)
        .and_then(|_| atomic_replace(&temporary, &root.join("activation.json")))
        .and_then(|_| sync_directory(root));
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn copy_and_verify(source: &Path, destination: &Path, expected: &str) -> Result<(), UpdateError> {
    let mut source = File::open(source).map_err(|_| UpdateError::Installation)?;
    let mut destination = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|_| UpdateError::Installation)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = source
            .read(&mut buffer)
            .map_err(|_| UpdateError::Installation)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        destination
            .write_all(&buffer[..count])
            .map_err(|_| UpdateError::Installation)?;
    }
    if hex::encode(hasher.finalize()) != expected {
        return Err(UpdateError::Verification);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        destination
            .set_permissions(std::fs::Permissions::from_mode(0o755))
            .map_err(|_| UpdateError::Installation)?;
    }
    destination
        .sync_all()
        .map_err(|_| UpdateError::Installation)
}

fn hash_file(path: &Path) -> Result<String, UpdateError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| UpdateError::Verification)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(UpdateError::Verification);
    }
    let mut file = File::open(path).map_err(|_| UpdateError::Verification)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| UpdateError::Verification)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn verify_slot(root: &Path, slot: &ActivationSlot) -> Result<(), UpdateError> {
    validate_slot(slot)?;
    let target = root.join(&slot.relative_path);
    let canonical = target
        .canonicalize()
        .map_err(|_| UpdateError::Verification)?;
    if !canonical.starts_with(root) || hash_file(&canonical)? != slot.sha256 {
        return Err(UpdateError::Verification);
    }
    Ok(())
}

fn validate_install(config: &InstallConfig, expected_sha256: &str) -> Result<(), UpdateError> {
    if !absolute(&config.install_root)
        || !safe_component(&config.version)
        || !safe_component(&config.installed_name)
        || !valid_digest(expected_sha256)
    {
        return Err(UpdateError::InvalidConfiguration);
    }
    Ok(())
}

fn validate_state(state: &ActivationState) -> Result<(), UpdateError> {
    if state.format_version != 1 {
        return Err(UpdateError::InvalidActivationState);
    }
    for slot in [&state.active, &state.previous, &state.pending]
        .into_iter()
        .flatten()
    {
        validate_slot(slot)?;
    }
    Ok(())
}

fn validate_slot(slot: &ActivationSlot) -> Result<(), UpdateError> {
    let path = Path::new(&slot.relative_path);
    if !safe_component(&slot.version)
        || !valid_digest(&slot.sha256)
        || path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        || !slot
            .relative_path
            .starts_with(&format!("versions/{}/", slot.version))
    {
        return Err(UpdateError::InvalidActivationState);
    }
    Ok(())
}

fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && !windows_reserved_component(value)
        && value
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'.' | b'_' | b'-'))
}

fn windows_reserved_component(value: &str) -> bool {
    let stem = value
        .split('.')
        .next()
        .unwrap_or(value)
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|value| value.is_ascii_hexdigit())
}

fn canonical_install_root(path: &Path) -> Result<PathBuf, UpdateError> {
    if !absolute(path) {
        return Err(UpdateError::InvalidConfiguration);
    }
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| UpdateError::InvalidConfiguration)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(UpdateError::InvalidConfiguration);
    }
    path.canonicalize()
        .map_err(|_| UpdateError::InvalidConfiguration)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), UpdateError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| UpdateError::Installation)
}

#[cfg(windows)]
fn sync_directory(_path: &Path) -> Result<(), UpdateError> {
    Ok(())
}

#[cfg(unix)]
fn atomic_replace(source: &Path, destination: &Path) -> Result<(), UpdateError> {
    std::fs::rename(source, destination).map_err(|_| UpdateError::Installation)
}

#[cfg(windows)]
fn atomic_replace(source: &Path, destination: &Path) -> Result<(), UpdateError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(UpdateError::Installation);
    }
    Ok(())
}

fn validate(config: &UpdateConfig) -> Result<(), UpdateError> {
    if config.metadata_base_url.scheme() != "https"
        || config.targets_base_url.scheme() != "https"
        || config.metadata_base_url.host_str().is_none()
        || config.targets_base_url.host_str().is_none()
        || config.target_name.is_empty()
        || config.target_name.len() > 255
        || !absolute(&config.trusted_root)
        || !absolute(&config.datastore)
        || !absolute(&config.staging_directory)
    {
        return Err(UpdateError::InvalidConfiguration);
    }
    Ok(())
}

fn absolute(path: &Path) -> bool {
    path.is_absolute() && !path.as_os_str().is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> UpdateConfig {
        UpdateConfig {
            trusted_root: std::env::temp_dir().join("root.json"),
            metadata_base_url: Url::parse("https://updates.example/metadata/").unwrap(),
            targets_base_url: Url::parse("https://updates.example/targets/").unwrap(),
            datastore: std::env::temp_dir().join("certael-tuf-state"),
            staging_directory: std::env::temp_dir().join("certael-stage"),
            target_name: "certael-agent.bin".into(),
        }
    }

    #[test]
    fn requires_https_and_absolute_state_paths() {
        assert!(validate(&config()).is_ok());
        let mut insecure = config();
        insecure.metadata_base_url = Url::parse("http://updates.example/metadata/").unwrap();
        assert!(matches!(
            validate(&insecure),
            Err(UpdateError::InvalidConfiguration)
        ));
        let mut relative = config();
        relative.datastore = "relative".into();
        assert!(matches!(
            validate(&relative),
            Err(UpdateError::InvalidConfiguration)
        ));
    }

    #[test]
    fn installs_activates_recovers_and_rolls_back_immutable_versions() {
        let root = std::env::temp_dir().join(format!(
            "certael-update-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let staged_one = root.join("staged-one");
        std::fs::write(&staged_one, b"version-one").unwrap();
        let one_digest = hex::encode(Sha256::digest(b"version-one"));
        let one = InstallConfig {
            install_root: root.clone(),
            version: "1.0.0".into(),
            installed_name: "certael-agent".into(),
        };
        let installed_one = install_verified_target(&staged_one, &one, &one_digest).unwrap();
        assert_eq!(std::fs::read(&installed_one).unwrap(), b"version-one");
        let state = activate_pending(&root).unwrap();
        assert_eq!(state.active.as_ref().unwrap().version, "1.0.0");

        let staged_two = root.join("staged-two");
        std::fs::write(&staged_two, b"version-two").unwrap();
        let two = InstallConfig {
            install_root: root.clone(),
            version: "1.1.0".into(),
            installed_name: "certael-agent".into(),
        };
        install_verified_target(
            &staged_two,
            &two,
            &hex::encode(Sha256::digest(b"version-two")),
        )
        .unwrap();
        let state = activate_pending(&root).unwrap();
        assert_eq!(state.active.as_ref().unwrap().version, "1.1.0");
        assert_eq!(state.previous.as_ref().unwrap().version, "1.0.0");
        let state = rollback(&root).unwrap();
        assert_eq!(state.active.as_ref().unwrap().version, "1.0.0");

        std::fs::write(root.join("versions/1.1.0/certael-agent"), b"tampered").unwrap();
        let state = recover(&root).unwrap();
        assert_eq!(state.active.as_ref().unwrap().version, "1.0.0");
        assert!(state.pending.is_none());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn registers_and_resolves_offline_installed_versions() {
        let root = std::env::temp_dir().join(format!(
            "certael-update-register-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("versions/1.0.0")).unwrap();
        std::fs::write(root.join("versions/1.0.0/certael-agent"), b"one").unwrap();
        let state = register_existing_version(&root, "1.0.0", "certael-agent", true).unwrap();
        assert_eq!(state.active.as_ref().unwrap().version, "1.0.0");
        assert_eq!(
            active_target(&root).unwrap(),
            root.join("versions/1.0.0/certael-agent")
                .canonicalize()
                .unwrap()
        );

        std::fs::create_dir_all(root.join("versions/1.1.0")).unwrap();
        std::fs::write(root.join("versions/1.1.0/certael-agent"), b"two").unwrap();
        let staged = register_existing_version(&root, "1.1.0", "certael-agent", false).unwrap();
        assert_eq!(staged.active.as_ref().unwrap().version, "1.0.0");
        assert_eq!(staged.pending.as_ref().unwrap().version, "1.1.0");
        assert_eq!(
            activate_pending(&root).unwrap().active.unwrap().version,
            "1.1.0"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_wrong_digest_and_unsafe_install_paths() {
        let root =
            std::env::temp_dir().join(format!("certael-update-invalid-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let staged = root.join("staged");
        std::fs::write(&staged, b"payload").unwrap();
        let invalid = InstallConfig {
            install_root: root.clone(),
            version: "../escape".into(),
            installed_name: "agent".into(),
        };
        assert!(matches!(
            install_verified_target(&staged, &invalid, &"00".repeat(32)),
            Err(UpdateError::InvalidConfiguration)
        ));
        let wrong = InstallConfig {
            version: "1.0.0".into(),
            ..invalid
        };
        assert!(matches!(
            install_verified_target(&staged, &wrong, &"00".repeat(32)),
            Err(UpdateError::Verification)
        ));
        std::fs::remove_dir_all(root).unwrap();
    }
}
