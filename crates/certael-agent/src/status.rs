use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeStatus {
    pub format_version: u32,
    pub registration_id: String,
    pub game_id: String,
    pub state: String,
    pub public_reason: Option<String>,
    pub updated_at_unix: i64,
}

pub fn path(registration_id: &str) -> Result<PathBuf> {
    if registration_id.is_empty()
        || registration_id.len() > 128
        || !registration_id
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'.' | b'_' | b'-'))
    {
        bail!("invalid status registration ID");
    }
    #[cfg(windows)]
    let root = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .context("LOCALAPPDATA is unavailable")?
        .join("Certael")
        .join("status");
    #[cfg(not(windows))]
    let root = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")))
        .context("user state directory is unavailable")?
        .join("certael-agent");
    Ok(root.join(format!("{registration_id}.json")))
}

pub fn publish(path: &Path, status: &RuntimeStatus) -> Result<()> {
    let parent = path.parent().context("status path has no parent")?;
    std::fs::create_dir_all(parent).context("cannot create Agent status directory")?;
    let bytes = serde_json::to_vec(status)?;
    let temporary = parent.join(format!(
        ".status-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    let result = file
        .write_all(&bytes)
        .and_then(|_| file.sync_all())
        .and_then(|_| std::fs::rename(&temporary, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result.context("cannot publish Agent status")
}

pub fn read(path: &Path) -> Result<RuntimeStatus> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 16 * 1024 {
        bail!("Agent status file is invalid");
    }
    let value: RuntimeStatus = serde_json::from_slice(&std::fs::read(path)?)?;
    if value.format_version != 1 {
        bail!("Agent status version is unsupported");
    }
    Ok(value)
}
