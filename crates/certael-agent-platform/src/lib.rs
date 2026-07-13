use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegritySnapshot {
    pub executable_name: String,
    pub executable_sha256: String,
    pub executable_size: u64,
    pub debugger_observed: bool,
    pub platform: String,
    pub process_id: u32,
}

pub fn inspect_executable(path: &Path) -> Result<IntegritySnapshot> {
    let canonical = path
        .canonicalize()
        .context("game executable does not exist")?;
    let metadata = canonical
        .metadata()
        .context("cannot inspect game executable")?;
    if !metadata.is_file() {
        bail!("game path is not a regular file");
    }
    let name = canonical
        .file_name()
        .and_then(|v| v.to_str())
        .context("game filename is not UTF-8")?;
    let mut file = File::open(&canonical).context("cannot open game executable")?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .context("cannot hash game executable")?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(IntegritySnapshot {
        executable_name: name.to_owned(),
        executable_sha256: hex::encode(hasher.finalize()),
        executable_size: metadata.len(),
        debugger_observed: debugger_observed(),
        platform: std::env::consts::OS.to_owned(),
        process_id: std::process::id(),
    })
}

pub fn validate_game_path(path: &Path) -> Result<PathBuf> {
    let canonical = path
        .canonicalize()
        .context("game executable does not exist")?;
    if !canonical.is_file() {
        bail!("game path is not a regular file");
    }
    Ok(canonical)
}

#[cfg(target_os = "linux")]
fn debugger_observed() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|line| {
                line.strip_prefix("TracerPid:")
                    .map(str::trim)
                    .map(str::to_owned)
            })
        })
        .is_some_and(|value| value != "0")
}

#[cfg(target_os = "macos")]
fn debugger_observed() -> bool {
    false
}

#[cfg(target_os = "windows")]
fn debugger_observed() -> bool {
    false
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn debugger_observed() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hashes_a_regular_file() {
        let snapshot =
            inspect_executable(Path::new(std::env::current_exe().unwrap().as_path())).unwrap();
        assert_eq!(snapshot.executable_sha256.len(), 64);
        assert!(snapshot.executable_size > 0);
    }
    #[test]
    fn rejects_missing_path() {
        assert!(validate_game_path(Path::new("definitely-not-a-game")).is_err());
    }
}
