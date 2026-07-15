use crate::trust;
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use certael_agent_protocol::{
    verify_game_registration, GameRegistrationClaimsV1, SignedGameRegistrationV1,
};
use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_REGISTRATION_BYTES: u64 = 64 * 1024;
const MAX_ROOT_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRegistration {
    format_version: u32,
    signed_registration_base64: String,
    game_root: String,
}

pub struct RegisteredGame {
    pub claims: GameRegistrationClaimsV1,
    pub game: PathBuf,
    pub game_root: PathBuf,
    pub trust_store: PathBuf,
    pub update_root: PathBuf,
    pub state_root: PathBuf,
    pub status_path: PathBuf,
}

pub fn default_root() -> PathBuf {
    #[cfg(windows)]
    {
        let base = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        return base.join("Certael").join("games");
    }
    #[cfg(not(windows))]
    PathBuf::from("/usr/local/etc/certael/games")
}

pub fn register(
    registry_root: &Path,
    signed_registration: &Path,
    publisher_trust_store: &Path,
    update_root: &Path,
    game_root: &Path,
) -> Result<GameRegistrationClaimsV1> {
    install_registration(
        registry_root,
        signed_registration,
        publisher_trust_store,
        update_root,
        game_root,
        false,
    )
}

pub fn update(
    registry_root: &Path,
    signed_registration: &Path,
    publisher_trust_store: &Path,
    update_root: &Path,
    game_root: &Path,
) -> Result<GameRegistrationClaimsV1> {
    install_registration(
        registry_root,
        signed_registration,
        publisher_trust_store,
        update_root,
        game_root,
        true,
    )
}

fn install_registration(
    registry_root: &Path,
    signed_registration: &Path,
    publisher_trust_store: &Path,
    update_root: &Path,
    game_root: &Path,
    replace: bool,
) -> Result<GameRegistrationClaimsV1> {
    let registration_bytes = read_regular(signed_registration, MAX_REGISTRATION_BYTES)
        .context("signed game registration is invalid")?;
    let signed = SignedGameRegistrationV1::decode(registration_bytes.as_slice())
        .context("signed game registration is malformed")?;
    if signed.encode_to_vec() != registration_bytes {
        bail!("signed game registration is not canonical");
    }
    let keys = trust::load(publisher_trust_store)?;
    let claims = verify_game_registration(&signed, &keys, now_unix()?)
        .context("game registration signature was rejected")?;
    let trust_bytes = read_regular(publisher_trust_store, MAX_ROOT_BYTES)
        .context("publisher trust store is invalid")?;
    let update_bytes =
        read_regular(update_root, MAX_ROOT_BYTES).context("TUF update root is invalid")?;
    if Sha256::digest(&trust_bytes).as_slice() != claims.trust_store_sha256
        || Sha256::digest(&update_bytes).as_slice() != claims.update_root_sha256
    {
        bail!("game registration does not bind the supplied trust material");
    }
    let game_root = game_root
        .canonicalize()
        .context("game installation root does not exist")?;
    if !game_root.is_dir() {
        bail!("game installation root is not a directory");
    }
    let game = game_root.join(&claims.executable_relative_path);
    let canonical_game = game
        .canonicalize()
        .context("registered game executable does not exist")?;
    if !canonical_game.starts_with(&game_root) || !canonical_game.is_file() {
        bail!("registered executable escapes the game installation root");
    }

    std::fs::create_dir_all(registry_root).context("cannot create Agent game registry")?;
    let destination = registry_root.join(&claims.registration_id);
    let backup = registry_root.join(format!(".backup-{}", claims.registration_id));
    recover_registration(&destination, &backup)?;
    if destination.exists() && !replace {
        bail!("this game registration already exists");
    }
    if !destination.exists() && replace {
        bail!("this game registration is not installed");
    }
    let temporary = registry_root.join(format!(
        ".register-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    std::fs::create_dir(&temporary).context("cannot stage game registration")?;
    let result = (|| -> Result<()> {
        write_new(&temporary.join("trust-store.json"), &trust_bytes)?;
        write_new(&temporary.join("update-root.json"), &update_bytes)?;
        let record = StoredRegistration {
            format_version: 1,
            signed_registration_base64: BASE64.encode(&registration_bytes),
            game_root: game_root.to_string_lossy().into_owned(),
        };
        write_new(
            &temporary.join("registration.json"),
            &serde_json::to_vec(&record)?,
        )?;
        if replace {
            std::fs::rename(&destination, &backup)
                .context("cannot stage existing game registration")?;
            if let Err(error) = std::fs::rename(&temporary, &destination) {
                let _ = std::fs::rename(&backup, &destination);
                return Err(error).context("cannot activate updated game registration");
            }
            std::fs::remove_dir_all(&backup).context("cannot retire previous game registration")?;
        } else {
            std::fs::rename(&temporary, &destination)
                .context("cannot activate game registration")?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&temporary);
    }
    result?;
    Ok(claims)
}

fn recover_registration(destination: &Path, backup: &Path) -> Result<()> {
    match (destination.exists(), backup.exists()) {
        (false, true) => std::fs::rename(backup, destination)
            .context("cannot recover interrupted game registration"),
        (true, true) => {
            std::fs::remove_dir_all(backup).context("cannot finish interrupted game registration")
        }
        _ => Ok(()),
    }
}

pub fn load(registry_root: &Path, registration_id: &str) -> Result<RegisteredGame> {
    if !safe_id(registration_id) {
        bail!("invalid game registration ID");
    }
    let state_root = registry_root.join(registration_id);
    let record_bytes = read_regular(
        &state_root.join("registration.json"),
        MAX_REGISTRATION_BYTES,
    )
    .context("registered game metadata is unavailable")?;
    let record: StoredRegistration =
        serde_json::from_slice(&record_bytes).context("registered game metadata is invalid")?;
    if record.format_version != 1 {
        bail!("registered game metadata version is unsupported");
    }
    let signed_bytes = BASE64
        .decode(&record.signed_registration_base64)
        .context("registered game signature is invalid")?;
    let signed = SignedGameRegistrationV1::decode(signed_bytes.as_slice())
        .context("registered game signature is malformed")?;
    if signed.encode_to_vec() != signed_bytes {
        bail!("registered game signature is not canonical");
    }
    let trust_store = state_root.join("trust-store.json");
    let update_root = state_root.join("update-root.json");
    let trust_bytes = read_regular(&trust_store, MAX_ROOT_BYTES)?;
    let update_bytes = read_regular(&update_root, MAX_ROOT_BYTES)?;
    let claims = verify_game_registration(&signed, &trust::load(&trust_store)?, now_unix()?)
        .context("registered game is expired or revoked")?;
    if claims.registration_id != registration_id
        || Sha256::digest(&trust_bytes).as_slice() != claims.trust_store_sha256
        || Sha256::digest(&update_bytes).as_slice() != claims.update_root_sha256
    {
        bail!("registered game trust binding is invalid");
    }
    let game_root = PathBuf::from(record.game_root)
        .canonicalize()
        .context("registered game installation is unavailable")?;
    let game = game_root
        .join(&claims.executable_relative_path)
        .canonicalize()?;
    if !game.starts_with(&game_root) || !game.is_file() {
        bail!("registered game executable is unsafe");
    }
    Ok(RegisteredGame {
        claims,
        game,
        game_root,
        trust_store,
        update_root,
        state_root,
        status_path: crate::status::path(registration_id)?,
    })
}

pub fn list(registry_root: &Path) -> Result<Vec<String>> {
    if !registry_root.exists() {
        return Ok(vec![]);
    }
    let mut games = std::fs::read_dir(registry_root)?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            entry.file_type().ok()?.is_dir().then(|| entry.file_name())
        })
        .filter_map(|name| name.into_string().ok())
        .filter(|name| safe_id(name) && !name.starts_with('.'))
        .collect::<Vec<_>>();
    games.sort();
    Ok(games)
}

fn read_regular(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        bail!("file is not a bounded regular file");
    }
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        bail!("file exceeds its size limit");
    }
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'.' | b'_' | b'-'))
}

fn now_unix() -> Result<i64> {
    Ok(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use certael_agent_protocol::{GameRegistrationClaimsV1, REGISTRATION_DOMAIN};
    use ed25519_dalek::{Signer, SigningKey};
    use prost::Message;

    #[test]
    fn registers_and_reloads_isolated_signed_game() {
        let root = std::env::temp_dir().join(format!(
            "certael-registration-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let game_root = root.join("game");
        let registry_root = root.join("registry");
        std::fs::create_dir_all(game_root.join("bin")).unwrap();
        std::fs::write(game_root.join("bin/game"), b"game").unwrap();
        let key = SigningKey::from_bytes(&[9; 32]);
        let now = now_unix().unwrap();
        let trust = serde_json::json!({"keys": [{
            "key_id": "publisher-key",
            "public_key_hex": hex::encode(key.verifying_key().as_bytes()),
            "not_before_unix": now - 60,
            "not_after_unix": now + 3600,
            "revoked": false
        }]});
        let trust_bytes = serde_json::to_vec(&trust).unwrap();
        let update_bytes = b"tuf-root".to_vec();
        let trust_path = root.join("trust.json");
        let update_path = root.join("root.json");
        std::fs::write(&trust_path, &trust_bytes).unwrap();
        std::fs::write(&update_path, &update_bytes).unwrap();
        let claims = GameRegistrationClaimsV1 {
            protocol_version: 1,
            registration_id: "sample-production".into(),
            publisher_id: "sample-publisher".into(),
            tenant_id: "tenant".into(),
            game_id: "game".into(),
            environment_id: "prod".into(),
            executable_relative_path: "bin/game".into(),
            trust_store_sha256: Sha256::digest(&trust_bytes).to_vec(),
            update_root_sha256: Sha256::digest(&update_bytes).to_vec(),
            update_metadata_url: "https://updates.example/metadata/".into(),
            update_targets_url: "https://updates.example/targets/".into(),
            update_channel: "stable".into(),
            not_before_unix: now - 1,
            expires_at_unix: now + 3600,
        };
        let claim_bytes = claims.encode_to_vec();
        let signed = SignedGameRegistrationV1 {
            claims: claim_bytes.clone(),
            signature: key
                .sign(&[REGISTRATION_DOMAIN, &claim_bytes].concat())
                .to_bytes()
                .to_vec(),
            key_id: "publisher-key".into(),
        };
        let registration = root.join("registration.pb");
        std::fs::write(&registration, signed.encode_to_vec()).unwrap();
        let registered = register(
            &registry_root,
            &registration,
            &trust_path,
            &update_path,
            &game_root,
        )
        .unwrap();
        assert_eq!(registered.registration_id, "sample-production");
        update(
            &registry_root,
            &registration,
            &trust_path,
            &update_path,
            &game_root,
        )
        .unwrap();
        let loaded = load(&registry_root, "sample-production").unwrap();
        assert_eq!(
            loaded.game,
            game_root.join("bin/game").canonicalize().unwrap()
        );
        assert_eq!(list(&registry_root).unwrap(), vec!["sample-production"]);
        std::fs::remove_dir_all(root).unwrap();
    }
}
