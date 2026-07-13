use anyhow::{bail, Context, Result};
use certael_agent_protocol::{VerificationKey, VerificationKeyRing};
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustStoreFile {
    keys: Vec<TrustKeyFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustKeyFile {
    key_id: String,
    public_key_hex: String,
    not_before_unix: i64,
    not_after_unix: i64,
    #[serde(default)]
    revoked: bool,
}

pub fn load(path: &Path) -> Result<VerificationKeyRing> {
    let metadata = std::fs::symlink_metadata(path).context("Agent trust store does not exist")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 64 * 1024 {
        bail!("Agent trust store must be a regular file no larger than 64 KiB");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o022 != 0 {
            bail!("Agent trust store must not be group- or world-writable");
        }
    }
    let input = std::fs::read(path).context("cannot read Agent trust store")?;
    let parsed: TrustStoreFile =
        serde_json::from_slice(&input).context("Agent trust store is not valid JSON")?;
    let keys = parsed
        .keys
        .into_iter()
        .map(|value| {
            let bytes = hex::decode(value.public_key_hex)
                .context("Agent trust key is not valid hexadecimal")?;
            let raw: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Agent trust key must be 32 bytes"))?;
            Ok(VerificationKey {
                key_id: value.key_id,
                key: VerifyingKey::from_bytes(&raw).context("Agent trust key is invalid")?,
                not_before_unix: value.not_before_unix,
                not_after_unix: value.not_after_unix,
                revoked: value.revoked,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    VerificationKeyRing::new(keys).context("Agent trust store is invalid")
}
