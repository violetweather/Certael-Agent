use std::path::{Path, PathBuf};
use tough::{ExpirationEnforcement, Limits, Prefix, RepositoryLoader, TargetName};
use url::Url;

const MAX_TRUSTED_ROOT_BYTES: u64 = 1024 * 1024;

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
}

/// Verifies TUF root rotation, timestamp/snapshot/targets signatures,
/// expiration, rollback state, target length, and target hashes before staging.
/// This function never replaces a running executable.
pub async fn verify_and_stage(config: &UpdateConfig) -> Result<PathBuf, UpdateError> {
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
    if repository
        .all_targets()
        .all(|(candidate, _)| candidate != &target)
    {
        return Err(UpdateError::TargetMissing);
    }
    repository
        .save_target(&target, &config.staging_directory, Prefix::None)
        .await
        .map_err(|_| UpdateError::Verification)?;
    Ok(config.staging_directory.join(target.resolved()))
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
}
