use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use prost::Message;
use sha2::{Digest, Sha256};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;
pub const REPORT_DOMAIN: &[u8] = b"certael.agent.report.v1\0";
pub const LAUNCH_DOMAIN: &[u8] = b"certael.agent.launch.v1\0";
pub const POLICY_DOMAIN: &[u8] = b"certael.agent.policy.v1\0";
pub const BUILD_MANIFEST_DOMAIN: &[u8] = b"certael.agent.build-manifest.v1\0";
pub const REGISTRATION_DOMAIN: &[u8] = b"certael.agent.registration.v1\0";
pub const REVOCATION_DOMAIN: &[u8] = b"certael.agent.revocation.v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum AgentRequirementModeV1 {
    Disabled = 0,
    Optional = 1,
    Required = 2,
}

#[derive(Clone, PartialEq, Message)]
pub struct AgentPolicyClaimsV1 {
    #[prost(uint32, tag = "1")]
    pub protocol_version: u32,
    #[prost(string, tag = "2")]
    pub policy_id: String,
    #[prost(string, tag = "3")]
    pub game_id: String,
    #[prost(string, tag = "4")]
    pub environment_id: String,
    #[prost(enumeration = "AgentRequirementModeV1", tag = "5")]
    pub requirement_mode: i32,
    #[prost(uint32, tag = "6")]
    pub heartbeat_seconds: u32,
    #[prost(uint32, tag = "7")]
    pub report_seconds: u32,
    #[prost(uint32, tag = "8")]
    pub disconnect_grace_seconds: u32,
    #[prost(string, tag = "9")]
    pub minimum_agent_version: String,
    #[prost(int64, tag = "10")]
    pub expires_at_unix: i64,
    #[prost(string, tag = "11")]
    pub tenant_id: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct SignedAgentPolicyV1 {
    #[prost(bytes = "vec", tag = "1")]
    pub claims: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub signature: Vec<u8>,
    #[prost(string, tag = "3")]
    pub key_id: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct AgentLaunchGrantClaimsV1 {
    #[prost(uint32, tag = "1")]
    pub protocol_version: u32,
    #[prost(string, tag = "2")]
    pub grant_id: String,
    #[prost(string, tag = "3")]
    pub tenant_id: String,
    #[prost(string, tag = "4")]
    pub game_id: String,
    #[prost(string, tag = "5")]
    pub environment_id: String,
    #[prost(string, tag = "6")]
    pub player_subject: String,
    #[prost(string, tag = "7")]
    pub match_id: String,
    #[prost(string, tag = "8")]
    pub build_id: String,
    #[prost(bytes = "vec", tag = "9")]
    pub agent_public_key: Vec<u8>,
    #[prost(int64, tag = "10")]
    pub issued_at_unix: i64,
    #[prost(int64, tag = "11")]
    pub expires_at_unix: i64,
    #[prost(bytes = "vec", tag = "12")]
    pub policy_digest: Vec<u8>,
    #[prost(string, tag = "13")]
    pub authoritative_server_id: String,
    #[prost(bytes = "vec", tag = "14")]
    pub build_manifest_digest: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct AgentHelloV1 {
    #[prost(uint32, tag = "1")]
    pub protocol_version: u32,
    #[prost(string, tag = "2")]
    pub agent_version: String,
    #[prost(bytes = "vec", tag = "3")]
    pub agent_public_key: Vec<u8>,
    #[prost(string, tag = "4")]
    pub build_id: String,
    #[prost(bytes = "vec", tag = "5")]
    pub executable_sha256: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct SignedAgentLaunchGrantV1 {
    #[prost(bytes = "vec", tag = "1")]
    pub claims: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub signature: Vec<u8>,
    #[prost(string, tag = "3")]
    pub key_id: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct AgentLaunchBundleV1 {
    #[prost(bytes = "vec", tag = "1")]
    pub signed_policy: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub signed_launch_grant: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub signed_build_manifest: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ProtectedBuildFileV1 {
    #[prost(string, tag = "1")]
    pub path: String,
    #[prost(uint64, tag = "2")]
    pub size: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub sha256: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct BuildManifestClaimsV1 {
    #[prost(uint32, tag = "1")]
    pub protocol_version: u32,
    #[prost(string, tag = "2")]
    pub manifest_id: String,
    #[prost(string, tag = "3")]
    pub tenant_id: String,
    #[prost(string, tag = "4")]
    pub game_id: String,
    #[prost(string, tag = "5")]
    pub environment_id: String,
    #[prost(string, tag = "6")]
    pub build_id: String,
    #[prost(message, repeated, tag = "7")]
    pub files: Vec<ProtectedBuildFileV1>,
    #[prost(int64, tag = "8")]
    pub not_before_unix: i64,
    #[prost(int64, tag = "9")]
    pub expires_at_unix: i64,
}

#[derive(Clone, PartialEq, Message)]
pub struct SignedBuildManifestV1 {
    #[prost(bytes = "vec", tag = "1")]
    pub claims: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub signature: Vec<u8>,
    #[prost(string, tag = "3")]
    pub key_id: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct GameRegistrationClaimsV1 {
    #[prost(uint32, tag = "1")]
    pub protocol_version: u32,
    #[prost(string, tag = "2")]
    pub registration_id: String,
    #[prost(string, tag = "3")]
    pub publisher_id: String,
    #[prost(string, tag = "4")]
    pub tenant_id: String,
    #[prost(string, tag = "5")]
    pub game_id: String,
    #[prost(string, tag = "6")]
    pub environment_id: String,
    #[prost(string, tag = "7")]
    pub executable_relative_path: String,
    #[prost(bytes = "vec", tag = "8")]
    pub trust_store_sha256: Vec<u8>,
    #[prost(bytes = "vec", tag = "9")]
    pub update_root_sha256: Vec<u8>,
    #[prost(string, tag = "10")]
    pub update_metadata_url: String,
    #[prost(string, tag = "11")]
    pub update_targets_url: String,
    #[prost(string, tag = "12")]
    pub update_channel: String,
    #[prost(int64, tag = "13")]
    pub not_before_unix: i64,
    #[prost(int64, tag = "14")]
    pub expires_at_unix: i64,
}

#[derive(Clone, PartialEq, Message)]
pub struct SignedGameRegistrationV1 {
    #[prost(bytes = "vec", tag = "1")]
    pub claims: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub signature: Vec<u8>,
    #[prost(string, tag = "3")]
    pub key_id: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BoundAgentLaunch {
    pub session_id: String,
    pub tenant_id: String,
    pub game_id: String,
    pub environment_id: String,
    pub player_subject: String,
    pub match_id: String,
    pub build_id: String,
    pub authoritative_server_id: String,
    pub build_manifest: BuildManifestClaimsV1,
    pub build_manifest_digest: [u8; 32],
    pub heartbeat_seconds: u32,
    pub report_seconds: u32,
    pub disconnect_grace_seconds: u32,
    pub policy_expires_at_unix: i64,
    pub grant_expires_at_unix: i64,
}

#[derive(Clone, PartialEq, Message)]
pub struct AgentReportChallengeV1 {
    #[prost(string, tag = "1")]
    pub agent_session_id: String,
    #[prost(bytes = "vec", tag = "2")]
    pub nonce: Vec<u8>,
    #[prost(int64, tag = "3")]
    pub expires_at_unix: i64,
}

#[derive(Clone, PartialEq, Message)]
pub struct IntegrityObservationV1 {
    #[prost(string, tag = "1")]
    pub code: String,
    #[prost(string, tag = "2")]
    pub value: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct AgentIntegrityReportV1 {
    #[prost(uint32, tag = "1")]
    pub protocol_version: u32,
    #[prost(string, tag = "2")]
    pub agent_session_id: String,
    #[prost(uint64, tag = "3")]
    pub sequence: u64,
    #[prost(bytes = "vec", tag = "4")]
    pub challenge_nonce: Vec<u8>,
    #[prost(int64, tag = "5")]
    pub observed_at_unix: i64,
    #[prost(string, tag = "6")]
    pub build_id: String,
    #[prost(bytes = "vec", tag = "7")]
    pub executable_sha256: Vec<u8>,
    #[prost(message, repeated, tag = "8")]
    pub observations: Vec<IntegrityObservationV1>,
    #[prost(bytes = "vec", tag = "9")]
    pub previous_report_digest: Vec<u8>,
    #[prost(bytes = "vec", tag = "10")]
    pub signature: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct AgentHealthV1 {
    #[prost(string, tag = "1")]
    pub agent_session_id: String,
    #[prost(string, tag = "2")]
    pub state: String,
    #[prost(int64, tag = "3")]
    pub last_report_at_unix: i64,
    #[prost(string, repeated, tag = "4")]
    pub public_reasons: Vec<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct AgentRevocationClaimsV1 {
    #[prost(uint32, tag = "1")]
    pub protocol_version: u32,
    #[prost(string, tag = "2")]
    pub tenant_id: String,
    #[prost(string, tag = "3")]
    pub game_id: String,
    #[prost(string, tag = "4")]
    pub environment_id: String,
    #[prost(string, tag = "5")]
    pub agent_session_id: String,
    #[prost(string, tag = "6")]
    pub reason: String,
    #[prost(int64, tag = "7")]
    pub revoked_at_unix: i64,
    #[prost(int64, tag = "8")]
    pub expires_at_unix: i64,
}

#[derive(Clone, PartialEq, Message)]
pub struct SignedAgentRevocationV1 {
    #[prost(bytes = "vec", tag = "1")]
    pub claims: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub signature: Vec<u8>,
    #[prost(string, tag = "3")]
    pub key_id: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("message exceeds the 64 KiB protocol limit")]
    TooLarge,
    #[error("invalid public key or signature")]
    InvalidSignature,
    #[error("invalid protocol field: {0}")]
    InvalidField(&'static str),
    #[error("protobuf decode failed")]
    Decode,
    #[error("signed object is expired or not yet valid")]
    Expired,
    #[error("unknown or revoked signing key")]
    UnknownKey,
    #[error("protobuf encoding is not canonical")]
    NonCanonical,
}

#[derive(Clone)]
pub struct VerificationKey {
    pub key_id: String,
    pub key: VerifyingKey,
    pub not_before_unix: i64,
    pub not_after_unix: i64,
    pub revoked: bool,
}

pub struct VerificationKeyRing {
    keys: Vec<VerificationKey>,
}

impl VerificationKeyRing {
    pub fn new(keys: Vec<VerificationKey>) -> Result<Self, ProtocolError> {
        if keys.is_empty()
            || keys.iter().any(|key| {
                key.key_id.is_empty()
                    || key.key_id.len() > 128
                    || key.not_before_unix >= key.not_after_unix
            })
        {
            return Err(ProtocolError::InvalidField("verification_keys"));
        }
        for (index, key) in keys.iter().enumerate() {
            if keys[..index]
                .iter()
                .any(|candidate| candidate.key_id == key.key_id)
            {
                return Err(ProtocolError::InvalidField("duplicate_key_id"));
            }
        }
        Ok(Self { keys })
    }

    fn resolve(&self, key_id: &str, now_unix: i64) -> Result<&VerifyingKey, ProtocolError> {
        let key = self
            .keys
            .iter()
            .find(|candidate| candidate.key_id == key_id)
            .ok_or(ProtocolError::UnknownKey)?;
        if key.revoked || now_unix < key.not_before_unix || now_unix >= key.not_after_unix {
            return Err(ProtocolError::UnknownKey);
        }
        Ok(&key.key)
    }
}

pub fn verify_policy(
    signed: &SignedAgentPolicyV1,
    keys: &VerificationKeyRing,
    now_unix: i64,
) -> Result<AgentPolicyClaimsV1, ProtocolError> {
    let claims: AgentPolicyClaimsV1 = decode_canonical(&signed.claims)?;
    validate_policy(&claims, now_unix)?;
    verify_signed_bytes(
        POLICY_DOMAIN,
        &signed.claims,
        &signed.signature,
        keys.resolve(&signed.key_id, now_unix)?,
    )?;
    Ok(claims)
}

pub fn verify_launch_grant(
    signed: &SignedAgentLaunchGrantV1,
    keys: &VerificationKeyRing,
    now_unix: i64,
) -> Result<AgentLaunchGrantClaimsV1, ProtocolError> {
    let claims: AgentLaunchGrantClaimsV1 = decode_canonical(&signed.claims)?;
    validate_launch_grant(&claims, now_unix)?;
    verify_signed_bytes(
        LAUNCH_DOMAIN,
        &signed.claims,
        &signed.signature,
        keys.resolve(&signed.key_id, now_unix)?,
    )?;
    Ok(claims)
}

pub fn verify_build_manifest(
    signed: &SignedBuildManifestV1,
    keys: &VerificationKeyRing,
    now_unix: i64,
) -> Result<BuildManifestClaimsV1, ProtocolError> {
    let claims: BuildManifestClaimsV1 = decode_canonical(&signed.claims)?;
    validate_build_manifest(&claims, now_unix)?;
    verify_signed_bytes(
        BUILD_MANIFEST_DOMAIN,
        &signed.claims,
        &signed.signature,
        keys.resolve(&signed.key_id, now_unix)?,
    )?;
    Ok(claims)
}

pub fn verify_game_registration(
    signed: &SignedGameRegistrationV1,
    keys: &VerificationKeyRing,
    now_unix: i64,
) -> Result<GameRegistrationClaimsV1, ProtocolError> {
    let claims: GameRegistrationClaimsV1 = decode_canonical(&signed.claims)?;
    validate_game_registration(&claims, now_unix)?;
    verify_signed_bytes(
        REGISTRATION_DOMAIN,
        &signed.claims,
        &signed.signature,
        keys.resolve(&signed.key_id, now_unix)?,
    )?;
    Ok(claims)
}

pub fn verify_revocation(
    signed: &SignedAgentRevocationV1,
    keys: &VerificationKeyRing,
    now_unix: i64,
) -> Result<AgentRevocationClaimsV1, ProtocolError> {
    let claims: AgentRevocationClaimsV1 = decode_canonical(&signed.claims)?;
    if claims.protocol_version != PROTOCOL_VERSION
        || !identifier(&claims.tenant_id)
        || !identifier(&claims.game_id)
        || !identifier(&claims.environment_id)
        || !identifier(&claims.agent_session_id)
        || !identifier(&claims.reason)
        || claims.revoked_at_unix > now_unix + 30
        || claims.expires_at_unix <= now_unix
        || claims.expires_at_unix - claims.revoked_at_unix > 300
    {
        return Err(ProtocolError::InvalidField("revocation"));
    }
    verify_signed_bytes(
        REVOCATION_DOMAIN,
        &signed.claims,
        &signed.signature,
        keys.resolve(&signed.key_id, now_unix)?,
    )?;
    Ok(claims)
}

pub fn verify_launch_bundle(
    input: &[u8],
    keys: &VerificationKeyRing,
    now_unix: i64,
    expected_agent_public_key: &[u8; 32],
    expected_build_id: &str,
    current_agent_version: &str,
) -> Result<BoundAgentLaunch, ProtocolError> {
    let bundle: AgentLaunchBundleV1 = decode_canonical(input)?;
    let policy_envelope: SignedAgentPolicyV1 = decode_canonical(&bundle.signed_policy)?;
    let grant_envelope: SignedAgentLaunchGrantV1 = decode_canonical(&bundle.signed_launch_grant)?;
    let manifest_envelope: SignedBuildManifestV1 = decode_canonical(&bundle.signed_build_manifest)?;
    let policy = verify_policy(&policy_envelope, keys, now_unix)?;
    let grant = verify_launch_grant(&grant_envelope, keys, now_unix)?;
    let manifest = verify_build_manifest(&manifest_envelope, keys, now_unix)?;
    let manifest_digest: [u8; 32] = Sha256::digest(&bundle.signed_build_manifest).into();
    let minimum = semver::Version::parse(&policy.minimum_agent_version)
        .map_err(|_| ProtocolError::InvalidField("minimum_agent_version"))?;
    let current = semver::Version::parse(current_agent_version)
        .map_err(|_| ProtocolError::InvalidField("current_agent_version"))?;
    if grant.agent_public_key.as_slice() != expected_agent_public_key
        || grant.build_id != expected_build_id
        || policy.tenant_id != grant.tenant_id
        || policy.game_id != grant.game_id
        || policy.environment_id != grant.environment_id
        || grant.policy_digest.as_slice() != Sha256::digest(&bundle.signed_policy).as_slice()
        || grant.build_manifest_digest.as_slice() != manifest_digest
        || manifest.tenant_id != grant.tenant_id
        || manifest.game_id != grant.game_id
        || manifest.environment_id != grant.environment_id
        || manifest.build_id != grant.build_id
    {
        return Err(ProtocolError::InvalidField("launch_binding"));
    }
    if current < minimum {
        return Err(ProtocolError::InvalidField("agent_update_required"));
    }
    Ok(BoundAgentLaunch {
        session_id: grant.grant_id,
        tenant_id: grant.tenant_id,
        game_id: grant.game_id,
        environment_id: grant.environment_id,
        player_subject: grant.player_subject,
        match_id: grant.match_id,
        build_id: grant.build_id,
        authoritative_server_id: grant.authoritative_server_id,
        build_manifest: manifest,
        build_manifest_digest: manifest_digest,
        heartbeat_seconds: policy.heartbeat_seconds,
        report_seconds: policy.report_seconds,
        disconnect_grace_seconds: policy.disconnect_grace_seconds,
        policy_expires_at_unix: policy.expires_at_unix,
        grant_expires_at_unix: grant.expires_at_unix,
    })
}

pub fn decode_challenge(
    input: &[u8],
    now_unix: i64,
) -> Result<AgentReportChallengeV1, ProtocolError> {
    let challenge: AgentReportChallengeV1 = decode_canonical(input)?;
    if !identifier(&challenge.agent_session_id)
        || challenge.nonce.len() < 16
        || challenge.nonce.len() > 256
        || challenge.expires_at_unix <= now_unix
        || challenge.expires_at_unix > now_unix + 120
    {
        return Err(ProtocolError::InvalidField("challenge"));
    }
    Ok(challenge)
}

fn decode_canonical<M: Message + Default>(input: &[u8]) -> Result<M, ProtocolError> {
    if input.is_empty() || input.len() > MAX_MESSAGE_BYTES {
        return Err(ProtocolError::TooLarge);
    }
    let value = M::decode(input).map_err(|_| ProtocolError::Decode)?;
    if value.encode_to_vec() != input {
        return Err(ProtocolError::NonCanonical);
    }
    Ok(value)
}

fn verify_signed_bytes(
    domain: &[u8],
    claims: &[u8],
    signature: &[u8],
    key: &VerifyingKey,
) -> Result<(), ProtocolError> {
    let signature =
        Signature::from_slice(signature).map_err(|_| ProtocolError::InvalidSignature)?;
    let mut message = Vec::with_capacity(domain.len() + claims.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(claims);
    key.verify(&message, &signature)
        .map_err(|_| ProtocolError::InvalidSignature)
}

fn validate_policy(claims: &AgentPolicyClaimsV1, now_unix: i64) -> Result<(), ProtocolError> {
    if claims.protocol_version != PROTOCOL_VERSION
        || !identifier(&claims.policy_id)
        || !identifier(&claims.tenant_id)
        || !identifier(&claims.game_id)
        || !identifier(&claims.environment_id)
        || AgentRequirementModeV1::try_from(claims.requirement_mode).is_err()
        || !(5..=300).contains(&claims.heartbeat_seconds)
        || !(15..=3600).contains(&claims.report_seconds)
        || claims.report_seconds < claims.heartbeat_seconds
        || claims.disconnect_grace_seconds > 300
        || !version_identifier(&claims.minimum_agent_version)
    {
        return Err(ProtocolError::InvalidField("policy"));
    }
    if claims.expires_at_unix <= now_unix {
        return Err(ProtocolError::Expired);
    }
    Ok(())
}

fn validate_launch_grant(
    claims: &AgentLaunchGrantClaimsV1,
    now_unix: i64,
) -> Result<(), ProtocolError> {
    if claims.protocol_version != PROTOCOL_VERSION
        || !identifier(&claims.grant_id)
        || !identifier(&claims.tenant_id)
        || !identifier(&claims.game_id)
        || !identifier(&claims.environment_id)
        || !identifier(&claims.player_subject)
        || !identifier(&claims.match_id)
        || !identifier(&claims.build_id)
        || !identifier(&claims.authoritative_server_id)
        || claims.agent_public_key.len() != 32
        || claims.policy_digest.len() != 32
        || claims.build_manifest_digest.len() != 32
        || claims.issued_at_unix > now_unix + 30
        || claims.expires_at_unix <= claims.issued_at_unix
        || claims.expires_at_unix - claims.issued_at_unix > 120
    {
        return Err(ProtocolError::InvalidField("launch_grant"));
    }
    if claims.expires_at_unix <= now_unix {
        return Err(ProtocolError::Expired);
    }
    Ok(())
}

fn validate_build_manifest(
    claims: &BuildManifestClaimsV1,
    now_unix: i64,
) -> Result<(), ProtocolError> {
    if claims.protocol_version != PROTOCOL_VERSION
        || !identifier(&claims.manifest_id)
        || !identifier(&claims.tenant_id)
        || !identifier(&claims.game_id)
        || !identifier(&claims.environment_id)
        || !identifier(&claims.build_id)
        || claims.files.is_empty()
        || claims.files.len() > 16_384
        || claims.not_before_unix > now_unix + 30
        || claims.expires_at_unix <= now_unix
        || claims.expires_at_unix <= claims.not_before_unix
    {
        return Err(ProtocolError::InvalidField("build_manifest"));
    }
    let mut paths = std::collections::BTreeSet::new();
    if claims.files.iter().any(|file| {
        !safe_relative_path(&file.path)
            || file.sha256.len() != 32
            || !paths.insert(file.path.to_ascii_lowercase())
    }) {
        return Err(ProtocolError::InvalidField("build_manifest_file"));
    }
    Ok(())
}

fn validate_game_registration(
    claims: &GameRegistrationClaimsV1,
    now_unix: i64,
) -> Result<(), ProtocolError> {
    if claims.protocol_version != PROTOCOL_VERSION
        || !identifier(&claims.registration_id)
        || !identifier(&claims.publisher_id)
        || !identifier(&claims.tenant_id)
        || !identifier(&claims.game_id)
        || !identifier(&claims.environment_id)
        || !safe_relative_path(&claims.executable_relative_path)
        || claims.trust_store_sha256.len() != 32
        || claims.update_root_sha256.len() != 32
        || !https_url(&claims.update_metadata_url)
        || !https_url(&claims.update_targets_url)
        || !matches!(claims.update_channel.as_str(), "stable" | "beta")
        || claims.not_before_unix > now_unix + 30
        || claims.expires_at_unix <= now_unix
        || claims.expires_at_unix <= claims.not_before_unix
    {
        return Err(ProtocolError::InvalidField("game_registration"));
    }
    Ok(())
}

fn safe_relative_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value.starts_with('/')
        && !value.starts_with('\\')
        && !(value.len() >= 2 && value.as_bytes()[1] == b':')
        && value
            .split(['/', '\\'])
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn https_url(value: &str) -> bool {
    value.len() <= 2048
        && value.starts_with("https://")
        && value[8..].contains('.')
        && !value.chars().any(char::is_control)
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'.' | b'_' | b'-'))
}

fn version_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'.' | b'+' | b'-'))
}

pub fn signing_bytes<M: Message>(domain: &[u8], message: &M) -> Result<Vec<u8>, ProtocolError> {
    let encoded = message.encode_to_vec();
    if encoded.len() > MAX_MESSAGE_BYTES {
        return Err(ProtocolError::TooLarge);
    }
    let mut bytes = Vec::with_capacity(domain.len() + encoded.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&encoded);
    Ok(bytes)
}

pub fn sign_report(
    mut report: AgentIntegrityReportV1,
    key: &SigningKey,
) -> Result<AgentIntegrityReportV1, ProtocolError> {
    report.signature.clear();
    validate_report(&report)?;
    report.signature = key
        .sign(&signing_bytes(REPORT_DOMAIN, &report)?)
        .to_bytes()
        .to_vec();
    Ok(report)
}

pub fn verify_report(
    report: &AgentIntegrityReportV1,
    key: &VerifyingKey,
) -> Result<(), ProtocolError> {
    validate_report(report)?;
    let signature =
        Signature::from_slice(&report.signature).map_err(|_| ProtocolError::InvalidSignature)?;
    let mut unsigned = report.clone();
    unsigned.signature.clear();
    key.verify(&signing_bytes(REPORT_DOMAIN, &unsigned)?, &signature)
        .map_err(|_| ProtocolError::InvalidSignature)
}

pub fn report_digest(report: &AgentIntegrityReportV1) -> [u8; 32] {
    Sha256::digest(report.encode_to_vec()).into()
}

fn validate_report(report: &AgentIntegrityReportV1) -> Result<(), ProtocolError> {
    if report.protocol_version != PROTOCOL_VERSION {
        return Err(ProtocolError::InvalidField("protocol_version"));
    }
    if report.agent_session_id.is_empty() || report.agent_session_id.len() > 128 {
        return Err(ProtocolError::InvalidField("agent_session_id"));
    }
    if report.sequence == 0 {
        return Err(ProtocolError::InvalidField("sequence"));
    }
    if report.challenge_nonce.len() < 16 || report.challenge_nonce.len() > 256 {
        return Err(ProtocolError::InvalidField("challenge_nonce"));
    }
    if report.build_id.is_empty() || report.build_id.len() > 128 {
        return Err(ProtocolError::InvalidField("build_id"));
    }
    if report.executable_sha256.len() != 32 {
        return Err(ProtocolError::InvalidField("executable_sha256"));
    }
    if !report.previous_report_digest.is_empty() && report.previous_report_digest.len() != 32 {
        return Err(ProtocolError::InvalidField("previous_report_digest"));
    }
    if report.observations.len() > 1024 {
        return Err(ProtocolError::InvalidField("observations"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn report() -> AgentIntegrityReportV1 {
        AgentIntegrityReportV1 {
            protocol_version: 1,
            agent_session_id: "session".into(),
            sequence: 1,
            challenge_nonce: vec![7; 32],
            observed_at_unix: 1_700_000_000,
            build_id: "build".into(),
            executable_sha256: vec![8; 32],
            observations: vec![],
            previous_report_digest: vec![],
            signature: vec![],
        }
    }

    #[test]
    fn signed_report_verifies_and_tampering_fails() {
        let key = SigningKey::generate(&mut OsRng);
        let signed = sign_report(report(), &key).unwrap();
        verify_report(&signed, &key.verifying_key()).unwrap();
        let mut tampered = signed;
        tampered.sequence = 2;
        assert_eq!(
            verify_report(&tampered, &key.verifying_key()),
            Err(ProtocolError::InvalidSignature)
        );
    }

    #[test]
    fn invalid_nonce_is_rejected() {
        let key = SigningKey::generate(&mut OsRng);
        let mut value = report();
        value.challenge_nonce = vec![0; 4];
        assert_eq!(
            sign_report(value, &key),
            Err(ProtocolError::InvalidField("challenge_nonce"))
        );
    }

    fn key_ring(key: &SigningKey) -> VerificationKeyRing {
        VerificationKeyRing::new(vec![VerificationKey {
            key_id: "root-1".into(),
            key: key.verifying_key(),
            not_before_unix: 1_600_000_000,
            not_after_unix: 1_800_000_000,
            revoked: false,
        }])
        .unwrap()
    }

    #[test]
    fn verifies_bound_short_lived_launch_grant() {
        let key = SigningKey::generate(&mut OsRng);
        let claims = AgentLaunchGrantClaimsV1 {
            protocol_version: 1,
            grant_id: "grant-1".into(),
            tenant_id: "tenant-1".into(),
            game_id: "game-1".into(),
            environment_id: "prod".into(),
            player_subject: "player-1".into(),
            match_id: "match-1".into(),
            build_id: "build-1".into(),
            agent_public_key: vec![3; 32],
            issued_at_unix: 1_700_000_000,
            expires_at_unix: 1_700_000_060,
            policy_digest: vec![4; 32],
            authoritative_server_id: "server-1".into(),
            build_manifest_digest: vec![5; 32],
        };
        let encoded = claims.encode_to_vec();
        let mut message = LAUNCH_DOMAIN.to_vec();
        message.extend_from_slice(&encoded);
        let signed = SignedAgentLaunchGrantV1 {
            claims: encoded,
            signature: key.sign(&message).to_bytes().to_vec(),
            key_id: "root-1".into(),
        };
        assert_eq!(
            verify_launch_grant(&signed, &key_ring(&key), 1_700_000_001).unwrap(),
            claims
        );
        assert_eq!(
            verify_launch_grant(&signed, &key_ring(&key), 1_700_000_061),
            Err(ProtocolError::Expired)
        );
    }

    #[test]
    fn verifies_policy_and_rejects_revoked_key() {
        let key = SigningKey::generate(&mut OsRng);
        let claims = AgentPolicyClaimsV1 {
            protocol_version: 1,
            policy_id: "competitive-default".into(),
            tenant_id: "tenant-1".into(),
            game_id: "game-1".into(),
            environment_id: "prod".into(),
            requirement_mode: AgentRequirementModeV1::Required as i32,
            heartbeat_seconds: 15,
            report_seconds: 60,
            disconnect_grace_seconds: 30,
            minimum_agent_version: "0.1.0".into(),
            expires_at_unix: 1_700_003_600,
        };
        let encoded = claims.encode_to_vec();
        let mut message = POLICY_DOMAIN.to_vec();
        message.extend_from_slice(&encoded);
        let signed = SignedAgentPolicyV1 {
            claims: encoded,
            signature: key.sign(&message).to_bytes().to_vec(),
            key_id: "root-1".into(),
        };
        assert_eq!(
            verify_policy(&signed, &key_ring(&key), 1_700_000_000).unwrap(),
            claims
        );
        let revoked = VerificationKeyRing::new(vec![VerificationKey {
            key_id: "root-1".into(),
            key: key.verifying_key(),
            not_before_unix: 1_600_000_000,
            not_after_unix: 1_800_000_000,
            revoked: true,
        }])
        .unwrap();
        assert_eq!(
            verify_policy(&signed, &revoked, 1_700_000_000),
            Err(ProtocolError::UnknownKey)
        );
    }

    #[test]
    fn launch_bundle_binds_policy_key_build_and_agent_version() {
        let root = SigningKey::generate(&mut OsRng);
        let agent = SigningKey::generate(&mut OsRng);
        let policy_claims = AgentPolicyClaimsV1 {
            protocol_version: 1,
            policy_id: "competitive".into(),
            tenant_id: "tenant".into(),
            game_id: "game".into(),
            environment_id: "prod".into(),
            requirement_mode: AgentRequirementModeV1::Required as i32,
            heartbeat_seconds: 15,
            report_seconds: 60,
            disconnect_grace_seconds: 30,
            minimum_agent_version: "0.1.0".into(),
            expires_at_unix: 1_700_003_600,
        };
        let policy_claim_bytes = policy_claims.encode_to_vec();
        let policy = SignedAgentPolicyV1 {
            signature: root
                .sign(&[POLICY_DOMAIN, &policy_claim_bytes].concat())
                .to_bytes()
                .to_vec(),
            claims: policy_claim_bytes,
            key_id: "root-1".into(),
        }
        .encode_to_vec();
        let manifest_claims = BuildManifestClaimsV1 {
            protocol_version: 1,
            manifest_id: "manifest".into(),
            tenant_id: "tenant".into(),
            game_id: "game".into(),
            environment_id: "prod".into(),
            build_id: "build".into(),
            files: vec![ProtectedBuildFileV1 {
                path: "game.exe".into(),
                size: 100,
                sha256: vec![7; 32],
            }],
            not_before_unix: 1_699_999_000,
            expires_at_unix: 1_700_003_600,
        };
        let manifest_claim_bytes = manifest_claims.encode_to_vec();
        let manifest = SignedBuildManifestV1 {
            signature: root
                .sign(&[BUILD_MANIFEST_DOMAIN, &manifest_claim_bytes].concat())
                .to_bytes()
                .to_vec(),
            claims: manifest_claim_bytes,
            key_id: "root-1".into(),
        }
        .encode_to_vec();
        let grant_claims = AgentLaunchGrantClaimsV1 {
            protocol_version: 1,
            grant_id: "session".into(),
            tenant_id: "tenant".into(),
            game_id: "game".into(),
            environment_id: "prod".into(),
            player_subject: "player".into(),
            match_id: "match".into(),
            build_id: "build".into(),
            agent_public_key: agent.verifying_key().to_bytes().to_vec(),
            issued_at_unix: 1_700_000_000,
            expires_at_unix: 1_700_000_060,
            policy_digest: Sha256::digest(&policy).to_vec(),
            authoritative_server_id: "server".into(),
            build_manifest_digest: Sha256::digest(&manifest).to_vec(),
        };
        let grant_claim_bytes = grant_claims.encode_to_vec();
        let grant = SignedAgentLaunchGrantV1 {
            signature: root
                .sign(&[LAUNCH_DOMAIN, &grant_claim_bytes].concat())
                .to_bytes()
                .to_vec(),
            claims: grant_claim_bytes,
            key_id: "root-1".into(),
        }
        .encode_to_vec();
        let bundle = AgentLaunchBundleV1 {
            signed_policy: policy,
            signed_launch_grant: grant.clone(),
            signed_build_manifest: manifest.clone(),
        }
        .encode_to_vec();
        assert_eq!(
            verify_launch_bundle(
                &bundle,
                &key_ring(&root),
                1_700_000_001,
                &agent.verifying_key().to_bytes(),
                "build",
                "0.1.0",
            )
            .unwrap()
            .session_id,
            "session"
        );
        assert_eq!(
            verify_launch_bundle(
                &bundle,
                &key_ring(&root),
                1_700_000_001,
                &agent.verifying_key().to_bytes(),
                "other-build",
                "0.1.0",
            ),
            Err(ProtocolError::InvalidField("launch_binding"))
        );

        let other_tenant_claims = AgentPolicyClaimsV1 {
            tenant_id: "other-tenant".into(),
            ..policy_claims
        };
        let other_tenant_bytes = other_tenant_claims.encode_to_vec();
        let other_tenant_policy = SignedAgentPolicyV1 {
            signature: root
                .sign(&[POLICY_DOMAIN, &other_tenant_bytes].concat())
                .to_bytes()
                .to_vec(),
            claims: other_tenant_bytes,
            key_id: "root-1".into(),
        }
        .encode_to_vec();
        let mismatch_grant_claims = AgentLaunchGrantClaimsV1 {
            policy_digest: Sha256::digest(&other_tenant_policy).to_vec(),
            ..grant_claims
        };
        let mismatch_grant_bytes = mismatch_grant_claims.encode_to_vec();
        let mismatch_grant = SignedAgentLaunchGrantV1 {
            signature: root
                .sign(&[LAUNCH_DOMAIN, &mismatch_grant_bytes].concat())
                .to_bytes()
                .to_vec(),
            claims: mismatch_grant_bytes,
            key_id: "root-1".into(),
        }
        .encode_to_vec();
        let mismatched_bundle = AgentLaunchBundleV1 {
            signed_policy: other_tenant_policy,
            signed_launch_grant: mismatch_grant,
            signed_build_manifest: manifest,
        }
        .encode_to_vec();
        assert_eq!(
            verify_launch_bundle(
                &mismatched_bundle,
                &key_ring(&root),
                1_700_000_001,
                &agent.verifying_key().to_bytes(),
                "build",
                "0.1.0",
            ),
            Err(ProtocolError::InvalidField("launch_binding"))
        );
    }

    #[test]
    fn rejects_noncanonical_claim_encoding() {
        let key = SigningKey::generate(&mut OsRng);
        // Field 1 encoded with a non-minimal varint. Prost accepts it, but the
        // canonical re-encoding differs and must therefore be rejected.
        let claims = vec![0x08, 0x81, 0x00];
        let mut message = POLICY_DOMAIN.to_vec();
        message.extend_from_slice(&claims);
        let signed = SignedAgentPolicyV1 {
            claims,
            signature: key.sign(&message).to_bytes().to_vec(),
            key_id: "root-1".into(),
        };
        assert_eq!(
            verify_policy(&signed, &key_ring(&key), 1_700_000_000),
            Err(ProtocolError::NonCanonical)
        );
    }

    #[test]
    fn golden_policy_vector_is_stable() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let claims = AgentPolicyClaimsV1 {
            protocol_version: 1,
            policy_id: "competitive".into(),
            tenant_id: "tenant".into(),
            game_id: "game".into(),
            environment_id: "prod".into(),
            requirement_mode: AgentRequirementModeV1::Required as i32,
            heartbeat_seconds: 15,
            report_seconds: 60,
            disconnect_grace_seconds: 30,
            minimum_agent_version: "1.0.0".into(),
            expires_at_unix: 1_800_000_000,
        };
        let encoded = claims.encode_to_vec();
        assert_eq!(hex::encode(&encoded), "0801120b636f6d70657469746976651a0467616d65220470726f642802300f383c401e4a05312e302e305080a4a7da065a0674656e616e74");
        assert_eq!(
            hex::encode(key.sign(&[POLICY_DOMAIN, &encoded].concat()).to_bytes()),
            "7cbfbe7094e668b794c064f9a9d7828af08d17951afa92411088cca17a4030d4cfac746a991e2a203134b7abc547a409f3429c4ecc4b3651b48648c28af3df0b"
        );
    }

    #[test]
    fn golden_launch_grant_vector_is_stable() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let policy_claims = AgentPolicyClaimsV1 {
            protocol_version: 1,
            policy_id: "competitive".into(),
            tenant_id: "tenant".into(),
            game_id: "game".into(),
            environment_id: "prod".into(),
            requirement_mode: AgentRequirementModeV1::Required as i32,
            heartbeat_seconds: 15,
            report_seconds: 60,
            disconnect_grace_seconds: 30,
            minimum_agent_version: "1.0.0".into(),
            expires_at_unix: 1_800_000_000,
        };
        let policy_bytes = policy_claims.encode_to_vec();
        let signed_policy = SignedAgentPolicyV1 {
            signature: key
                .sign(&[POLICY_DOMAIN, &policy_bytes].concat())
                .to_bytes()
                .to_vec(),
            claims: policy_bytes,
            key_id: "vector-key".into(),
        }
        .encode_to_vec();
        let claims = AgentLaunchGrantClaimsV1 {
            protocol_version: 1,
            grant_id: "grant".into(),
            tenant_id: "tenant".into(),
            game_id: "game".into(),
            environment_id: "prod".into(),
            player_subject: "player".into(),
            match_id: "match".into(),
            build_id: "build".into(),
            agent_public_key: key.verifying_key().to_bytes().to_vec(),
            issued_at_unix: 1_700_000_000,
            expires_at_unix: 1_700_000_060,
            policy_digest: Sha256::digest(signed_policy).to_vec(),
            authoritative_server_id: "server".into(),
            build_manifest_digest: vec![5; 32],
        };
        let encoded = claims.encode_to_vec();
        assert_eq!(hex::encode(&encoded), "080112056772616e741a0674656e616e74220467616d652a0470726f643206706c617965723a056d6174636842056275696c644a20ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c5080e2cfaa0658bce2cfaa066220947cc7a0c10233b2ff5c0aae415b2e37cfc97915e5747edcc3eb8245f600f4406a0673657276657272200505050505050505050505050505050505050505050505050505050505050505");
    }
}
