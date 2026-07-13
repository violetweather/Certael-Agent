use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use prost::Message;
use sha2::{Digest, Sha256};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;
pub const REPORT_DOMAIN: &[u8] = b"certael.agent.report.v1\0";
pub const LAUNCH_DOMAIN: &[u8] = b"certael.agent.launch.v1\0";
pub const POLICY_DOMAIN: &[u8] = b"certael.agent.policy.v1\0";

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
pub struct AgentRevocationV1 {
    #[prost(string, tag = "1")]
    pub agent_session_id: String,
    #[prost(string, tag = "2")]
    pub reason: String,
    #[prost(int64, tag = "3")]
    pub revoked_at_unix: i64,
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
}
