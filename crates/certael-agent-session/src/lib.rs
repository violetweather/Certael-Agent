use certael_agent_protocol::{
    report_digest, sign_report, AgentIntegrityReportV1, AgentLaunchGrantClaimsV1,
    AgentPolicyClaimsV1, AgentReportChallengeV1, IntegrityObservationV1, ProtocolError,
    SignedAgentPolicyV1, PROTOCOL_VERSION,
};
use ed25519_dalek::SigningKey;
use prost::Message;
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SessionError {
    #[error("launch grant is not bound to this Agent key")]
    KeyBinding,
    #[error("launch grant and policy do not match")]
    PolicyBinding,
    #[error("challenge is invalid, expired, or belongs to another session")]
    Challenge,
    #[error("report sequence is exhausted")]
    SequenceExhausted,
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}

pub struct AgentSession {
    signing_key: SigningKey,
    grant: AgentLaunchGrantClaimsV1,
    policy: AgentPolicyClaimsV1,
    agent_session_id: String,
    sequence: u64,
    previous_digest: [u8; 32],
    last_challenge_digest: Option<[u8; 32]>,
}

impl AgentSession {
    pub fn activate(
        signing_key: SigningKey,
        grant: AgentLaunchGrantClaimsV1,
        policy: AgentPolicyClaimsV1,
        signed_policy: &SignedAgentPolicyV1,
        agent_session_id: String,
    ) -> Result<Self, SessionError> {
        if grant.agent_public_key != signing_key.verifying_key().as_bytes() {
            return Err(SessionError::KeyBinding);
        }
        if grant.game_id != policy.game_id || grant.environment_id != policy.environment_id {
            return Err(SessionError::PolicyBinding);
        }
        let policy_digest = Sha256::digest(signed_policy.encode_to_vec());
        if grant.policy_digest.as_slice() != policy_digest.as_slice() {
            return Err(SessionError::PolicyBinding);
        }
        if agent_session_id.is_empty() || agent_session_id.len() > 128 {
            return Err(SessionError::Challenge);
        }
        Ok(Self {
            signing_key,
            grant,
            policy,
            agent_session_id,
            sequence: 0,
            previous_digest: [0; 32],
            last_challenge_digest: None,
        })
    }

    pub fn create_report(
        &mut self,
        challenge: &AgentReportChallengeV1,
        now_unix: i64,
        executable_sha256: [u8; 32],
        observations: Vec<IntegrityObservationV1>,
    ) -> Result<AgentIntegrityReportV1, SessionError> {
        if challenge.agent_session_id != self.agent_session_id
            || challenge.nonce.len() < 16
            || challenge.nonce.len() > 256
            || challenge.expires_at_unix <= now_unix
            || challenge.expires_at_unix - now_unix > 120
        {
            return Err(SessionError::Challenge);
        }
        let challenge_digest: [u8; 32] = Sha256::digest(challenge.encode_to_vec()).into();
        if self.last_challenge_digest == Some(challenge_digest) {
            return Err(SessionError::Challenge);
        }
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(SessionError::SequenceExhausted)?;
        let report = sign_report(
            AgentIntegrityReportV1 {
                protocol_version: PROTOCOL_VERSION,
                agent_session_id: self.agent_session_id.clone(),
                sequence,
                challenge_nonce: challenge.nonce.clone(),
                observed_at_unix: now_unix,
                build_id: self.grant.build_id.clone(),
                executable_sha256: executable_sha256.to_vec(),
                observations,
                previous_report_digest: self.previous_digest.to_vec(),
                signature: vec![],
            },
            &self.signing_key,
        )?;
        self.sequence = sequence;
        self.previous_digest = report_digest(&report);
        self.last_challenge_digest = Some(challenge_digest);
        Ok(report)
    }

    pub fn policy(&self) -> &AgentPolicyClaimsV1 {
        &self.policy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use certael_agent_protocol::{AgentRequirementModeV1, SignedAgentPolicyV1};
    use rand_core::OsRng;

    fn fixture() -> (AgentSession, AgentReportChallengeV1) {
        let key = SigningKey::generate(&mut OsRng);
        let policy = AgentPolicyClaimsV1 {
            protocol_version: 1,
            policy_id: "policy".into(),
            tenant_id: "tenant".into(),
            game_id: "game".into(),
            environment_id: "prod".into(),
            requirement_mode: AgentRequirementModeV1::Required as i32,
            heartbeat_seconds: 15,
            report_seconds: 60,
            disconnect_grace_seconds: 30,
            minimum_agent_version: "0.1.0".into(),
            expires_at_unix: 2_000_000_000,
        };
        let signed_policy = SignedAgentPolicyV1 {
            claims: policy.encode_to_vec(),
            signature: vec![1; 64],
            key_id: "policy-key".into(),
        };
        let grant = AgentLaunchGrantClaimsV1 {
            protocol_version: 1,
            grant_id: "grant".into(),
            tenant_id: "tenant".into(),
            game_id: "game".into(),
            environment_id: "prod".into(),
            player_subject: "player".into(),
            match_id: "match".into(),
            build_id: "build".into(),
            agent_public_key: key.verifying_key().as_bytes().to_vec(),
            issued_at_unix: 1_700_000_000,
            expires_at_unix: 1_700_000_060,
            policy_digest: Sha256::digest(signed_policy.encode_to_vec()).to_vec(),
            authoritative_server_id: "server".into(),
        };
        let session =
            AgentSession::activate(key, grant, policy, &signed_policy, "session".into()).unwrap();
        let challenge = AgentReportChallengeV1 {
            agent_session_id: "session".into(),
            nonce: vec![9; 32],
            expires_at_unix: 1_700_000_030,
        };
        (session, challenge)
    }

    #[test]
    fn sequences_and_chains_reports() {
        let (mut session, first_challenge) = fixture();
        let first = session
            .create_report(&first_challenge, 1_700_000_001, [3; 32], vec![])
            .unwrap();
        let second_challenge = AgentReportChallengeV1 {
            nonce: vec![8; 32],
            ..first_challenge
        };
        let second = session
            .create_report(&second_challenge, 1_700_000_002, [3; 32], vec![])
            .unwrap();
        assert_eq!(first.sequence, 1);
        assert_eq!(first.previous_report_digest, vec![0; 32]);
        assert_eq!(second.sequence, 2);
        assert_eq!(second.previous_report_digest, report_digest(&first));
    }

    #[test]
    fn rejects_reused_wrong_and_expired_challenges() {
        let (mut session, challenge) = fixture();
        session
            .create_report(&challenge, 1_700_000_001, [3; 32], vec![])
            .unwrap();
        assert_eq!(
            session.create_report(&challenge, 1_700_000_002, [3; 32], vec![]),
            Err(SessionError::Challenge)
        );
        assert_eq!(
            session.create_report(
                &AgentReportChallengeV1 {
                    agent_session_id: "other".into(),
                    nonce: vec![1; 32],
                    expires_at_unix: 1_700_000_030,
                },
                1_700_000_002,
                [3; 32],
                vec![],
            ),
            Err(SessionError::Challenge)
        );
    }
}
