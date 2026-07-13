use certael_agent_protocol::{
    AgentLaunchGrantClaimsV1, AgentPolicyClaimsV1, AgentRequirementModeV1, SignedAgentPolicyV1,
    LAUNCH_DOMAIN, POLICY_DOMAIN,
};
use ed25519_dalek::{Signer, SigningKey};
use prost::Message;
use sha2::{Digest, Sha256};

fn main() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let policy_claims = AgentPolicyClaimsV1 {
        protocol_version: 1,
        policy_id: "competitive".into(),
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
    let policy_signature = key
        .sign(&[POLICY_DOMAIN, &policy_bytes].concat())
        .to_bytes()
        .to_vec();
    let signed_policy = SignedAgentPolicyV1 {
        claims: policy_bytes.clone(),
        signature: policy_signature.clone(),
        key_id: "vector-key".into(),
    }
    .encode_to_vec();
    let policy_digest = Sha256::digest(&signed_policy).to_vec();
    let grant_claims = AgentLaunchGrantClaimsV1 {
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
        policy_digest,
        authoritative_server_id: "server".into(),
    };
    let grant_bytes = grant_claims.encode_to_vec();
    let grant_signature = key.sign(&[LAUNCH_DOMAIN, &grant_bytes].concat()).to_bytes();
    println!("policy_claims={}", hex::encode(policy_bytes));
    println!("policy_signature={}", hex::encode(policy_signature));
    println!("signed_policy={}", hex::encode(signed_policy));
    println!("grant_claims={}", hex::encode(grant_bytes));
    println!("grant_signature={}", hex::encode(grant_signature));
}
