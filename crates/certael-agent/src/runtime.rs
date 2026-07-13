use anyhow::{bail, Context, Result};
use certael_agent_ipc::{read_frame, write_frame, Frame, IpcError, MessageType};
use certael_agent_platform::inspect_executable;
use certael_agent_protocol::{
    decode_challenge, report_digest, sign_report, verify_launch_bundle, AgentHelloV1,
    AgentIntegrityReportV1, IntegrityObservationV1, VerificationKeyRing, PROTOCOL_VERSION,
};
use ed25519_dalek::SigningKey;
use prost::Message;
use std::{
    io::{Read, Write},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

pub struct RuntimeState {
    pub game: PathBuf,
    pub game_process_id: u32,
    pub key: SigningKey,
    pub hello: AgentHelloV1,
    pub trust: VerificationKeyRing,
}

pub fn serve(reader: &mut impl Read, writer: &mut impl Write, state: &RuntimeState) -> Result<()> {
    write_frame(
        writer,
        &Frame {
            message_type: MessageType::AgentHello,
            payload: state.hello.encode_to_vec(),
        },
    )
    .context("failed to send Agent hello")?;
    let bootstrap = read_frame(reader).context("protected game closed before Agent admission")?;
    if bootstrap.message_type != MessageType::LaunchGrant {
        bail!("protected game did not provide a signed Agent launch bundle");
    }
    let public_key = state.key.verifying_key().to_bytes();
    let launch = verify_launch_bundle(
        &bootstrap.payload,
        &state.trust,
        now_unix()?,
        &public_key,
        &state.hello.build_id,
        env!("CARGO_PKG_VERSION"),
    )
    .context("signed Agent launch bundle was rejected")?;
    let mut sequence = 1_u64;
    let mut previous_digest = [0_u8; 32];
    loop {
        let frame = match read_frame(reader) {
            Ok(value) => value,
            Err(IpcError::Io) => return Ok(()),
            Err(error) => return Err(error).context("Agent channel frame was rejected"),
        };
        match frame.message_type {
            MessageType::Challenge => {
                let now = now_unix()?;
                let challenge = decode_challenge(&frame.payload, now)
                    .context("Agent report challenge was rejected")?;
                if challenge.agent_session_id != launch.session_id {
                    bail!("Agent report challenge is bound to another session");
                }
                let snapshot = inspect_executable(&state.game)
                    .context("failed to refresh protected executable evidence")?;
                if snapshot.executable_sha256 != state.hello.build_id {
                    bail!("protected executable changed after launch");
                }
                let mut observations = vec![
                    observation("agent.platform", &snapshot.platform),
                    observation("agent.process_id", &std::process::id().to_string()),
                    observation("game.process_id", &state.game_process_id.to_string()),
                    observation(
                        "agent.debugger_observed",
                        if snapshot.debugger_observed {
                            "true"
                        } else {
                            "false"
                        },
                    ),
                    observation("agent.probe_health", "connected"),
                ];
                observations.extend(
                    snapshot
                        .loaded_module_basenames
                        .iter()
                        .filter(|module| safe_value(module))
                        .map(|module| observation("agent.module", module)),
                );
                let report = sign_report(
                    AgentIntegrityReportV1 {
                        protocol_version: PROTOCOL_VERSION,
                        agent_session_id: launch.session_id.clone(),
                        sequence,
                        challenge_nonce: challenge.nonce,
                        observed_at_unix: now,
                        build_id: launch.build_id.clone(),
                        executable_sha256: hex::decode(&snapshot.executable_sha256)
                            .context("executable digest is invalid")?,
                        observations,
                        previous_report_digest: previous_digest.to_vec(),
                        signature: vec![],
                    },
                    &state.key,
                )?;
                previous_digest = report_digest(&report);
                sequence = sequence
                    .checked_add(1)
                    .context("Agent report sequence exhausted")?;
                write_frame(
                    writer,
                    &Frame {
                        message_type: MessageType::IntegrityReport,
                        payload: report.encode_to_vec(),
                    },
                )
                .context("failed to return signed Agent report")?;
            }
            MessageType::Shutdown => {
                if !frame.payload.is_empty() {
                    bail!("Agent shutdown frame must be empty");
                }
                return Ok(());
            }
            _ => bail!("unexpected Agent channel message after admission"),
        }
    }
}

fn observation(code: &str, value: &str) -> IntegrityObservationV1 {
    IntegrityObservationV1 {
        code: code.to_owned(),
        value: value.to_owned(),
    }
}

fn safe_value(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
}

fn now_unix() -> Result<i64> {
    Ok(i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before Unix epoch")?
            .as_secs(),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use certael_agent_ipc::{read_frame, write_frame};
    use certael_agent_protocol::{
        verify_report, AgentLaunchBundleV1, AgentLaunchGrantClaimsV1, AgentPolicyClaimsV1,
        AgentReportChallengeV1, AgentRequirementModeV1, SignedAgentLaunchGrantV1,
        SignedAgentPolicyV1, VerificationKey, LAUNCH_DOMAIN, POLICY_DOMAIN,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;
    use sha2::{Digest, Sha256};
    use std::io::Cursor;

    #[test]
    fn serves_verified_bundle_and_returns_chained_signed_report() {
        let now = now_unix().unwrap();
        let root = SigningKey::generate(&mut OsRng);
        let agent = SigningKey::generate(&mut OsRng);
        let game = std::env::current_exe().unwrap();
        let snapshot = inspect_executable(&game).unwrap();
        let policy_claims = AgentPolicyClaimsV1 {
            protocol_version: 1,
            policy_id: "competitive".into(),
            game_id: "game".into(),
            environment_id: "test".into(),
            requirement_mode: AgentRequirementModeV1::Required as i32,
            heartbeat_seconds: 15,
            report_seconds: 60,
            disconnect_grace_seconds: 30,
            minimum_agent_version: env!("CARGO_PKG_VERSION").into(),
            expires_at_unix: now + 3600,
        };
        let policy_claim_bytes = policy_claims.encode_to_vec();
        let policy = SignedAgentPolicyV1 {
            claims: policy_claim_bytes.clone(),
            signature: root
                .sign(&[POLICY_DOMAIN, &policy_claim_bytes].concat())
                .to_bytes()
                .to_vec(),
            key_id: "root".into(),
        }
        .encode_to_vec();
        let grant_claims = AgentLaunchGrantClaimsV1 {
            protocol_version: 1,
            grant_id: "session".into(),
            tenant_id: "tenant".into(),
            game_id: "game".into(),
            environment_id: "test".into(),
            player_subject: "player".into(),
            match_id: "match".into(),
            build_id: snapshot.executable_sha256.clone(),
            agent_public_key: agent.verifying_key().to_bytes().to_vec(),
            issued_at_unix: now,
            expires_at_unix: now + 60,
            policy_digest: Sha256::digest(&policy).to_vec(),
            authoritative_server_id: "server".into(),
        };
        let grant_claim_bytes = grant_claims.encode_to_vec();
        let grant = SignedAgentLaunchGrantV1 {
            claims: grant_claim_bytes.clone(),
            signature: root
                .sign(&[LAUNCH_DOMAIN, &grant_claim_bytes].concat())
                .to_bytes()
                .to_vec(),
            key_id: "root".into(),
        }
        .encode_to_vec();
        let mut input = vec![];
        write_frame(
            &mut input,
            &Frame {
                message_type: MessageType::LaunchGrant,
                payload: AgentLaunchBundleV1 {
                    signed_policy: policy,
                    signed_launch_grant: grant,
                }
                .encode_to_vec(),
            },
        )
        .unwrap();
        write_frame(
            &mut input,
            &Frame {
                message_type: MessageType::Challenge,
                payload: AgentReportChallengeV1 {
                    agent_session_id: "session".into(),
                    nonce: vec![9; 32],
                    expires_at_unix: now + 30,
                }
                .encode_to_vec(),
            },
        )
        .unwrap();
        write_frame(
            &mut input,
            &Frame {
                message_type: MessageType::Shutdown,
                payload: vec![],
            },
        )
        .unwrap();
        let state = RuntimeState {
            game,
            game_process_id: 42,
            hello: AgentHelloV1 {
                protocol_version: 1,
                agent_version: env!("CARGO_PKG_VERSION").into(),
                agent_public_key: agent.verifying_key().to_bytes().to_vec(),
                build_id: snapshot.executable_sha256.clone(),
                executable_sha256: hex::decode(&snapshot.executable_sha256).unwrap(),
            },
            key: agent,
            trust: VerificationKeyRing::new(vec![VerificationKey {
                key_id: "root".into(),
                key: root.verifying_key(),
                not_before_unix: now - 60,
                not_after_unix: now + 3600,
                revoked: false,
            }])
            .unwrap(),
        };
        let mut output = vec![];
        serve(&mut Cursor::new(input), &mut output, &state).unwrap();
        let mut output = Cursor::new(output);
        assert_eq!(
            read_frame(&mut output).unwrap().message_type,
            MessageType::AgentHello
        );
        let report_frame = read_frame(&mut output).unwrap();
        assert_eq!(report_frame.message_type, MessageType::IntegrityReport);
        let report = AgentIntegrityReportV1::decode(report_frame.payload.as_slice()).unwrap();
        assert_eq!(report.agent_session_id, "session");
        assert_eq!(report.previous_report_digest, vec![0; 32]);
        verify_report(&report, &state.key.verifying_key()).unwrap();
    }
}
