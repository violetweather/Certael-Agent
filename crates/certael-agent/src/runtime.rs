use anyhow::{bail, Context, Result};
use certael_agent_ipc::{read_frame, write_frame, Frame, IpcError, MessageType};
use certael_agent_platform::{
    inspect_executable, inspect_game_process_bound, verify_build_manifest as verify_files,
    ProtectedBuildFile, ProtectedBuildManifest,
};
use certael_agent_protocol::{
    decode_challenge, report_digest, sign_report, verify_launch_bundle, verify_revocation,
    AgentHealthV1, AgentHelloV1, AgentIntegrityReportV1, IntegrityObservationV1,
    SignedAgentRevocationV1, VerificationKeyRing, PROTOCOL_VERSION,
};
use ed25519_dalek::SigningKey;
use prost::Message;
use std::{
    io::{Read, Write},
    path::PathBuf,
    sync::mpsc,
    thread,
    time::Duration,
    time::{SystemTime, UNIX_EPOCH},
};

pub struct RuntimeState {
    pub game: PathBuf,
    pub game_root: PathBuf,
    pub game_process_id: u32,
    pub game_process_identity: Option<u64>,
    pub key: SigningKey,
    pub hello: AgentHelloV1,
    pub trust: VerificationKeyRing,
    pub registration: Option<RegistrationBinding>,
}

pub struct RegistrationBinding {
    pub registration_id: String,
    pub tenant_id: String,
    pub game_id: String,
    pub environment_id: String,
    pub status_path: PathBuf,
}

pub fn serve(
    mut reader: impl Read + Send + 'static,
    mut writer: impl Write,
    state: &RuntimeState,
) -> Result<()> {
    write_frame(
        &mut writer,
        &Frame {
            message_type: MessageType::AgentHello,
            payload: state.hello.encode_to_vec(),
        },
    )
    .context("failed to send Agent hello")?;
    publish_runtime(state, "awaiting_admission", None);
    let (frames, incoming) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("certael-agent-ipc".into())
        .spawn(move || loop {
            let frame = read_frame(&mut reader);
            let finished = frame.is_err();
            if frames.send(frame).is_err() || finished {
                break;
            }
        })
        .context("failed to start bounded Agent channel reader")?;
    let bootstrap = incoming
        .recv_timeout(Duration::from_secs(15))
        .context("protected game did not provide Agent admission in time")?
        .context("protected game closed before Agent admission")?;
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
    if state.registration.as_ref().is_some_and(|registration| {
        registration.tenant_id != launch.tenant_id
            || registration.game_id != launch.game_id
            || registration.environment_id != launch.environment_id
    }) {
        bail!("signed launch bundle does not match the registered game");
    }
    let manifest = ProtectedBuildManifest {
        build_id: launch.build_manifest.build_id.clone(),
        files: launch
            .build_manifest
            .files
            .iter()
            .map(|file| ProtectedBuildFile {
                path: file.path.clone(),
                size: file.size,
                sha256: hex::encode(&file.sha256),
            })
            .collect(),
    };
    let mismatches = verify_files(&state.game_root, &manifest)
        .context("protected build manifest could not be verified")?;
    if !mismatches.is_empty() {
        bail!("protected build does not match its signed manifest");
    }
    write_health(&mut writer, &launch.session_id, "ready", 0, &[])?;
    publish_runtime(state, "protected", None);
    let mut sequence = 1_u64;
    let mut previous_digest = [0_u8; 32];
    let mut last_report_at = 0_i64;
    let mut next_heartbeat = now_unix()? + i64::from(launch.heartbeat_seconds);
    let mut report_deadline =
        now_unix()? + i64::from(launch.report_seconds + launch.disconnect_grace_seconds);
    loop {
        let now = now_unix()?;
        if now >= launch.policy_expires_at_unix {
            write_health(
                &mut writer,
                &launch.session_id,
                "expired",
                last_report_at,
                &["POLICY_EXPIRED"],
            )?;
            publish_runtime(state, "expired", Some("POLICY_EXPIRED"));
            bail!("Agent policy expired");
        }
        if now >= report_deadline {
            write_health(
                &mut writer,
                &launch.session_id,
                "lost",
                last_report_at,
                &["REPORT_DEADLINE_MISSED"],
            )?;
            publish_runtime(state, "lost", Some("REPORT_DEADLINE_MISSED"));
            bail!("Agent report deadline was missed");
        }
        let wake_at = next_heartbeat
            .min(report_deadline)
            .min(launch.policy_expires_at_unix);
        let wait = Duration::from_secs(u64::try_from((wake_at - now).max(1))?);
        let frame = match incoming.recv_timeout(wait) {
            Ok(Ok(value)) => value,
            Ok(Err(IpcError::Io)) => {
                publish_runtime(state, "stopped", Some("GAME_CHANNEL_CLOSED"));
                return Ok(());
            }
            Ok(Err(error)) => return Err(error).context("Agent channel frame was rejected"),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let now = now_unix()?;
                if now >= next_heartbeat && now < report_deadline {
                    write_health(
                        &mut writer,
                        &launch.session_id,
                        "protected",
                        last_report_at,
                        &[],
                    )?;
                    publish_runtime(state, "protected", None);
                    next_heartbeat = now + i64::from(launch.heartbeat_seconds);
                }
                continue;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                publish_runtime(state, "stopped", Some("GAME_CHANNEL_CLOSED"));
                return Ok(());
            }
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
                let game_process = inspect_game_process_bound(
                    state.game_process_id,
                    &state.game,
                    state.game_process_identity,
                );
                let mut observations = vec![
                    observation("agent.platform", &snapshot.platform),
                    observation("agent.process_id", &std::process::id().to_string()),
                    observation("game.process_id", &state.game_process_id.to_string()),
                    observation("game.process_running", bool_value(game_process.running)),
                    observation(
                        "game.executable_matches",
                        bool_value(game_process.executable_matches),
                    ),
                    observation(
                        "game.parent_is_agent",
                        game_process
                            .parent_is_agent
                            .map(bool_value)
                            .unwrap_or("unknown"),
                    ),
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
                if let Some(build_id) = snapshot
                    .executable_build_id
                    .as_deref()
                    .filter(|value| safe_value(value))
                {
                    observations.push(observation("game.elf_build_id", build_id));
                }
                observations.push(observation(
                    "game.process_identity_stable",
                    game_process
                        .process_identity_stable
                        .map(bool_value)
                        .unwrap_or("unknown"),
                ));
                observations.extend(
                    snapshot
                        .loaded_module_basenames
                        .iter()
                        .filter(|module| safe_value(module))
                        .take(96)
                        .map(|module| observation("agent.module", module)),
                );
                observations.extend(
                    game_process
                        .loaded_module_basenames
                        .iter()
                        .filter(|module| safe_value(module))
                        .take(96)
                        .map(|module| observation("game.module", module)),
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
                last_report_at = now;
                report_deadline =
                    now + i64::from(launch.report_seconds + launch.disconnect_grace_seconds);
                sequence = sequence
                    .checked_add(1)
                    .context("Agent report sequence exhausted")?;
                write_frame(
                    &mut writer,
                    &Frame {
                        message_type: MessageType::IntegrityReport,
                        payload: report.encode_to_vec(),
                    },
                )
                .context("failed to return signed Agent report")?;
                publish_runtime(state, "protected", None);
            }
            MessageType::Revocation => {
                let signed = SignedAgentRevocationV1::decode(frame.payload.as_slice())
                    .context("Agent revocation is malformed")?;
                if signed.encode_to_vec() != frame.payload {
                    bail!("Agent revocation is not canonical");
                }
                let revocation = verify_revocation(&signed, &state.trust, now_unix()?)
                    .context("Agent revocation was rejected")?;
                if revocation.agent_session_id != launch.session_id
                    || revocation.tenant_id != launch.tenant_id
                    || revocation.game_id != launch.game_id
                    || revocation.environment_id != launch.environment_id
                {
                    bail!("Agent revocation is bound to another session");
                }
                write_health(
                    &mut writer,
                    &launch.session_id,
                    "revoked",
                    last_report_at,
                    &["SESSION_REVOKED"],
                )?;
                publish_runtime(state, "revoked", Some("SESSION_REVOKED"));
                bail!("Agent session was revoked");
            }
            MessageType::Shutdown => {
                if !frame.payload.is_empty() {
                    bail!("Agent shutdown frame must be empty");
                }
                publish_runtime(state, "stopped", None);
                return Ok(());
            }
            _ => bail!("unexpected Agent channel message after admission"),
        }
    }
}

fn publish_runtime(state: &RuntimeState, runtime_state: &str, reason: Option<&str>) {
    let Some(registration) = &state.registration else {
        return;
    };
    let _ = crate::status::publish(
        &registration.status_path,
        &crate::status::RuntimeStatus {
            format_version: 1,
            registration_id: registration.registration_id.clone(),
            game_id: registration.game_id.clone(),
            state: runtime_state.to_owned(),
            public_reason: reason.map(str::to_owned),
            updated_at_unix: now_unix().unwrap_or(0),
        },
    );
}

fn write_health(
    writer: &mut impl Write,
    session_id: &str,
    state: &str,
    last_report_at_unix: i64,
    reasons: &[&str],
) -> Result<()> {
    write_frame(
        writer,
        &Frame {
            message_type: MessageType::Health,
            payload: AgentHealthV1 {
                agent_session_id: session_id.to_owned(),
                state: state.to_owned(),
                last_report_at_unix,
                public_reasons: reasons.iter().map(|value| (*value).to_owned()).collect(),
            }
            .encode_to_vec(),
        },
    )
    .context("failed to send Agent health state")
}

fn observation(code: &str, value: &str) -> IntegrityObservationV1 {
    IntegrityObservationV1 {
        code: code.to_owned(),
        value: value.to_owned(),
    }
}

fn bool_value(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
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
        AgentReportChallengeV1, AgentRequirementModeV1, BuildManifestClaimsV1,
        ProtectedBuildFileV1, SignedAgentLaunchGrantV1, SignedAgentPolicyV1, SignedBuildManifestV1,
        VerificationKey, BUILD_MANIFEST_DOMAIN, LAUNCH_DOMAIN, POLICY_DOMAIN,
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
            tenant_id: "tenant".into(),
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
        let manifest_claims = BuildManifestClaimsV1 {
            protocol_version: 1,
            manifest_id: "manifest".into(),
            tenant_id: "tenant".into(),
            game_id: "game".into(),
            environment_id: "test".into(),
            build_id: snapshot.executable_sha256.clone(),
            files: vec![ProtectedBuildFileV1 {
                path: game.file_name().unwrap().to_string_lossy().into_owned(),
                size: game.metadata().unwrap().len(),
                sha256: hex::decode(&snapshot.executable_sha256).unwrap(),
            }],
            not_before_unix: now - 60,
            expires_at_unix: now + 3600,
        };
        let manifest_claim_bytes = manifest_claims.encode_to_vec();
        let manifest = SignedBuildManifestV1 {
            claims: manifest_claim_bytes.clone(),
            signature: root
                .sign(&[BUILD_MANIFEST_DOMAIN, &manifest_claim_bytes].concat())
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
            build_manifest_digest: Sha256::digest(&manifest).to_vec(),
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
                    signed_build_manifest: manifest,
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
        let game_root = game.parent().unwrap().to_path_buf();
        let state = RuntimeState {
            game,
            game_root,
            game_process_id: 42,
            game_process_identity: None,
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
            registration: None,
        };
        let mut output = vec![];
        serve(Cursor::new(input), &mut output, &state).unwrap();
        let mut output = Cursor::new(output);
        assert_eq!(
            read_frame(&mut output).unwrap().message_type,
            MessageType::AgentHello
        );
        assert_eq!(
            read_frame(&mut output).unwrap().message_type,
            MessageType::Health
        );
        let report_frame = read_frame(&mut output).unwrap();
        assert_eq!(report_frame.message_type, MessageType::IntegrityReport);
        let report = AgentIntegrityReportV1::decode(report_frame.payload.as_slice()).unwrap();
        assert_eq!(report.agent_session_id, "session");
        assert_eq!(report.previous_report_digest, vec![0; 32]);
        verify_report(&report, &state.key.verifying_key()).unwrap();
    }
}
