use sha2::{Digest, Sha256};
#[cfg(any(unix, windows))]
use std::sync::Mutex;
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    slice,
};

pub const CERTAEL_PROBE_ABI_VERSION: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertaelProbeResult {
    Ok = 0,
    InvalidArgument = 1,
    BufferTooSmall = 2,
    NotConnected = 3,
    InvalidFrame = 4,
    UnsupportedPlatform = 5,
    InternalError = 255,
}

pub struct CertaelAgentChannel {
    #[cfg(any(unix, windows))]
    state: Mutex<ChannelState>,
    #[cfg(not(any(unix, windows)))]
    _private: (),
}

#[cfg(any(unix, windows))]
struct ChannelState {
    #[cfg(unix)]
    file: std::fs::File,
    #[cfg(windows)]
    read_file: std::fs::File,
    #[cfg(windows)]
    write_file: std::fs::File,
    pending: Option<certael_agent_ipc::Frame>,
}

#[no_mangle]
pub extern "C" fn certael_probe_abi_version() -> u32 {
    CERTAEL_PROBE_ABI_VERSION
}

#[no_mangle]
/// Binds an Agent nonce to this probe ABI.
///
/// # Safety
/// `nonce` must point to `nonce_len` readable bytes and `output` must point to
/// `output_len` writable bytes for the duration of the call. The regions must
/// not overlap.
pub unsafe extern "C" fn certael_probe_bind_nonce(
    nonce: *const u8,
    nonce_len: usize,
    output: *mut u8,
    output_len: usize,
) -> CertaelProbeResult {
    catch_unwind(AssertUnwindSafe(|| {
        if nonce.is_null() || output.is_null() || !(16..=256).contains(&nonce_len) {
            return CertaelProbeResult::InvalidArgument;
        }
        if output_len < 32 {
            return CertaelProbeResult::BufferTooSmall;
        }
        let nonce = slice::from_raw_parts(nonce, nonce_len);
        let digest = Sha256::digest([b"certael.agent.probe.v1\0".as_slice(), nonce].concat());
        std::ptr::copy_nonoverlapping(digest.as_ptr(), output, 32);
        CertaelProbeResult::Ok
    }))
    .unwrap_or(CertaelProbeResult::InternalError)
}

/// Opens the private channel inherited from Certael Agent.
///
/// # Safety
/// `output` must point to writable storage for one channel pointer. The caller
/// owns the returned channel and must destroy it exactly once.
#[no_mangle]
pub unsafe extern "C" fn certael_agent_channel_open(
    output: *mut *mut CertaelAgentChannel,
) -> CertaelProbeResult {
    catch_unwind(AssertUnwindSafe(|| {
        if output.is_null() {
            return CertaelProbeResult::InvalidArgument;
        }
        #[cfg(unix)]
        {
            use std::os::fd::FromRawFd;
            let Ok(raw) = std::env::var("CERTAEL_AGENT_FD") else {
                return CertaelProbeResult::NotConnected;
            };
            let Ok(fd) = raw.parse::<std::os::fd::RawFd>() else {
                return CertaelProbeResult::NotConnected;
            };
            if fd < 0 {
                return CertaelProbeResult::NotConnected;
            }
            std::env::remove_var("CERTAEL_AGENT_FD");
            let channel = Box::new(CertaelAgentChannel {
                state: Mutex::new(ChannelState {
                    file: std::fs::File::from_raw_fd(fd),
                    pending: None,
                }),
            });
            output.write(Box::into_raw(channel));
            CertaelProbeResult::Ok
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::FromRawHandle;
            let (Ok(raw_read), Ok(raw_write)) = (
                std::env::var("CERTAEL_AGENT_READ_HANDLE"),
                std::env::var("CERTAEL_AGENT_WRITE_HANDLE"),
            ) else {
                return CertaelProbeResult::NotConnected;
            };
            let (Ok(read_handle), Ok(write_handle)) =
                (raw_read.parse::<usize>(), raw_write.parse::<usize>())
            else {
                return CertaelProbeResult::NotConnected;
            };
            if read_handle == 0 || write_handle == 0 || read_handle == write_handle {
                return CertaelProbeResult::NotConnected;
            }
            std::env::remove_var("CERTAEL_AGENT_READ_HANDLE");
            std::env::remove_var("CERTAEL_AGENT_WRITE_HANDLE");
            let channel = Box::new(CertaelAgentChannel {
                state: Mutex::new(ChannelState {
                    read_file: std::fs::File::from_raw_handle(read_handle as *mut _),
                    write_file: std::fs::File::from_raw_handle(write_handle as *mut _),
                    pending: None,
                }),
            });
            output.write(Box::into_raw(channel));
            CertaelProbeResult::Ok
        }
        #[cfg(not(any(unix, windows)))]
        {
            output.write(std::ptr::null_mut());
            CertaelProbeResult::UnsupportedPlatform
        }
    }))
    .unwrap_or(CertaelProbeResult::InternalError)
}

/// Reads one typed frame without losing it when the caller's buffer is small.
///
/// # Safety
/// `channel` must be a live pointer returned by `certael_agent_channel_open`.
/// `message_type` and `written` must be writable. When `capacity` is nonzero,
/// `output` must point to `capacity` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn certael_agent_channel_read(
    channel: *mut CertaelAgentChannel,
    message_type: *mut u8,
    output: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> CertaelProbeResult {
    catch_unwind(AssertUnwindSafe(|| {
        if channel.is_null()
            || message_type.is_null()
            || written.is_null()
            || (capacity > 0 && output.is_null())
        {
            return CertaelProbeResult::InvalidArgument;
        }
        #[cfg(not(any(unix, windows)))]
        return CertaelProbeResult::UnsupportedPlatform;
        #[cfg(any(unix, windows))]
        {
            let channel = &*channel;
            let Ok(mut state) = channel.state.lock() else {
                return CertaelProbeResult::InternalError;
            };
            if state.pending.is_none() {
                #[cfg(unix)]
                let result = certael_agent_ipc::read_frame(&mut state.file);
                #[cfg(windows)]
                let result = certael_agent_ipc::read_frame(&mut state.read_file);
                state.pending = match result {
                    Ok(frame) => Some(frame),
                    Err(_) => return CertaelProbeResult::InvalidFrame,
                };
            }
            let frame = state.pending.as_ref().expect("pending frame");
            written.write(frame.payload.len());
            message_type.write(frame.message_type as u8);
            if capacity < frame.payload.len() {
                return CertaelProbeResult::BufferTooSmall;
            }
            if !frame.payload.is_empty() {
                std::ptr::copy_nonoverlapping(frame.payload.as_ptr(), output, frame.payload.len());
            }
            state.pending = None;
            CertaelProbeResult::Ok
        }
    }))
    .unwrap_or(CertaelProbeResult::InternalError)
}

/// Writes one typed frame to the Agent channel.
///
/// # Safety
/// `channel` must be live. When `payload_len` is nonzero, `payload` must point
/// to `payload_len` readable bytes for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn certael_agent_channel_write(
    channel: *mut CertaelAgentChannel,
    message_type: u8,
    payload: *const u8,
    payload_len: usize,
) -> CertaelProbeResult {
    catch_unwind(AssertUnwindSafe(|| {
        if channel.is_null() || (payload_len > 0 && payload.is_null()) {
            return CertaelProbeResult::InvalidArgument;
        }
        let Ok(message_type) = certael_agent_ipc::MessageType::try_from(message_type) else {
            return CertaelProbeResult::InvalidArgument;
        };
        if payload_len > certael_agent_ipc::MAX_FRAME_PAYLOAD {
            return CertaelProbeResult::InvalidArgument;
        }
        #[cfg(not(any(unix, windows)))]
        return CertaelProbeResult::UnsupportedPlatform;
        #[cfg(any(unix, windows))]
        {
            let channel = &*channel;
            let Ok(mut state) = channel.state.lock() else {
                return CertaelProbeResult::InternalError;
            };
            let payload = if payload_len == 0 {
                &[]
            } else {
                slice::from_raw_parts(payload, payload_len)
            };
            let frame = certael_agent_ipc::Frame {
                message_type,
                payload: payload.to_vec(),
            };
            #[cfg(unix)]
            let result = certael_agent_ipc::write_frame(&mut state.file, &frame);
            #[cfg(windows)]
            let result = certael_agent_ipc::write_frame(&mut state.write_file, &frame);
            match result {
                Ok(()) => CertaelProbeResult::Ok,
                Err(_) => CertaelProbeResult::InvalidFrame,
            }
        }
    }))
    .unwrap_or(CertaelProbeResult::InternalError)
}

/// Destroys a channel created by `certael_agent_channel_open`.
///
/// # Safety
/// `channel` must be null or a live pointer returned by
/// `certael_agent_channel_open`, and it must not be used again after this call.
#[no_mangle]
pub unsafe extern "C" fn certael_agent_channel_destroy(channel: *mut CertaelAgentChannel) {
    if channel.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| drop(Box::from_raw(channel))));
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn binds_valid_nonce() {
        let nonce = [3_u8; 32];
        let mut output = [0_u8; 32];
        let result = unsafe {
            certael_probe_bind_nonce(
                nonce.as_ptr(),
                nonce.len(),
                output.as_mut_ptr(),
                output.len(),
            )
        };
        assert_eq!(result, CertaelProbeResult::Ok);
        assert_ne!(output, [0; 32]);
    }

    #[cfg(unix)]
    #[test]
    fn channel_preserves_frame_when_buffer_is_too_small() {
        use certael_agent_ipc::{write_frame, Frame, MessageType};
        use std::os::fd::{FromRawFd, IntoRawFd};
        let (mut writer, reader) = std::os::unix::net::UnixStream::pair().unwrap();
        write_frame(
            &mut writer,
            &Frame {
                message_type: MessageType::AgentHello,
                payload: vec![1, 2, 3, 4],
            },
        )
        .unwrap();
        let channel = Box::into_raw(Box::new(CertaelAgentChannel {
            state: Mutex::new(ChannelState {
                file: unsafe { std::fs::File::from_raw_fd(reader.into_raw_fd()) },
                pending: None,
            }),
        }));
        let mut message_type = 0;
        let mut written = 0;
        let mut short = [0_u8; 2];
        assert_eq!(
            unsafe {
                certael_agent_channel_read(
                    channel,
                    &mut message_type,
                    short.as_mut_ptr(),
                    short.len(),
                    &mut written,
                )
            },
            CertaelProbeResult::BufferTooSmall
        );
        assert_eq!(written, 4);
        let mut complete = [0_u8; 4];
        assert_eq!(
            unsafe {
                certael_agent_channel_read(
                    channel,
                    &mut message_type,
                    complete.as_mut_ptr(),
                    complete.len(),
                    &mut written,
                )
            },
            CertaelProbeResult::Ok
        );
        assert_eq!(message_type, MessageType::AgentHello as u8);
        assert_eq!(complete, [1, 2, 3, 4]);
        let response = [8_u8, 9];
        assert_eq!(
            unsafe {
                certael_agent_channel_write(
                    channel,
                    MessageType::Challenge as u8,
                    response.as_ptr(),
                    response.len(),
                )
            },
            CertaelProbeResult::Ok
        );
        let received = certael_agent_ipc::read_frame(&mut writer).unwrap();
        assert_eq!(received.message_type, MessageType::Challenge);
        assert_eq!(received.payload, response);
        unsafe { certael_agent_channel_destroy(channel) };
    }
}
