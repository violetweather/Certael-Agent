use sha2::{Digest, Sha256};
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
    InternalError = 255,
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
}
