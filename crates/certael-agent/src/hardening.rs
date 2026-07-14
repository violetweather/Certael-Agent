use anyhow::{bail, Result};

pub fn apply() -> Result<()> {
    #[cfg(unix)]
    unsafe {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
            bail!("failed to disable Agent core dumps");
        }
    }
    #[cfg(target_os = "linux")]
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            bail!("failed to restrict Agent process-memory access");
        }
    }
    #[cfg(windows)]
    apply_windows()?;
    Ok(())
}

#[cfg(windows)]
fn apply_windows() -> Result<()> {
    use windows_sys::Win32::System::Threading::{
        ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy, ProcessStrictHandleCheckPolicy,
        SetProcessDEPPolicy, SetProcessMitigationPolicy, PROCESS_DEP_ENABLE,
    };
    if unsafe { SetProcessDEPPolicy(PROCESS_DEP_ENABLE) } == 0 {
        bail!("failed to enable Agent DEP policy");
    }
    for (policy, flags, reason) in [
        (
            ProcessStrictHandleCheckPolicy,
            3_u32,
            "strict-handle checks",
        ),
        (
            ProcessExtensionPointDisablePolicy,
            1_u32,
            "extension-point disablement",
        ),
        (ProcessImageLoadPolicy, 7_u32, "safe image-loading policy"),
    ] {
        if unsafe {
            SetProcessMitigationPolicy(
                policy,
                (&flags as *const u32).cast(),
                std::mem::size_of::<u32>(),
            )
        } == 0
        {
            bail!("failed to enable Agent {reason}");
        }
    }
    Ok(())
}
