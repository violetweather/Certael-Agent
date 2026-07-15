use crate::runtime::{self, RuntimeState};
use anyhow::{bail, Context, Result};
use std::{
    ffi::OsStr,
    os::windows::{ffi::OsStrExt, io::FromRawHandle},
    path::{Path, PathBuf},
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, GetLastError, SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, WAIT_OBJECT_0,
    },
    Security::SECURITY_ATTRIBUTES,
    System::{
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        },
        Pipes::CreatePipe,
        Threading::{
            CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
            InitializeProcThreadAttributeList, ResumeThread, UpdateProcThreadAttribute,
            WaitForSingleObject, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
            EXTENDED_STARTUPINFO_PRESENT, INFINITE, PROCESS_INFORMATION,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
            STARTUPINFOEXW,
        },
    },
};

pub fn launch(game: PathBuf, args: Vec<String>, mut state: RuntimeState) -> Result<()> {
    let mut security = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    let (game_read, mut agent_write) = create_pipe(&mut security)?;
    let (mut agent_read, game_write) = create_pipe(&mut security)?;
    clear_inheritance(agent_write.raw())?;
    clear_inheritance(agent_read.raw())?;

    let child_handles = [game_read.raw(), game_write.raw()];
    let mut attribute_bytes = 0;
    unsafe {
        InitializeProcThreadAttributeList(std::ptr::null_mut(), 2, 0, &mut attribute_bytes);
    }
    if attribute_bytes == 0 {
        bail!("Windows did not provide an attribute-list size");
    }
    let words = attribute_bytes.div_ceil(std::mem::size_of::<usize>());
    let mut attribute_storage = vec![0_usize; words];
    let attribute_list = attribute_storage.as_mut_ptr().cast();
    if unsafe { InitializeProcThreadAttributeList(attribute_list, 2, 0, &mut attribute_bytes) } == 0
    {
        bail!("failed to initialize process attributes: {}", unsafe {
            GetLastError()
        });
    }
    let _attributes = AttributeList(attribute_list);
    if unsafe {
        UpdateProcThreadAttribute(
            attribute_list,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            child_handles.as_ptr().cast(),
            std::mem::size_of_val(&child_handles),
            std::ptr::null_mut(),
            std::ptr::null(),
        )
    } == 0
    {
        bail!("failed to restrict inherited handles: {}", unsafe {
            GetLastError()
        });
    }
    // Conservative process mitigations that do not prohibit engines from JITing,
    // loading game plugins, or using graphics APIs. Security-sensitive projects
    // may add stricter per-game policy after compatibility testing.
    const DEP_ENABLE: u64 = 0x0000_0001;
    const SEHOP_ENABLE: u64 = 0x0000_0004;
    const FORCE_RELOCATE_IMAGES_ALWAYS_ON: u64 = 0x0000_0100;
    const HEAP_TERMINATE_ALWAYS_ON: u64 = 0x0000_1000;
    const BOTTOM_UP_ASLR_ALWAYS_ON: u64 = 0x0001_0000;
    const HIGH_ENTROPY_ASLR_ALWAYS_ON: u64 = 0x0010_0000;
    const STRICT_HANDLE_CHECKS_ALWAYS_ON: u64 = 0x0100_0000;
    let mut mitigation_policy = DEP_ENABLE
        | SEHOP_ENABLE
        | FORCE_RELOCATE_IMAGES_ALWAYS_ON
        | HEAP_TERMINATE_ALWAYS_ON
        | BOTTOM_UP_ASLR_ALWAYS_ON
        | HIGH_ENTROPY_ASLR_ALWAYS_ON
        | STRICT_HANDLE_CHECKS_ALWAYS_ON;
    if unsafe {
        UpdateProcThreadAttribute(
            attribute_list,
            0,
            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY as usize,
            (&mut mitigation_policy as *mut u64).cast(),
            std::mem::size_of::<u64>(),
            std::ptr::null_mut(),
            std::ptr::null(),
        )
    } == 0
    {
        bail!(
            "failed to apply protected-game process mitigations: {}",
            unsafe { GetLastError() }
        );
    }

    let mut command_line = wide(windows_command_line(&game, &args));
    let application = wide(game.as_os_str());
    let mut environment = environment_block(game_read.raw(), game_write.raw())?;
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.lpAttributeList = attribute_list;
    let mut process = PROCESS_INFORMATION::default();
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(),
            command_line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
            environment.as_mut_ptr().cast(),
            std::ptr::null(),
            (&startup.StartupInfo) as *const _,
            &mut process,
        )
    };
    if created == 0 {
        bail!("failed to launch protected game: {}", unsafe {
            GetLastError()
        });
    }
    let process_handle = OwnedHandle(process.hProcess);
    let _thread_handle = OwnedHandle(process.hThread);
    let job = create_containment_job()?;
    if unsafe { AssignProcessToJobObject(job.raw(), process_handle.raw()) } == 0 {
        bail!("failed to contain protected game: {}", unsafe {
            GetLastError()
        });
    }
    if unsafe { ResumeThread(_thread_handle.raw()) } == u32::MAX {
        bail!("failed to resume contained game: {}", unsafe {
            GetLastError()
        });
    }
    state.game_process_id = process.dwProcessId;
    state.game_process_identity = certael_agent_platform::process_identity(process.dwProcessId);
    drop(game_read);
    drop(game_write);

    let mut outbound = unsafe { std::fs::File::from_raw_handle(agent_write.take() as *mut _) };
    let mut inbound = unsafe { std::fs::File::from_raw_handle(agent_read.take() as *mut _) };
    runtime::serve(inbound, &mut outbound, &state).context("protected Agent session failed")?;
    drop(outbound);
    drop(inbound);

    if unsafe { WaitForSingleObject(process_handle.raw(), INFINITE) } != WAIT_OBJECT_0 {
        bail!("failed while waiting for protected game");
    }
    let mut exit_code = 0;
    if unsafe { GetExitCodeProcess(process_handle.raw(), &mut exit_code) } == 0 {
        bail!("failed to read protected game exit code");
    }
    if exit_code != 0 {
        bail!("game exited unsuccessfully with code {exit_code}");
    }
    Ok(())
}

fn create_containment_job() -> Result<OwnedHandle> {
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job.is_null() {
        bail!("failed to create game containment job: {}", unsafe {
            GetLastError()
        });
    }
    let job = OwnedHandle(job);
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if unsafe {
        SetInformationJobObject(
            job.raw(),
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    } == 0
    {
        bail!("failed to configure game containment job: {}", unsafe {
            GetLastError()
        });
    }
    Ok(job)
}

fn create_pipe(security: &mut SECURITY_ATTRIBUTES) -> Result<(OwnedHandle, OwnedHandle)> {
    let mut read: HANDLE = std::ptr::null_mut();
    let mut write: HANDLE = std::ptr::null_mut();
    if unsafe { CreatePipe(&mut read, &mut write, security, 64 * 1024) } == 0 {
        bail!("failed to create inherited Agent pipe: {}", unsafe {
            GetLastError()
        });
    }
    Ok((OwnedHandle(read), OwnedHandle(write)))
}

fn clear_inheritance(handle: HANDLE) -> Result<()> {
    if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0 {
        bail!("failed to secure Agent pipe handle: {}", unsafe {
            GetLastError()
        });
    }
    Ok(())
}

fn environment_block(read: HANDLE, write: HANDLE) -> Result<Vec<u16>> {
    let values: Vec<(String, String)> = std::env::vars_os()
        .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)))
        .collect();
    environment_block_from(values, read as usize, write as usize)
}

fn environment_block_from(
    mut values: Vec<(String, String)>,
    read: usize,
    write: usize,
) -> Result<Vec<u16>> {
    values.retain(|(key, _)| {
        !key.eq_ignore_ascii_case("CERTAEL_AGENT_READ_HANDLE")
            && !key.eq_ignore_ascii_case("CERTAEL_AGENT_WRITE_HANDLE")
    });
    values.push(("CERTAEL_AGENT_READ_HANDLE".into(), read.to_string()));
    values.push(("CERTAEL_AGENT_WRITE_HANDLE".into(), write.to_string()));
    values.sort_by_key(|(key, _)| key.to_uppercase());
    let mut block = Vec::new();
    for (key, value) in values {
        // Windows uses special entries such as `=C:=C:\\directory` to carry
        // each drive's current directory into a child process. They are part
        // of the environment block even though ordinary variable names may
        // not contain `=`.
        let drive_current_directory = is_drive_current_directory_key(&key);
        if key.is_empty()
            || (!drive_current_directory && key.contains('='))
            || key.contains('\0')
            || value.contains('\0')
        {
            bail!("process environment contains an invalid entry");
        }
        block.extend(OsStr::new(&format!("{key}={value}")).encode_wide());
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

fn is_drive_current_directory_key(key: &str) -> bool {
    let bytes = key.as_bytes();
    bytes.len() == 3 && bytes[0] == b'=' && bytes[1].is_ascii_alphabetic() && bytes[2] == b':'
}

fn windows_command_line(game: &Path, args: &[String]) -> String {
    std::iter::once(game.to_string_lossy().into_owned())
        .chain(args.iter().cloned())
        .map(|value| quote(&value))
        .collect::<Vec<_>>()
        .join(" ")
}

fn quote(value: &str) -> String {
    if !value.is_empty()
        && !value
            .bytes()
            .any(|byte| matches!(byte, b' ' | b'\t' | b'"'))
    {
        return value.to_owned();
    }
    let mut output = String::from("\"");
    let mut slashes = 0;
    for character in value.chars() {
        if character == '\\' {
            slashes += 1;
            continue;
        }
        if character == '"' {
            output.push_str(&"\\".repeat(slashes * 2 + 1));
        } else {
            output.push_str(&"\\".repeat(slashes));
        }
        slashes = 0;
        output.push(character);
    }
    output.push_str(&"\\".repeat(slashes * 2));
    output.push('"');
    output
}

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value
        .as_ref()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

struct OwnedHandle(HANDLE);
impl OwnedHandle {
    fn raw(&self) -> HANDLE {
        self.0
    }
    fn take(&mut self) -> HANDLE {
        let value = self.0;
        self.0 = std::ptr::null_mut();
        value
    }
}
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

struct AttributeList(windows_sys::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST);
impl Drop for AttributeList {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_environment_block(block: &[u16]) -> Vec<String> {
        block[..block.len() - 1]
            .split(|word| *word == 0)
            .map(String::from_utf16)
            .collect::<std::result::Result<Vec<_>, _>>()
            .expect("environment block should contain valid UTF-16")
    }

    #[test]
    fn quotes_windows_arguments() {
        assert_eq!(quote("plain"), "plain");
        assert_eq!(quote("two words"), "\"two words\"");
        assert_eq!(quote("a\\\"b"), "\"a\\\\\\\"b\"");
        assert_eq!(quote("trailing\\"), "trailing\\");
    }

    #[test]
    fn preserves_drive_current_directories() {
        let block = environment_block_from(
            vec![
                ("Path".into(), r"C:\Windows\System32".into()),
                ("=C:".into(), r"C:\Games\Certael".into()),
                ("certael_agent_read_handle".into(), "attacker".into()),
            ],
            123,
            456,
        )
        .expect("Windows drive-current-directory entries should be accepted");
        let entries = decode_environment_block(&block);

        assert!(entries.contains(&r"=C:=C:\Games\Certael".to_owned()));
        assert!(entries.contains(&"CERTAEL_AGENT_READ_HANDLE=123".to_owned()));
        assert!(entries.contains(&"CERTAEL_AGENT_WRITE_HANDLE=456".to_owned()));
        assert!(!entries.iter().any(|entry| entry.ends_with("=attacker")));
        assert_eq!(block.last(), Some(&0));
        assert_eq!(block[block.len() - 2], 0);
    }

    #[test]
    fn rejects_other_equals_signs_in_environment_keys() {
        for key in ["", "INVALID=KEY", "=CC:", "=C:extra", "=1:", "="] {
            assert!(
                environment_block_from(vec![(key.into(), "value".into())], 123, 456).is_err(),
                "unexpectedly accepted environment key {key:?}"
            );
        }
    }
}
