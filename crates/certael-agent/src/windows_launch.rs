use anyhow::{bail, Context, Result};
use certael_agent_ipc::{write_frame, Frame, MessageType};
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
        Pipes::CreatePipe,
        Threading::{
            CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
            InitializeProcThreadAttributeList, UpdateProcThreadAttribute, WaitForSingleObject,
            CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT, INFINITE,
            PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTUPINFOEXW,
        },
    },
};

pub fn launch(game: PathBuf, args: Vec<String>, hello: Vec<u8>) -> Result<()> {
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
        InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut attribute_bytes);
    }
    if attribute_bytes == 0 {
        bail!("Windows did not provide an attribute-list size");
    }
    let words = attribute_bytes.div_ceil(std::mem::size_of::<usize>());
    let mut attribute_storage = vec![0_usize; words];
    let attribute_list = attribute_storage.as_mut_ptr().cast();
    if unsafe { InitializeProcThreadAttributeList(attribute_list, 1, 0, &mut attribute_bytes) } == 0
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
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
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
    drop(game_read);
    drop(game_write);

    let mut outbound = unsafe { std::fs::File::from_raw_handle(agent_write.take() as *mut _) };
    let _inbound = unsafe { std::fs::File::from_raw_handle(agent_read.take() as *mut _) };
    write_frame(
        &mut outbound,
        &Frame {
            message_type: MessageType::AgentHello,
            payload: hello,
        },
    )
    .context("failed to bootstrap protected game")?;
    drop(outbound);

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
    let mut values: Vec<(String, String)> = std::env::vars_os()
        .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)))
        .filter(|(key, _)| {
            key != "CERTAEL_AGENT_READ_HANDLE" && key != "CERTAEL_AGENT_WRITE_HANDLE"
        })
        .collect();
    values.push((
        "CERTAEL_AGENT_READ_HANDLE".into(),
        (read as usize).to_string(),
    ));
    values.push((
        "CERTAEL_AGENT_WRITE_HANDLE".into(),
        (write as usize).to_string(),
    ));
    values.sort_by_key(|(key, _)| key.to_uppercase());
    let mut block = Vec::new();
    for (key, value) in values {
        if key.contains('=') || key.contains('\0') || value.contains('\0') {
            bail!("process environment contains an invalid entry");
        }
        block.extend(OsStr::new(&format!("{key}={value}")).encode_wide());
        block.push(0);
    }
    block.push(0);
    Ok(block)
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
    #[test]
    fn quotes_windows_arguments() {
        assert_eq!(quote("plain"), "plain");
        assert_eq!(quote("two words"), "\"two words\"");
        assert_eq!(quote("a\\\"b"), "\"a\\\\\\\"b\"");
        assert_eq!(quote("trailing\\"), "trailing\\");
    }
}
