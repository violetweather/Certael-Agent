use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegritySnapshot {
    pub executable_name: String,
    pub executable_sha256: String,
    pub executable_size: u64,
    pub debugger_observed: bool,
    pub platform: String,
    pub process_id: u32,
    pub loaded_module_basenames: Vec<String>,
    pub executable_build_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GameProcessSnapshot {
    pub running: bool,
    pub executable_matches: bool,
    pub parent_is_agent: Option<bool>,
    pub loaded_module_basenames: Vec<String>,
    pub process_identity_stable: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtectedBuildFile {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtectedBuildManifest {
    pub build_id: String,
    pub files: Vec<ProtectedBuildFile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestMismatch {
    pub path: String,
    pub reason: &'static str,
}

pub fn verify_build_manifest(
    root: &Path,
    manifest: &ProtectedBuildManifest,
) -> Result<Vec<ManifestMismatch>> {
    let canonical_root = root.canonicalize().context("game root does not exist")?;
    if !canonical_root.is_dir()
        || manifest.build_id.is_empty()
        || manifest.build_id.len() > 128
        || manifest.files.is_empty()
        || manifest.files.len() > 16_384
    {
        bail!("build manifest is invalid");
    }
    let mut seen = BTreeSet::new();
    let mut mismatches = Vec::new();
    for expected in &manifest.files {
        if !safe_relative_path(&expected.path)
            || expected.sha256.len() != 64
            || !expected
                .sha256
                .bytes()
                .all(|value| value.is_ascii_hexdigit())
            || !seen.insert(expected.path.clone())
        {
            bail!("build manifest contains an invalid file entry");
        }
        let candidate = canonical_root.join(&expected.path);
        let Ok(link_metadata) = std::fs::symlink_metadata(&candidate) else {
            mismatches.push(ManifestMismatch {
                path: expected.path.clone(),
                reason: "MISSING",
            });
            continue;
        };
        if link_metadata.file_type().is_symlink() || !link_metadata.is_file() {
            mismatches.push(ManifestMismatch {
                path: expected.path.clone(),
                reason: "UNSAFE_TYPE",
            });
            continue;
        }
        let canonical = candidate
            .canonicalize()
            .context("cannot resolve protected file")?;
        if !canonical.starts_with(&canonical_root) {
            mismatches.push(ManifestMismatch {
                path: expected.path.clone(),
                reason: "PATH_ESCAPE",
            });
            continue;
        }
        if link_metadata.len() != expected.size {
            mismatches.push(ManifestMismatch {
                path: expected.path.clone(),
                reason: "SIZE_MISMATCH",
            });
            continue;
        }
        let actual = hash_file(&canonical)?;
        if !actual.eq_ignore_ascii_case(&expected.sha256) {
            mismatches.push(ManifestMismatch {
                path: expected.path.clone(),
                reason: "HASH_MISMATCH",
            });
        }
    }
    Ok(mismatches)
}

fn safe_relative_path(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && value.len() <= 512
        && !path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        })
}

fn hash_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).context("cannot open protected file")?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .context("cannot hash protected file")?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

pub fn inspect_executable(path: &Path) -> Result<IntegritySnapshot> {
    let canonical = path
        .canonicalize()
        .context("game executable does not exist")?;
    let metadata = canonical
        .metadata()
        .context("cannot inspect game executable")?;
    if !metadata.is_file() {
        bail!("game path is not a regular file");
    }
    let name = canonical
        .file_name()
        .and_then(|v| v.to_str())
        .context("game filename is not UTF-8")?;
    let mut file = File::open(&canonical).context("cannot open game executable")?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .context("cannot hash game executable")?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(IntegritySnapshot {
        executable_name: name.to_owned(),
        executable_sha256: hex::encode(hasher.finalize()),
        executable_size: metadata.len(),
        debugger_observed: debugger_observed(),
        platform: std::env::consts::OS.to_owned(),
        process_id: std::process::id(),
        loaded_module_basenames: loaded_module_basenames(),
        executable_build_id: executable_build_id(&canonical),
    })
}

pub fn validate_game_path(path: &Path) -> Result<PathBuf> {
    let canonical = path
        .canonicalize()
        .context("game executable does not exist")?;
    if !canonical.is_file() {
        bail!("game path is not a regular file");
    }
    Ok(canonical)
}

/// Confirms that the process launched by the Agent is still present and still
/// refers to the approved executable. The relationship is advisory user-mode
/// evidence; it is not a trust boundary.
pub fn inspect_game_process(process_id: u32, expected_path: &Path) -> GameProcessSnapshot {
    inspect_game_process_bound(process_id, expected_path, None)
}

pub fn inspect_game_process_bound(
    process_id: u32,
    expected_path: &Path,
    expected_identity: Option<u64>,
) -> GameProcessSnapshot {
    if process_id == 0 {
        return GameProcessSnapshot {
            running: false,
            executable_matches: false,
            parent_is_agent: None,
            loaded_module_basenames: vec![],
            process_identity_stable: None,
        };
    }
    let mut snapshot = inspect_game_process_platform(process_id, expected_path);
    snapshot.process_identity_stable = expected_identity
        .map(|expected| process_identity(process_id) == Some(expected))
        .or(snapshot.process_identity_stable);
    snapshot
}

pub fn process_identity(process_id: u32) -> Option<u64> {
    (process_id != 0)
        .then(|| process_identity_platform(process_id))
        .flatten()
}

#[cfg(target_os = "linux")]
fn process_identity_platform(process_id: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{process_id}/stat")).ok()?;
    let after_name = stat.rsplit_once(')')?.1.trim_start();
    after_name.split_whitespace().nth(19)?.parse().ok()
}

#[cfg(target_os = "macos")]
fn process_identity_platform(process_id: u32) -> Option<u64> {
    macos_process_times(process_id).map(|(seconds, micros)| seconds ^ micros.rotate_left(32))
}

#[cfg(target_os = "windows")]
fn process_identity_platform(process_id: u32) -> Option<u64> {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, FILETIME},
        System::Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION},
    };
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        return None;
    }
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    let success =
        unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) } != 0;
    unsafe { CloseHandle(process) };
    success
        .then_some((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn process_identity_platform(_process_id: u32) -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn inspect_game_process_platform(process_id: u32, expected_path: &Path) -> GameProcessSnapshot {
    let process_identity_stable = linux_pidfd_alive(process_id);
    let actual = std::fs::read_link(format!("/proc/{process_id}/exe"));
    let running = actual.is_ok();
    let executable_matches = actual
        .ok()
        .and_then(|path| path.canonicalize().ok())
        .zip(expected_path.canonicalize().ok())
        .is_some_and(|(actual, expected)| actual == expected);
    let parent_is_agent = std::fs::read_to_string(format!("/proc/{process_id}/stat"))
        .ok()
        .and_then(|stat| {
            let after_name = stat.rsplit_once(')')?.1.trim_start();
            after_name.split_whitespace().nth(1)?.parse::<u32>().ok()
        })
        .map(|parent| parent == std::process::id());
    let loaded_module_basenames = std::fs::read_to_string(format!("/proc/{process_id}/maps"))
        .map(|maps| module_basenames_from_maps(&maps))
        .unwrap_or_default();
    GameProcessSnapshot {
        running,
        executable_matches,
        parent_is_agent,
        loaded_module_basenames,
        process_identity_stable,
    }
}

#[cfg(target_os = "macos")]
fn inspect_game_process_platform(process_id: u32, expected_path: &Path) -> GameProcessSnapshot {
    use std::ffi::CStr;
    unsafe extern "C" {
        fn proc_pidpath(
            pid: libc::c_int,
            buffer: *mut libc::c_void,
            buffersize: u32,
        ) -> libc::c_int;
    }
    let mut buffer = [0_u8; 4096];
    let read = unsafe {
        proc_pidpath(
            process_id as libc::c_int,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
        )
    };
    let actual = (read > 0)
        .then(|| unsafe { CStr::from_ptr(buffer.as_ptr().cast()) })
        .and_then(|value| value.to_str().ok())
        .map(PathBuf::from);
    let executable_matches = actual
        .as_ref()
        .and_then(|path| path.canonicalize().ok())
        .zip(expected_path.canonicalize().ok())
        .is_some_and(|(actual, expected)| actual == expected);
    let parent_is_agent =
        macos_process_parent(process_id).map(|parent| parent == std::process::id());
    GameProcessSnapshot {
        running: actual.is_some(),
        executable_matches,
        parent_is_agent,
        loaded_module_basenames: vec![],
        process_identity_stable: None,
    }
}

#[cfg(target_os = "windows")]
fn inspect_game_process_platform(process_id: u32, expected_path: &Path) -> GameProcessSnapshot {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                TH32CS_SNAPPROCESS,
            },
            Threading::{
                OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
            },
        },
    };
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if handle.is_null() {
        return GameProcessSnapshot {
            running: false,
            executable_matches: false,
            parent_is_agent: None,
            loaded_module_basenames: vec![],
            process_identity_stable: None,
        };
    }
    let mut path = vec![0_u16; 32_768];
    let mut length = path.len() as u32;
    let queried =
        unsafe { QueryFullProcessImageNameW(handle, 0, path.as_mut_ptr(), &mut length) } != 0;
    let loaded_module_basenames = windows_process_modules(process_id);
    unsafe { CloseHandle(handle) };
    let executable_matches = queried
        && windows_paths_equal(
            Path::new(&String::from_utf16_lossy(&path[..length as usize])),
            expected_path,
        );

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    let parent_is_agent = if snapshot == INVALID_HANDLE_VALUE {
        None
    } else {
        let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut found = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
        let mut parent = None;
        while found {
            if entry.th32ProcessID == process_id {
                parent = Some(entry.th32ParentProcessID == std::process::id());
                break;
            }
            found = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
        }
        unsafe { CloseHandle(snapshot) };
        parent
    };
    GameProcessSnapshot {
        running: queried,
        executable_matches,
        parent_is_agent,
        loaded_module_basenames,
        process_identity_stable: None,
    }
}

#[cfg(target_os = "windows")]
fn windows_paths_equal(actual: &Path, expected: &Path) -> bool {
    let actual = actual
        .canonicalize()
        .unwrap_or_else(|_| actual.to_path_buf());
    let expected = expected
        .canonicalize()
        .unwrap_or_else(|_| expected.to_path_buf());
    actual
        .to_string_lossy()
        .eq_ignore_ascii_case(&expected.to_string_lossy())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn inspect_game_process_platform(_process_id: u32, _expected_path: &Path) -> GameProcessSnapshot {
    GameProcessSnapshot {
        running: false,
        executable_matches: false,
        parent_is_agent: None,
        loaded_module_basenames: vec![],
        process_identity_stable: None,
    }
}

#[cfg(target_os = "linux")]
fn linux_pidfd_alive(process_id: u32) -> Option<bool> {
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, process_id, 0) as libc::c_int };
    if descriptor < 0 {
        return None;
    }
    let mut poll = libc::pollfd {
        fd: descriptor,
        events: libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut poll, 1, 0) };
    unsafe { libc::close(descriptor) };
    (result >= 0).then_some(result == 0)
}

#[cfg(target_os = "linux")]
fn executable_build_id(path: &Path) -> Option<String> {
    use object::Object;
    let bytes = std::fs::read(path).ok()?;
    let file = object::File::parse(bytes.as_slice()).ok()?;
    file.build_id()
        .ok()
        .flatten()
        .filter(|value| !value.is_empty())
        .map(hex::encode)
}

#[cfg(not(target_os = "linux"))]
fn executable_build_id(_path: &Path) -> Option<String> {
    None
}

#[cfg(target_os = "linux")]
fn debugger_observed() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|line| {
                line.strip_prefix("TracerPid:")
                    .map(str::trim)
                    .map(str::to_owned)
            })
        })
        .is_some_and(|value| value != "0")
}

#[cfg(target_os = "linux")]
fn loaded_module_basenames() -> Vec<String> {
    let Ok(maps) = std::fs::read_to_string("/proc/self/maps") else {
        return vec![];
    };
    module_basenames_from_maps(&maps)
}

#[cfg(target_os = "linux")]
fn module_basenames_from_maps(maps: &str) -> Vec<String> {
    maps.lines()
        .filter_map(|line| line.split_whitespace().last())
        .filter(|value| value.starts_with('/'))
        .filter_map(|value| Path::new(value).file_name()?.to_str())
        .filter(|value| !value.is_empty() && value.len() <= 255)
        .map(str::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(1024)
        .collect()
}

#[cfg(target_os = "windows")]
fn windows_process_modules(process_id: u32) -> Vec<String> {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HMODULE},
        System::{
            ProcessStatus::{K32EnumProcessModules, K32GetModuleBaseNameW},
            Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
        },
    };
    let process =
        unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, process_id) };
    if process.is_null() {
        return vec![];
    }
    let mut needed = 0_u32;
    unsafe { K32EnumProcessModules(process, std::ptr::null_mut(), 0, &mut needed) };
    let count = (needed as usize / std::mem::size_of::<HMODULE>()).min(1024);
    let mut modules = vec![std::ptr::null_mut(); count];
    let success = count > 0
        && unsafe {
            K32EnumProcessModules(
                process,
                modules.as_mut_ptr(),
                (modules.len() * std::mem::size_of::<HMODULE>()) as u32,
                &mut needed,
            )
        } != 0;
    let result = if success {
        modules
            .into_iter()
            .filter_map(|module| {
                let mut name = [0_u16; 256];
                let length = unsafe {
                    K32GetModuleBaseNameW(process, module, name.as_mut_ptr(), name.len() as u32)
                } as usize;
                (length > 0 && length < name.len())
                    .then(|| String::from_utf16_lossy(&name[..length]))
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    } else {
        vec![]
    };
    unsafe { CloseHandle(process) };
    result
}

#[cfg(target_os = "macos")]
fn macos_process_parent(process_id: u32) -> Option<u32> {
    macos_process_info(process_id).map(|info| info.pbi_ppid)
}

#[cfg(target_os = "macos")]
fn macos_process_times(process_id: u32) -> Option<(u64, u64)> {
    macos_process_info(process_id).map(|info| (info.pbi_start_tvsec, info.pbi_start_tvusec))
}

#[cfg(target_os = "macos")]
fn macos_process_info(process_id: u32) -> Option<MacProcBsdInfo> {
    #[repr(C)]
    struct ProcBsdInfo {
        pbi_flags: u32,
        pbi_status: u32,
        pbi_xstatus: u32,
        pbi_pid: u32,
        pbi_ppid: u32,
        pbi_uid: u32,
        pbi_gid: u32,
        pbi_ruid: u32,
        pbi_rgid: u32,
        pbi_svuid: u32,
        pbi_svgid: u32,
        rfu_1: u32,
        pbi_comm: [libc::c_char; 16],
        pbi_name: [libc::c_char; 32],
        pbi_nfiles: u32,
        pbi_pgid: u32,
        pbi_pjobc: u32,
        e_tdev: u32,
        e_tpgid: u32,
        pbi_nice: i32,
        pbi_start_tvsec: u64,
        pbi_start_tvusec: u64,
    }
    #[link(name = "proc")]
    unsafe extern "C" {
        fn proc_pidinfo(
            pid: libc::c_int,
            flavor: libc::c_int,
            arg: u64,
            buffer: *mut libc::c_void,
            buffer_size: libc::c_int,
        ) -> libc::c_int;
    }
    const PROC_PIDTBSDINFO: libc::c_int = 3;
    let mut info: ProcBsdInfo = unsafe { std::mem::zeroed() };
    let expected = std::mem::size_of::<ProcBsdInfo>();
    let read = unsafe {
        proc_pidinfo(
            process_id as libc::c_int,
            PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut ProcBsdInfo).cast(),
            expected as libc::c_int,
        )
    };
    (read == expected as libc::c_int).then_some(MacProcBsdInfo {
        pbi_ppid: info.pbi_ppid,
        pbi_start_tvsec: info.pbi_start_tvsec,
        pbi_start_tvusec: info.pbi_start_tvusec,
    })
}

#[cfg(target_os = "macos")]
struct MacProcBsdInfo {
    pbi_ppid: u32,
    pbi_start_tvsec: u64,
    pbi_start_tvusec: u64,
}

#[cfg(target_os = "macos")]
fn debugger_observed() -> bool {
    #[repr(C)]
    struct ProcBsdInfo {
        pbi_flags: u32,
        pbi_status: u32,
        pbi_xstatus: u32,
        pbi_pid: u32,
        pbi_ppid: u32,
        pbi_uid: u32,
        pbi_gid: u32,
        pbi_ruid: u32,
        pbi_rgid: u32,
        pbi_svuid: u32,
        pbi_svgid: u32,
        rfu_1: u32,
        pbi_comm: [libc::c_char; 16],
        pbi_name: [libc::c_char; 32],
        pbi_nfiles: u32,
        pbi_pgid: u32,
        pbi_pjobc: u32,
        e_tdev: u32,
        e_tpgid: u32,
        pbi_nice: i32,
        pbi_start_tvsec: u64,
        pbi_start_tvusec: u64,
    }
    #[link(name = "proc")]
    unsafe extern "C" {
        fn proc_pidinfo(
            pid: libc::c_int,
            flavor: libc::c_int,
            arg: u64,
            buffer: *mut libc::c_void,
            buffer_size: libc::c_int,
        ) -> libc::c_int;
    }
    const PROC_PIDTBSDINFO: libc::c_int = 3;
    const PROC_FLAG_TRACED: u32 = 2;
    let mut info: ProcBsdInfo = unsafe { std::mem::zeroed() };
    let expected = std::mem::size_of::<ProcBsdInfo>();
    let read = unsafe {
        proc_pidinfo(
            libc::getpid(),
            PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut ProcBsdInfo).cast(),
            expected as libc::c_int,
        )
    };
    read == expected as libc::c_int && info.pbi_flags & PROC_FLAG_TRACED != 0
}

#[cfg(target_os = "macos")]
fn loaded_module_basenames() -> Vec<String> {
    use std::ffi::CStr;
    unsafe extern "C" {
        fn _dyld_image_count() -> u32;
        fn _dyld_get_image_name(image_index: u32) -> *const std::ffi::c_char;
    }
    let count = unsafe { _dyld_image_count() }.min(1024);
    (0..count)
        .filter_map(|index| {
            let pointer = unsafe { _dyld_get_image_name(index) };
            if pointer.is_null() {
                return None;
            }
            let path = unsafe { CStr::from_ptr(pointer) }.to_str().ok()?;
            Path::new(path).file_name()?.to_str().map(str::to_owned)
        })
        .filter(|value| !value.is_empty() && value.len() <= 255)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(target_os = "windows")]
fn debugger_observed() -> bool {
    unsafe extern "system" {
        fn IsDebuggerPresent() -> i32;
    }
    unsafe { IsDebuggerPresent() != 0 }
}

#[cfg(target_os = "windows")]
fn loaded_module_basenames() -> Vec<String> {
    use windows_sys::Win32::{
        Foundation::HMODULE,
        System::{
            ProcessStatus::{K32EnumProcessModules, K32GetModuleBaseNameW},
            Threading::GetCurrentProcess,
        },
    };
    let process = unsafe { GetCurrentProcess() };
    let mut needed = 0_u32;
    unsafe { K32EnumProcessModules(process, std::ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        return vec![];
    }
    let count = (needed as usize / std::mem::size_of::<HMODULE>()).min(1024);
    let mut modules = vec![std::ptr::null_mut(); count];
    if unsafe {
        K32EnumProcessModules(
            process,
            modules.as_mut_ptr(),
            (modules.len() * std::mem::size_of::<HMODULE>()) as u32,
            &mut needed,
        )
    } == 0
    {
        return vec![];
    }
    modules
        .into_iter()
        .filter_map(|module| {
            let mut name = [0_u16; 256];
            let length = unsafe {
                K32GetModuleBaseNameW(process, module, name.as_mut_ptr(), name.len() as u32)
            } as usize;
            (length > 0 && length < name.len()).then(|| String::from_utf16_lossy(&name[..length]))
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn debugger_observed() -> bool {
    false
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn loaded_module_basenames() -> Vec<String> {
    vec![]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hashes_a_regular_file() {
        let snapshot =
            inspect_executable(Path::new(std::env::current_exe().unwrap().as_path())).unwrap();
        assert_eq!(snapshot.executable_sha256.len(), 64);
        assert!(snapshot.executable_size > 0);
        assert!(snapshot.loaded_module_basenames.len() <= 1024);
        #[cfg(target_os = "linux")]
        assert!(snapshot.executable_build_id.as_ref().is_none_or(
            |value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        ));
    }

    #[test]
    fn confirms_live_process_executable_identity() {
        let executable = std::env::current_exe().unwrap();
        let snapshot = inspect_game_process(std::process::id(), &executable);
        assert!(snapshot.running);
        assert!(snapshot.executable_matches);
        assert_ne!(snapshot.parent_is_agent, Some(true));
        #[cfg(target_os = "linux")]
        assert_eq!(snapshot.process_identity_stable, Some(true));
    }
    #[test]
    fn rejects_missing_path() {
        assert!(validate_game_path(Path::new("definitely-not-a-game")).is_err());
    }

    #[test]
    fn verifies_manifest_and_reports_tampering() {
        let root = std::env::temp_dir().join(format!("certael-manifest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("game.bin"), b"approved").unwrap();
        let expected = ProtectedBuildManifest {
            build_id: "build-1".into(),
            files: vec![ProtectedBuildFile {
                path: "game.bin".into(),
                size: 8,
                sha256: hash_file(&root.join("game.bin")).unwrap(),
            }],
        };
        assert!(verify_build_manifest(&root, &expected).unwrap().is_empty());
        std::fs::write(root.join("game.bin"), b"tampered").unwrap();
        assert_eq!(
            verify_build_manifest(&root, &expected).unwrap(),
            vec![ManifestMismatch {
                path: "game.bin".into(),
                reason: "HASH_MISMATCH",
            }]
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_manifest_path_traversal() {
        let manifest = ProtectedBuildManifest {
            build_id: "build".into(),
            files: vec![ProtectedBuildFile {
                path: "../outside".into(),
                size: 1,
                sha256: "00".repeat(32),
            }],
        };
        assert!(verify_build_manifest(Path::new("."), &manifest).is_err());
    }
}
