use anyhow::{Context, Result, bail};
use std::time::{Duration, Instant};
use windows::{
    Win32::{
        Foundation::*,
        Security::{Authorization::*, *},
        Storage::FileSystem::*,
        System::{IO::*, Pipes::*, Services::*, Threading::*},
    },
    core::{BOOL, PCWSTR, PWSTR},
};

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}
struct Local(PSECURITY_DESCRIPTOR);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.0.0)));
        }
    }
}
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
fn is_error(e: &windows::core::Error, code: WIN32_ERROR) -> bool {
    e.code() == windows::core::HRESULT::from_win32(code.0)
}

#[derive(Debug)]
pub struct Identity {
    pub sid: String,
    pub app_container: bool,
    pub integrity: u32,
    pub session: u32,
}
fn token_bytes(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Result<Vec<usize>> {
    let mut needed = 0;
    unsafe {
        let _ = GetTokenInformation(token, class, None, 0, &mut needed);
    }
    if needed == 0 || needed > 65536 {
        bail!("Invalid token information size");
    }
    let mut bytes = vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
    unsafe {
        GetTokenInformation(
            token,
            class,
            Some(bytes.as_mut_ptr().cast()),
            needed,
            &mut needed,
        )?;
    }
    Ok(bytes)
}
fn sid_string(sid: PSID) -> Result<String> {
    let mut p = PWSTR::null();
    unsafe {
        ConvertSidToStringSidW(sid, &mut p)?;
    }
    let result = unsafe { p.to_string() };
    unsafe {
        let _ = LocalFree(Some(HLOCAL(p.0.cast())));
    }
    Ok(result?)
}
fn identity(token: HANDLE) -> Result<Identity> {
    let user = token_bytes(token, TokenUser)?;
    let label = token_bytes(token, TokenIntegrityLevel)?;
    // SAFETY: GetTokenInformation populated aligned storage for the requested type.
    let sid = sid_string(unsafe { (*(user.as_ptr().cast::<TOKEN_USER>())).User.Sid })?;
    let integrity_sid = unsafe {
        (*(label.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()))
            .Label
            .Sid
    };
    let count = unsafe { *GetSidSubAuthorityCount(integrity_sid) };
    if count == 0 {
        bail!("Missing integrity label");
    }
    let integrity = unsafe { *GetSidSubAuthority(integrity_sid, u32::from(count - 1)) };
    let app = token_bytes(token, TokenIsAppContainer)?;
    let session = token_bytes(token, TokenSessionId)?;
    Ok(Identity {
        sid,
        app_container: unsafe { *(app.as_ptr().cast::<u32>()) != 0 },
        integrity,
        session: unsafe { *(session.as_ptr().cast::<u32>()) },
    })
}
pub fn current_identity() -> Result<Identity> {
    let mut token = HANDLE::default();
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)?;
    }
    identity(Handle(token).0)
}
struct Impersonation;
impl Drop for Impersonation {
    fn drop(&mut self) {
        // Continuing as a client, or accidentally continuing privileged after an auth error,
        // is unacceptable. No unwinding or user code runs after a failed reversion.
        if unsafe { RevertToSelf() }.is_err() {
            std::process::abort();
        }
    }
}
fn authenticate_client(pipe: HANDLE, allowed: &[String]) -> Result<Identity> {
    unsafe {
        ImpersonateNamedPipeClient(pipe)?;
    }
    let revert = Impersonation;
    let mut token = HANDLE::default();
    unsafe {
        OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token)?;
    }
    let caller = identity(Handle(token).0)?;
    drop(revert);
    if caller.app_container || caller.integrity < 0x2000 || !allowed.contains(&caller.sid) {
        bail!("Caller token is not authorized");
    }
    Ok(caller)
}

/// A byte-mode pipe with bounded, length-prefixed frames and a single session deadline.
pub struct Channel {
    handle: Handle,
    deadline: Instant,
}
impl Channel {
    fn remaining(&self) -> u32 {
        self.deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(u32::MAX as u128) as u32
    }
    fn transfer(&self, buffer: &mut [u8], write: bool) -> Result<usize> {
        if self.remaining() == 0 {
            bail!("IPC session deadline exceeded");
        }
        let event = Handle(unsafe { CreateEventW(None, true, false, None)? });
        let mut overlapped = OVERLAPPED {
            hEvent: event.0,
            ..Default::default()
        };
        // SAFETY: buffer/OVERLAPPED/event stay live until completion, including cancellation.
        let started = unsafe {
            if write {
                WriteFile(self.handle.0, Some(buffer), None, Some(&mut overlapped))
            } else {
                ReadFile(self.handle.0, Some(buffer), None, Some(&mut overlapped))
            }
        };
        if let Err(ref e) = started
            && !is_error(e, ERROR_IO_PENDING)
        {
            return Err(started.err().context("I/O failure")?.into());
        }
        let wait = unsafe { WaitForSingleObject(event.0, self.remaining()) };
        let mut count = 0;
        if wait != WAIT_OBJECT_0 {
            unsafe {
                let _ = CancelIoEx(self.handle.0, Some(&overlapped));
                let _ = GetOverlappedResult(self.handle.0, &overlapped, &mut count, true);
            }
            bail!("IPC I/O deadline exceeded");
        }
        unsafe {
            GetOverlappedResult(self.handle.0, &overlapped, &mut count, false)?;
        }
        if count == 0 {
            bail!("IPC peer disconnected");
        }
        Ok(count as usize)
    }
    fn exact(&self, buffer: &mut [u8], write: bool) -> Result<()> {
        let mut offset = 0;
        while offset < buffer.len() {
            offset += self.transfer(&mut buffer[offset..], write)?;
        }
        Ok(())
    }
    pub fn read(&self) -> Result<Vec<u8>> {
        let mut header = [0; 4];
        self.exact(&mut header, false)?;
        let length = u32::from_be_bytes(header) as usize;
        if length == 0 || length > vasp_core::broker::MAX_FRAME {
            bail!("IPC frame size rejected");
        }
        let mut bytes = vec![0; length];
        self.exact(&mut bytes, false)?;
        Ok(bytes)
    }
    pub fn write(&self, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() || bytes.len() > vasp_core::broker::MAX_FRAME {
            bail!("IPC frame size rejected");
        }
        let mut frame = (bytes.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(bytes);
        self.exact(&mut frame, true)
    }
}

pub struct Server {
    channel: Channel,
    allowed: Vec<String>,
}
impl Server {
    pub fn new(name: &str, allowed: Vec<String>) -> Result<Self> {
        if !name.starts_with(r"\\.\pipe\VASP.")
            || name.len() > 150
            || name.contains('\0')
            || allowed.is_empty()
            || allowed.len() > 10
        {
            bail!("Invalid local IPC configuration");
        }
        let mut sddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)".to_owned();
        for sid in &allowed {
            if !vasp_core::broker::valid_sid(sid) {
                bail!("Invalid SID");
            }
            // Explicit data/read-attribute/synchronize rights: no FILE_CREATE_PIPE_INSTANCE.
            sddl.push_str(&format!("(A;;0x100083;;;{sid})"));
        }
        sddl.push_str("S:(ML;;NW;;;ME)");
        let sddl = wide(&sddl);
        let mut sd = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut sd,
                None,
            )?;
        }
        let sd = Local(sd);
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0.0,
            bInheritHandle: BOOL(0),
        };
        let name = wide(name);
        let pipe = unsafe {
            CreateNamedPipeW(
                PCWSTR(name.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                32768,
                32768,
                1000,
                Some(&attributes),
            )
        };
        if pipe == INVALID_HANDLE_VALUE {
            return Err(windows::core::Error::from_thread().into());
        }
        Ok(Self {
            channel: Channel {
                handle: Handle(pipe),
                deadline: Instant::now(),
            },
            allowed,
        })
    }
    pub fn accept(&mut self, timeout: Duration) -> Result<Option<Identity>> {
        let event = Handle(unsafe { CreateEventW(None, true, false, None)? });
        let mut overlapped = OVERLAPPED {
            hEvent: event.0,
            ..Default::default()
        };
        let result = unsafe { ConnectNamedPipe(self.channel.handle.0, Some(&mut overlapped)) };
        match result {
            Err(e) if is_error(&e, ERROR_PIPE_CONNECTED) => {}
            Err(e) if is_error(&e, ERROR_IO_PENDING) => {
                let mut count = 0;
                if unsafe {
                    WaitForSingleObject(event.0, timeout.as_millis().min(u32::MAX as u128) as u32)
                } != WAIT_OBJECT_0
                {
                    unsafe {
                        let _ = CancelIoEx(self.channel.handle.0, Some(&overlapped));
                        let _ = GetOverlappedResult(
                            self.channel.handle.0,
                            &overlapped,
                            &mut count,
                            true,
                        );
                        let _ = DisconnectNamedPipe(self.channel.handle.0);
                    }
                    return Ok(None);
                }
                unsafe {
                    GetOverlappedResult(self.channel.handle.0, &overlapped, &mut count, false)?;
                }
            }
            Err(e) => return Err(e.into()),
            Ok(()) => {}
        }
        self.channel.deadline = Instant::now() + Duration::from_secs(5);
        // Read a fixed preface BEFORE impersonation: Windows uses the last message read.
        if self.channel.read()? != b"VASP1" {
            bail!("IPC preface rejected");
        }
        Ok(Some(authenticate_client(
            self.channel.handle.0,
            &self.allowed,
        )?))
    }
    pub fn channel(&self) -> &Channel {
        &self.channel
    }
    pub fn disconnect(&self) {
        unsafe {
            let _ = DisconnectNamedPipe(self.channel.handle.0);
        }
    }
}

fn connect(name: &str) -> Result<Channel> {
    let name = wide(name);
    // Identification level permits token inspection but does not delegate impersonation rights.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(name.as_ptr()),
            0x100083,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            None,
        )?
    };
    Ok(Channel {
        handle: Handle(handle),
        deadline: Instant::now() + Duration::from_secs(5),
    })
}
pub fn connect_broker() -> Result<Channel> {
    let channel = connect(vasp_core::broker::PIPE)?;
    verify_service_server(channel.handle.0)?;
    channel.write(b"VASP1")?;
    Ok(channel)
}
struct ServiceHandle(SC_HANDLE);
impl Drop for ServiceHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseServiceHandle(self.0);
        }
    }
}
fn verify_service_server(pipe: HANDLE) -> Result<()> {
    let mut pid = 0;
    unsafe {
        GetNamedPipeServerProcessId(pipe, &mut pid)?;
    }
    let process = Handle(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)? });
    let mut token = HANDLE::default();
    unsafe {
        OpenProcessToken(process.0, TOKEN_QUERY, &mut token)?;
    }
    let who = identity(Handle(token).0)?;
    if who.sid != "S-1-5-18" || who.app_container || who.integrity < 0x4000 || who.session != 0 {
        bail!("Pipe server is not a SYSTEM service");
    }
    let scm = ServiceHandle(unsafe { OpenSCManagerW(None, None, SC_MANAGER_CONNECT)? });
    let name = wide(vasp_core::broker::SERVICE);
    let service =
        ServiceHandle(unsafe { OpenServiceW(scm.0, PCWSTR(name.as_ptr()), SERVICE_QUERY_STATUS)? });
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut needed = 0;
    let buffer = unsafe {
        std::slice::from_raw_parts_mut(
            (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
            std::mem::size_of_val(&status),
        )
    };
    unsafe {
        QueryServiceStatusEx(service.0, SC_STATUS_PROCESS_INFO, Some(buffer), &mut needed)?;
    }
    if status.dwProcessId != pid || status.dwCurrentState != SERVICE_RUNNING {
        bail!("Pipe server is not the registered VASP broker");
    }
    Ok(())
}

pub fn inventory() -> Result<vasp_core::broker::Inventory> {
    use winreg::{
        RegKey,
        enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY},
    };
    let key = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        KEY_READ | KEY_WOW64_64KEY,
    )?;
    Ok(vasp_core::broker::Inventory {
        windows_build: key.get_value::<String, _>("CurrentBuildNumber")?,
        revision: key.get_value("UBR")?,
    })
}

pub struct StateDirectory {
    pub path: std::path::PathBuf,
    _guard: Handle,
    _parent_guard: Handle,
}
fn secure_handle(path: &std::path::Path, directory: bool) -> Result<Handle> {
    use std::os::windows::fs::MetadataExt;
    for parent in path.ancestors() {
        if std::fs::symlink_metadata(parent)?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0
            != 0
        {
            bail!("Broker paths cannot contain reparse points");
        }
    }
    let name: Vec<u16> = path
        .as_os_str()
        .to_string_lossy()
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let handle = Handle(unsafe {
        CreateFileW(
            PCWSTR(name.as_ptr()),
            0x20081,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )?
    });
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe {
        GetFileInformationByHandle(handle.0, &mut info)?;
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0) != directory
    {
        bail!("Unexpected broker file type");
    }
    let mut owner = PSID::default();
    let mut dacl = std::ptr::null_mut();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        GetSecurityInfo(
            handle.0,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut dacl),
            None,
            Some(&mut sd),
        )
        .ok()?;
    }
    let _sd = Local(sd);
    let privileged = |sid: &str| matches!(sid, "S-1-5-18" | "S-1-5-32-544");
    if !privileged(&sid_string(owner)?) || dacl.is_null() {
        bail!("Broker state must be owned exclusively by SYSTEM/Administrators");
    }
    for index in 0..u32::from(unsafe { (*dacl).AceCount }) {
        let mut ace = std::ptr::null_mut();
        unsafe {
            GetAce(dacl, index, &mut ace)?;
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        // Only simple allow ACEs are accepted. Unknown/object/callback ACEs fail closed.
        if header.AceType != 0 {
            bail!("Unsupported broker ACL entry");
        }
        let ace = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = PSID((&ace.SidStart as *const u32).cast_mut().cast());
        if !privileged(&sid_string(sid)?) {
            bail!("Broker state grants access to an unprivileged account");
        }
    }
    Ok(handle)
}
pub fn state_directory() -> Result<StateDirectory> {
    use windows::Win32::{System::Com::CoTaskMemFree, UI::Shell::*};
    let p = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, KF_FLAG_DEFAULT, None)? };
    let text = unsafe { p.to_string() };
    unsafe {
        CoTaskMemFree(Some(p.0.cast()));
    }
    let path = std::path::PathBuf::from(text?).join("VASP").join("Broker");
    let parent_guard = secure_handle(path.parent().context("Missing state parent")?, true)?;
    let guard = secure_handle(&path, true)?;
    for file in ["broker.db", "broker.db-wal", "broker.db-shm"] {
        let child = path.join(file);
        if child.try_exists()? {
            let _ = secure_handle(&child, false)?;
        }
    }
    Ok(StateDirectory {
        path,
        _guard: guard,
        _parent_guard: parent_guard,
    })
}
pub fn read_protected_config(path: &std::path::Path) -> Result<Vec<u8>> {
    use std::{io::Read, os::windows::io::FromRawHandle};
    let handle = secure_handle(path, false)?;
    let raw = handle.0.0;
    std::mem::forget(handle);
    let file = unsafe { std::fs::File::from_raw_handle(raw) };
    let mut bytes = vec![];
    file.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        bail!("Broker config exceeds limit");
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unlisted_user_and_oversized_frames_are_rejected() {
        let denied_name = format!(r"\\.\pipe\VASP.Test.{}", uuid::Uuid::new_v4());
        let mut denied_server =
            Server::new(&denied_name, vec!["S-1-5-21-1-2-3-9999".into()]).unwrap();
        // Administrators can open the pipe via the administrative ACE, but still
        // cannot use the protocol unless their actual user SID is enrolled.
        if let Ok(client) = connect(&denied_name) {
            client.write(b"VASP1").unwrap();
            assert!(denied_server.accept(Duration::from_secs(3)).is_err());
        }
        let name = format!(r"\\.\pipe\VASP.Test.{}", uuid::Uuid::new_v4());
        let sid = current_identity().unwrap().sid;
        let (ready, rx) = std::sync::mpsc::channel();
        let child_name = name.clone();
        let thread = std::thread::spawn(move || {
            let mut server = Server::new(&child_name, vec![sid]).unwrap();
            ready.send(()).unwrap();
            assert!(server.accept(Duration::from_secs(3)).unwrap().is_some());
            assert!(server.channel().read().is_err());
            server.disconnect();
        });
        rx.recv().unwrap();
        let client = connect(&name).unwrap();
        client.write(b"VASP1").unwrap();
        client
            .exact(
                &mut ((vasp_core::broker::MAX_FRAME + 1) as u32).to_be_bytes(),
                true,
            )
            .unwrap();
        thread.join().unwrap();
    }

    #[test]
    fn user_owned_state_is_not_trusted_as_privileged_policy() {
        let path =
            std::env::temp_dir().join(format!("vasp-untrusted-{}.json", uuid::Uuid::new_v4()));
        std::fs::write(&path, b"{}").unwrap();
        let result = read_protected_config(&path);
        std::fs::remove_file(&path).unwrap();
        assert!(result.is_err());
    }
    #[test]
    fn pipe_authentication_deadlines_and_namespace_ownership() {
        let name = format!(r"\\.\pipe\VASP.Test.{}", uuid::Uuid::new_v4());
        let sid = current_identity().unwrap().sid;
        let (ready, rx) = std::sync::mpsc::channel();
        let thread_name = name.clone();
        let thread_sid = sid.clone();
        let server = std::thread::spawn(move || {
            let mut server = Server::new(&thread_name, vec![thread_sid.clone()]).unwrap();
            ready.send(()).unwrap();
            let who = server.accept(Duration::from_secs(3)).unwrap().unwrap();
            assert_eq!(who.sid, thread_sid);
            assert!(!who.app_container);
            assert_eq!(server.channel().read().unwrap(), b"typed request");
            server.channel().write(b"typed response").unwrap();
            // A short silent client cannot indefinitely retain the pipe.
            server.channel.deadline = Instant::now() + Duration::from_millis(50);
            assert!(server.channel().read().is_err());
            server.disconnect();
        });
        rx.recv().unwrap();
        assert!(Server::new(&name, vec![sid]).is_err());
        let client = connect(&name).unwrap();
        // Production authentication must reject this ordinary-user test server.
        assert!(verify_service_server(client.handle.0).is_err());
        client.write(b"VASP1").unwrap();
        client.write(b"typed request").unwrap();
        assert_eq!(client.read().unwrap(), b"typed response");
        server.join().unwrap();
    }
}
