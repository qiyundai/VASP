//! AppContainer launcher. Workers receive only inherited pipes and selected network capabilities.
use anyhow::Result;
use std::path::Path;

#[derive(Clone, Copy)]
pub enum NetworkAccess {
    None,
    Internet,
    CloudModel,
    Lan,
}
pub fn run(executable: &Path, input: Vec<u8>, network: NetworkAccess) -> Result<Vec<u8>> {
    #[cfg(windows)]
    {
        native::run(executable, input, network)
    }
    #[cfg(not(windows))]
    {
        let _ = (executable, input, network);
        anyhow::bail!("AppContainer is required")
    }
}

#[cfg(windows)]
mod native {
    use super::*;
    use anyhow::{Context, bail};
    use std::{
        fs::File,
        io::{Read, Write},
        os::windows::io::FromRawHandle,
    };
    use windows::{
        Win32::{
            Foundation::*,
            Security::Authorization::*,
            Security::Isolation::*,
            Security::*,
            System::{JobObjects::*, Pipes::*, Threading::*},
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
    struct Sid(PSID);
    impl Drop for Sid {
        fn drop(&mut self) {
            unsafe {
                FreeSid(self.0);
            }
        }
    }
    struct Attributes(LPPROC_THREAD_ATTRIBUTE_LIST);
    impl Drop for Attributes {
        fn drop(&mut self) {
            unsafe {
                DeleteProcThreadAttributeList(self.0);
            }
        }
    }
    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    fn grant(executable: &Path, sid: PSID) -> Result<()> {
        // Preserve the original DACL; grant this one AppContainer read/execute on this binary only.
        let path = wide(&executable.to_string_lossy());
        let mut old = std::ptr::null_mut();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            GetNamedSecurityInfoW(
                PCWSTR(path.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut old),
                None,
                &mut descriptor,
            )
            .ok()?;
        }
        let access = EXPLICIT_ACCESS_W {
            grfAccessPermissions: 0x1200a9,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: ACE_FLAGS(0),
            Trustee: TRUSTEE_W {
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_UNKNOWN,
                ptstrName: PWSTR(sid.0.cast()),
                ..Default::default()
            },
        };
        let mut new = std::ptr::null_mut();
        let result = unsafe {
            SetEntriesInAclW(Some(&[access]), Some(old), &mut new)
                .ok()
                .and_then(|_| {
                    SetNamedSecurityInfoW(
                        PCWSTR(path.as_ptr()),
                        SE_FILE_OBJECT,
                        DACL_SECURITY_INFORMATION,
                        None,
                        None,
                        Some(new),
                        None,
                    )
                    .ok()
                })
        };
        unsafe {
            if !new.is_null() {
                let _ = LocalFree(Some(HLOCAL(new.cast())));
            }
            let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        }
        result?;
        Ok(())
    }
    fn pipe() -> Result<(Handle, Handle)> {
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            bInheritHandle: BOOL(1),
            ..Default::default()
        };
        let mut r = HANDLE::default();
        let mut w = HANDLE::default();
        unsafe {
            CreatePipe(&mut r, &mut w, Some(&sa), 0)?;
        }
        Ok((Handle(r), Handle(w)))
    }
    fn file(handle: Handle) -> File {
        let raw = handle.0.0;
        std::mem::forget(handle);
        unsafe { File::from_raw_handle(raw) }
    }

    pub fn run(executable: &Path, input: Vec<u8>, network: NetworkAccess) -> Result<Vec<u8>> {
        let profile = wide(match network {
            NetworkAccess::None => "VASP.Parser.v1",
            NetworkAccess::Internet => "VASP.Internet.v1",
            NetworkAccess::CloudModel => "VASP.CloudAnalyst.v1",
            NetworkAccess::Lan => "VASP.LanAnalyst.v1",
        });
        let sid = Sid(unsafe {
            match CreateAppContainerProfile(
                PCWSTR(profile.as_ptr()),
                PCWSTR(profile.as_ptr()),
                PCWSTR(profile.as_ptr()),
                None,
            ) {
                Ok(s) => s,
                Err(e) if e.code().0 as u32 == 0x800700b7 => {
                    DeriveAppContainerSidFromAppContainerName(PCWSTR(profile.as_ptr()))
                        .context("Derive AppContainer profile")?
                }
                Err(e) => return Err(anyhow::Error::from(e).context("Create AppContainer profile")),
            }
        });
        grant(executable, sid.0).context("Grant sandbox executable read access")?;
        let mut cap_storage = vec![0usize; 16];
        let mut cap_size = (cap_storage.len() * std::mem::size_of::<usize>()) as u32;
        let mut capability = SID_AND_ATTRIBUTES::default();
        let mut caps = SECURITY_CAPABILITIES {
            AppContainerSid: sid.0,
            ..Default::default()
        };
        if !matches!(network, NetworkAccess::None) {
            let kind = if matches!(network, NetworkAccess::Internet | NetworkAccess::CloudModel) {
                WinCapabilityInternetClientSid
            } else {
                WinCapabilityPrivateNetworkClientServerSid
            };
            unsafe {
                CreateWellKnownSid(
                    kind,
                    None,
                    Some(PSID(cap_storage.as_mut_ptr().cast())),
                    &mut cap_size,
                )?;
            }
            capability.Sid = PSID(cap_storage.as_mut_ptr().cast());
            capability.Attributes = 4;
            caps.Capabilities = &mut capability;
            caps.CapabilityCount = 1;
        }
        let (stdin_read, stdin_write) = pipe()?;
        let (stdout_read, stdout_write) = pipe()?;
        let (stderr_read, stderr_write) = pipe()?;
        for h in [&stdin_write, &stdout_read, &stderr_read] {
            unsafe {
                SetHandleInformation(h.0, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0))?;
            }
        }
        let mut size = 0;
        unsafe {
            let _ = InitializeProcThreadAttributeList(None, 2, None, &mut size);
        }
        let mut buffer = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
        let list = LPPROC_THREAD_ATTRIBUTE_LIST(buffer.as_mut_ptr().cast());
        unsafe {
            InitializeProcThreadAttributeList(Some(list), 2, None, &mut size)?;
        }
        let attributes = Attributes(list);
        let handles = [stdin_read.0, stdout_write.0, stderr_write.0];
        unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                Some((&caps as *const SECURITY_CAPABILITIES).cast()),
                std::mem::size_of_val(&caps),
                None,
                None,
            )?;
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                Some(handles.as_ptr().cast()),
                std::mem::size_of_val(&handles),
                None,
                None,
            )?;
        }
        let mut startup = STARTUPINFOEXW {
            lpAttributeList: list,
            ..Default::default()
        };
        startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = stdin_read.0;
        startup.StartupInfo.hStdOutput = stdout_write.0;
        startup.StartupInfo.hStdError = stderr_write.0;
        let exe = wide(&executable.to_string_lossy());
        let mut command = wide(&format!("\"{}\" worker", executable.display()));
        let mut process = PROCESS_INFORMATION::default();
        let system = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        let cwd = wide(&system);
        // Do not inherit API keys, proxy configuration, PATH, or other parent environment secrets.
        let mut environment_text = String::new();
        for name in [
            "ALLUSERSPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
            "ProgramData",
            "SystemDrive",
            "SystemRoot",
            "TEMP",
            "TMP",
            "USERPROFILE",
            "windir",
        ] {
            if let Ok(value) = std::env::var(name)
                && !value.contains('\0')
            {
                environment_text.push_str(&format!("{name}={value}\0"));
            }
        }
        environment_text.push('\0');
        let environment: Vec<u16> = environment_text.encode_utf16().collect();
        unsafe {
            CreateProcessW(
                PCWSTR(exe.as_ptr()),
                Some(PWSTR(command.as_mut_ptr())),
                None,
                None,
                true,
                CREATE_SUSPENDED
                    | CREATE_NO_WINDOW
                    | EXTENDED_STARTUPINFO_PRESENT
                    | CREATE_UNICODE_ENVIRONMENT,
                Some(environment.as_ptr().cast()),
                PCWSTR(cwd.as_ptr()),
                &startup.StartupInfo,
                &mut process,
            )
            .context("Create AppContainer process")?;
        }
        let thread = Handle(process.hThread);
        let process = Handle(process.hProcess);
        drop(attributes);
        run_started(
            process,
            thread,
            stdin_read,
            stdin_write,
            stdout_read,
            stdout_write,
            stderr_read,
            stderr_write,
            input,
        )
    }
    struct Process(Handle);
    impl Drop for Process {
        fn drop(&mut self) {
            unsafe {
                let _ = TerminateProcess(self.0.0, 1);
            }
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn run_started(
        process: Handle,
        thread: Handle,
        in_r: Handle,
        in_w: Handle,
        out_r: Handle,
        out_w: Handle,
        err_r: Handle,
        err_w: Handle,
        input: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let process = Process(process);
        let job = Handle(unsafe { CreateJobObjectW(None, PCWSTR::null())? });
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        limits.BasicLimitInformation.ActiveProcessLimit = 1;
        limits.ProcessMemoryLimit = 384 * 1024 * 1024;
        unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
            )?;
            AssignProcessToJobObject(job.0, process.0.0)?;
            if ResumeThread(thread.0) == u32::MAX {
                bail!("Could not resume sandbox worker");
            }
        }
        drop(thread);
        drop(in_r);
        drop(out_w);
        drop(err_w);
        let mut writer = file(in_w);
        let reader = file(out_r);
        let errors = file(err_r);
        let write_thread = std::thread::spawn(move || writer.write_all(&input));
        let read_thread = std::thread::spawn(move || {
            let mut b = vec![];
            reader
                .take(64 * 1024 * 1024 + 1)
                .read_to_end(&mut b)
                .map(|_| b)
        });
        let error_thread = std::thread::spawn(move || {
            let mut b = vec![];
            errors.take(8192).read_to_end(&mut b).map(|_| b)
        });
        let wait = unsafe { WaitForSingleObject(process.0.0, 90000) };
        if wait != WAIT_OBJECT_0 {
            unsafe {
                let _ = TerminateProcess(process.0.0, 1);
            }
            bail!("AppContainer worker timed out");
        }
        let mut code = 0;
        unsafe {
            GetExitCodeProcess(process.0.0, &mut code)?;
        }
        let output = read_thread
            .join()
            .map_err(|_| anyhow::anyhow!("Sandbox reader failed"))??;
        let errors = error_thread
            .join()
            .map_err(|_| anyhow::anyhow!("Sandbox diagnostic reader failed"))??;
        write_thread
            .join()
            .map_err(|_| anyhow::anyhow!("Sandbox writer failed"))??;
        if code != 0 {
            bail!(
                "AppContainer worker failed ({code}): {}",
                String::from_utf8_lossy(&errors)
            );
        }
        if output.len() > 64 * 1024 * 1024 {
            bail!("Sandbox output limit exceeded");
        }
        Ok(output)
    }
}
