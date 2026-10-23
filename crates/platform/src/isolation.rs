//! Windows job limits. Resource containment alone is NOT a privilege sandbox.
use anyhow::Result;

#[cfg(windows)]
pub struct Job(windows::Win32::Foundation::HANDLE);
#[cfg(not(windows))]
pub struct Job;

#[cfg(windows)]
impl Job {
    pub fn attach(child: &std::process::Child, memory: usize) -> Result<Self> {
        use std::os::windows::io::AsRawHandle;
        use windows::{
            Win32::{Foundation::HANDLE, System::JobObjects::*},
            core::PCWSTR,
        };
        // SAFETY: owned job handle and borrowed live process handle, exact structure size.
        let job = Self(unsafe { CreateJobObjectW(None, PCWSTR::null())? });
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        limits.BasicLimitInformation.ActiveProcessLimit = 1;
        limits.ProcessMemoryLimit = memory;
        unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
            )?;
            AssignProcessToJobObject(job.0, HANDLE(child.as_raw_handle()))?;
        }
        Ok(job)
    }
}
#[cfg(windows)]
impl Drop for Job {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(self.0);
        }
    }
}
#[cfg(not(windows))]
impl Job {
    pub fn attach(_: &std::process::Child, _: usize) -> Result<Self> {
        anyhow::bail!("Windows job isolation is unavailable")
    }
}

/// Lock the data directory to the current user, SYSTEM, and administrators.
pub fn protect_directory(path: &std::path::Path) -> Result<()> {
    #[cfg(windows)]
    {
        use windows::{
            Win32::{Foundation::*, Security::Authorization::*, Security::*, System::Threading::*},
            core::{BOOL, PCWSTR, PWSTR},
        };
        let mut token = HANDLE::default();
        unsafe {
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)?;
        }
        let mut needed = 0;
        unsafe {
            let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
        }
        let mut storage = vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
        let read = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                Some(storage.as_mut_ptr().cast()),
                needed,
                &mut needed,
            )
        };
        unsafe {
            let _ = CloseHandle(token);
        }
        read?;
        // SAFETY: TOKEN_USER is in aligned storage produced by GetTokenInformation.
        let sid = unsafe { (*(storage.as_ptr() as *const TOKEN_USER)).User.Sid };
        let mut sid_string = PWSTR::null();
        unsafe {
            ConvertSidToStringSidW(sid, &mut sid_string)?;
        }
        let sid_text = unsafe { sid_string.to_string()? };
        unsafe {
            let _ = LocalFree(Some(HLOCAL(sid_string.0.cast())));
        }
        let sddl = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{sid_text})");
        let sddl: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut sd,
                None,
            )?;
        }
        let mut present = BOOL(0);
        let mut defaulted = BOOL(0);
        let mut dacl = std::ptr::null_mut();
        let path: Vec<u16> = path
            .as_os_str()
            .to_string_lossy()
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let result = unsafe {
            GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted).and_then(|_| {
                SetNamedSecurityInfoW(
                    PCWSTR(path.as_ptr()),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    None,
                    None,
                    Some(dacl),
                    None,
                )
                .ok()
            })
        };
        unsafe {
            let _ = LocalFree(Some(HLOCAL(sd.0)));
        }
        result?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        anyhow::bail!("Windows ACL protection is unavailable")
    }
}
