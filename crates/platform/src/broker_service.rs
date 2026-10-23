//! Small SCM callback bridge; the service body itself stays in safe Rust.
#[cfg(windows)]
mod native {
    use anyhow::Result;
    use std::sync::{
        Mutex, OnceLock,
        atomic::{AtomicBool, AtomicIsize, Ordering},
    };
    use windows::{
        Win32::System::Services::*,
        core::{PCWSTR, PWSTR},
    };
    static STOP: AtomicBool = AtomicBool::new(false);
    static HANDLE: AtomicIsize = AtomicIsize::new(0);
    static STATUS_LOCK: Mutex<()> = Mutex::new(());
    type Entry = fn(&AtomicBool) -> Result<()>;
    static ENTRY: OnceLock<Entry> = OnceLock::new();
    fn status(state: SERVICE_STATUS_CURRENT_STATE, error: u32) -> Result<()> {
        let _guard = STATUS_LOCK
            .lock()
            .map_err(|_| anyhow::anyhow!("SCM status lock poisoned"))?;
        let handle = HANDLE.load(Ordering::SeqCst);
        if handle == 0 {
            anyhow::bail!("SCM status handle is unavailable");
        }
        let pending = matches!(state, SERVICE_START_PENDING | SERVICE_STOP_PENDING);
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: if state == SERVICE_RUNNING {
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
            } else {
                0
            },
            dwWin32ExitCode: error,
            dwWaitHint: if pending { 10000 } else { 0 },
            dwCheckPoint: u32::from(pending),
            ..Default::default()
        };
        unsafe {
            SetServiceStatus(SERVICE_STATUS_HANDLE(handle as *mut _), &status)?;
        }
        if state == SERVICE_STOPPED {
            // SCM closes its RPC context on STOPPED; never report through it again.
            HANDLE.store(0, Ordering::SeqCst);
        }
        Ok(())
    }
    unsafe extern "system" fn control(
        code: u32,
        _: u32,
        _: *mut core::ffi::c_void,
        _: *mut core::ffi::c_void,
    ) -> u32 {
        match code {
            SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
                STOP.store(true, Ordering::SeqCst);
                if status(SERVICE_STOP_PENDING, 0).is_ok() {
                    0
                } else {
                    1064
                }
            }
            SERVICE_CONTROL_INTERROGATE => 0,
            _ => 120,
        }
    }
    unsafe extern "system" fn main(_: u32, _: *mut PWSTR) {
        let result = std::panic::catch_unwind(|| -> Result<()> {
            let name: Vec<u16> = vasp_core::broker::SERVICE
                .encode_utf16()
                .chain(Some(0))
                .collect();
            let handle = unsafe {
                RegisterServiceCtrlHandlerExW(PCWSTR(name.as_ptr()), Some(control), None)?
            };
            HANDLE.store(handle.0 as isize, Ordering::SeqCst);
            status(SERVICE_START_PENDING, 0)?;
            ENTRY
                .get()
                .ok_or_else(|| anyhow::anyhow!("Missing service entry"))?(&STOP)
        });
        let _ = status(
            SERVICE_STOPPED,
            if matches!(result, Ok(Ok(()))) {
                0
            } else {
                1064
            },
        );
    }
    pub fn ready() -> Result<()> {
        status(SERVICE_RUNNING, 0)
    }
    pub fn run(entry: Entry) -> Result<()> {
        ENTRY
            .set(entry)
            .map_err(|_| anyhow::anyhow!("Service already initialized"))?;
        let mut name: Vec<u16> = vasp_core::broker::SERVICE
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let table = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: PWSTR(name.as_mut_ptr()),
                lpServiceProc: Some(main),
            },
            SERVICE_TABLE_ENTRYW::default(),
        ];
        unsafe {
            StartServiceCtrlDispatcherW(table.as_ptr())?;
        }
        Ok(())
    }
}
#[cfg(windows)]
pub use native::{ready, run};
