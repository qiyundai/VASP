//! Small SCM callback bridge; the service body itself stays in safe Rust.
#[cfg(windows)]
mod native {
    use anyhow::Result;
    use std::sync::{
        OnceLock,
        atomic::{AtomicBool, AtomicIsize, Ordering},
    };
    use windows::{
        Win32::System::Services::*,
        core::{PCWSTR, PWSTR},
    };
    static STOP: AtomicBool = AtomicBool::new(false);
    static HANDLE: AtomicIsize = AtomicIsize::new(0);
    type Entry = fn(&AtomicBool) -> Result<()>;
    static ENTRY: OnceLock<Entry> = OnceLock::new();
    fn status(state: SERVICE_STATUS_CURRENT_STATE, error: u32) {
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: if state == SERVICE_RUNNING {
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
            } else {
                0
            },
            dwWin32ExitCode: error,
            dwWaitHint: if state == SERVICE_STOP_PENDING {
                10000
            } else {
                0
            },
            ..Default::default()
        };
        unsafe {
            let _ = SetServiceStatus(
                SERVICE_STATUS_HANDLE(HANDLE.load(Ordering::SeqCst) as *mut _),
                &status,
            );
        }
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
                status(SERVICE_STOP_PENDING, 0);
                0
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
            status(SERVICE_START_PENDING, 0);
            ENTRY
                .get()
                .ok_or_else(|| anyhow::anyhow!("Missing service entry"))?(&STOP)
        });
        status(
            SERVICE_STOPPED,
            if matches!(result, Ok(Ok(()))) {
                0
            } else {
                1064
            },
        );
    }
    pub fn ready() {
        status(SERVICE_RUNNING, 0);
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
