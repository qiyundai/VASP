//! Native dynamic-filter backend. Deliberately not exposed by the production CLI.
//! Activation requires a reviewed broker, authenticated IPC, and VM recovery acceptance.
use anyhow::Result;
use vasp_core::protocol::BlockTarget;

pub const RELEASE_ENFORCEMENT_APPROVED: bool = vasp_core::broker::ENFORCEMENT_ENABLED;

#[cfg(windows)]
pub struct DynamicSession {
    handle: windows::Win32::Foundation::HANDLE,
    sublayer: windows::core::GUID,
}
#[cfg(not(windows))]
pub struct DynamicSession;

#[cfg(windows)]
impl DynamicSession {
    pub fn open() -> Result<Self> {
        use windows::{
            Win32::{Foundation::HANDLE, NetworkManagement::WindowsFilteringPlatform::*},
            core::{GUID, PCWSTR, PWSTR},
        };
        let mut handle = HANDLE::default();
        let mut label: Vec<u16> = "VASP temporary containment"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let session = FWPM_SESSION0 {
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(label.as_mut_ptr()),
                ..Default::default()
            },
            ..Default::default()
        };
        // SAFETY: WFP copies parameters synchronously; engine is released on Drop.
        check(unsafe { FwpmEngineOpen0(PCWSTR::null(), 10, None, Some(&session), &mut handle) })?;
        let instance = Self {
            handle,
            sublayer: GUID::from_u128(uuid::Uuid::new_v4().as_u128()),
        };
        let layer = FWPM_SUBLAYER0 {
            subLayerKey: instance.sublayer,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(label.as_mut_ptr()),
                ..Default::default()
            },
            weight: 0x100,
            ..Default::default()
        };
        check(unsafe { FwpmSubLayerAdd0(instance.handle, &layer, None) })?;
        Ok(instance)
    }
    pub fn add(&self, target: &BlockTarget) -> Result<u64> {
        use std::net::IpAddr;
        use windows::{
            Win32::NetworkManagement::WindowsFilteringPlatform::*,
            core::{GUID, PCWSTR, PWSTR},
        };
        anyhow::ensure!(
            target.port() != 0 && !target.address().is_unspecified(),
            "Exact address and port required"
        );
        anyhow::ensure!(
            !target.application().contains('\0')
                && std::path::Path::new(target.application()).is_absolute(),
            "Absolute application path required"
        );
        let name: Vec<u16> = target.application().encode_utf16().chain(Some(0)).collect();
        struct Blob(*mut FWP_BYTE_BLOB);
        impl Drop for Blob {
            fn drop(&mut self) {
                unsafe {
                    FwpmFreeMemory0(&mut self.0 as *mut _ as *mut *mut std::ffi::c_void);
                }
            }
        }
        let mut app = Blob(std::ptr::null_mut());
        check(unsafe { FwpmGetAppIdFromFileName0(PCWSTR(name.as_ptr()), &mut app.0) })?;
        let outbound = matches!(target, BlockTarget::Destination { .. });
        let mut v6 = FWP_BYTE_ARRAY16::default();
        let value = match target.address() {
            IpAddr::V4(ip) => FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT32,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    uint32: u32::from_be_bytes(ip.octets()),
                },
            },
            IpAddr::V6(ip) => {
                v6.byteArray16 = ip.octets();
                FWP_CONDITION_VALUE0 {
                    r#type: FWP_BYTE_ARRAY16_TYPE,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        byteArray16: &mut v6,
                    },
                }
            }
        };
        let mut conditions = [
            FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_ALE_APP_ID,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_BYTE_BLOB_TYPE,
                    Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: app.0 },
                },
            },
            FWPM_FILTER_CONDITION0 {
                fieldKey: if outbound {
                    FWPM_CONDITION_IP_REMOTE_ADDRESS
                } else {
                    FWPM_CONDITION_IP_LOCAL_ADDRESS
                },
                matchType: FWP_MATCH_EQUAL,
                conditionValue: value,
            },
            FWPM_FILTER_CONDITION0 {
                fieldKey: if outbound {
                    FWPM_CONDITION_IP_REMOTE_PORT
                } else {
                    FWPM_CONDITION_IP_LOCAL_PORT
                },
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        uint16: target.port(),
                    },
                },
            },
            FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_PROTOCOL,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint8: 6 },
                },
            },
        ];
        let layer = match (outbound, target.address().is_ipv4()) {
            (true, true) => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            (true, false) => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            (false, true) => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            (false, false) => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        };
        let mut label: Vec<u16> = "VASP expiring block"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let filter = FWPM_FILTER0 {
            filterKey: GUID::from_u128(uuid::Uuid::new_v4().as_u128()),
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(label.as_mut_ptr()),
                ..Default::default()
            },
            layerKey: layer,
            subLayerKey: self.sublayer,
            action: FWPM_ACTION0 {
                r#type: FWP_ACTION_BLOCK,
                ..Default::default()
            },
            numFilterConditions: conditions.len() as u32,
            filterCondition: conditions.as_mut_ptr(),
            ..Default::default()
        };
        let mut id = 0;
        check(unsafe { FwpmFilterAdd0(self.handle, &filter, None, Some(&mut id)) })?;
        Ok(id)
    }
    pub fn remove(&self, id: u64) -> Result<()> {
        check(unsafe {
            windows::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmFilterDeleteById0(
                self.handle,
                id,
            )
        })
    }

    /// Read a filter key for recovery assertions; no borrowed WFP pointers escape.
    #[cfg(feature = "wfp-recovery-tests")]
    pub fn key(&self, id: u64) -> Result<uuid::Uuid> {
        use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
        let mut filter = std::ptr::null_mut();
        check(unsafe { FwpmFilterGetById0(self.handle, id, &mut filter) })?;
        let key = unsafe { (*filter).filterKey.to_u128() };
        unsafe {
            FwpmFreeMemory0(&mut filter as *mut _ as *mut *mut std::ffi::c_void);
        }
        Ok(uuid::Uuid::from_u128(key))
    }

    #[cfg(feature = "wfp-recovery-tests")]
    pub fn contains_key(&self, key: uuid::Uuid) -> Result<bool> {
        use windows::Win32::{
            Foundation::FWP_E_FILTER_NOT_FOUND, NetworkManagement::WindowsFilteringPlatform::*,
        };
        let mut filter = std::ptr::null_mut();
        let code = unsafe {
            FwpmFilterGetByKey0(
                self.handle,
                &windows::core::GUID::from_u128(key.as_u128()),
                &mut filter,
            )
        };
        if code == FWP_E_FILTER_NOT_FOUND.0 as u32 {
            return Ok(false);
        }
        check(code)?;
        unsafe {
            FwpmFreeMemory0(&mut filter as *mut _ as *mut *mut std::ffi::c_void);
        }
        Ok(true)
    }
}
#[cfg(windows)]
fn check(code: u32) -> Result<()> {
    if code != 0 {
        anyhow::bail!("Windows Filtering Platform error {code}");
    }
    Ok(())
}
#[cfg(windows)]
impl Drop for DynamicSession {
    fn drop(&mut self) {
        unsafe {
            windows::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmEngineClose0(
                self.handle,
            );
        }
    }
}

/// Interrupt time includes sleep. No wall-clock correction can extend this deadline.
#[cfg(windows)]
pub fn recovery_sample() -> vasp_core::recovery::Sample {
    vasp_core::recovery::Sample {
        // SAFETY: no pointers; Windows supplies a boot-relative 100ns clock including sleep.
        awake_and_sleep_ms: unsafe {
            windows::Win32::System::WindowsProgramming::QueryInterruptTime()
        } / 10_000,
        wall_seconds: vasp_core::now(),
    }
}

/// Native lease expiry. The independent supervisor is still required for a hung owner.
/// An expiry failure closes the entire dynamic session instead of retaining filters.
pub struct LeaseSession {
    session: Option<DynamicSession>,
    leases: Vec<(u64, vasp_core::recovery::RecoveryGuard, u64)>,
}
#[cfg(windows)]
impl LeaseSession {
    pub fn open() -> Result<Self> {
        Ok(Self {
            session: Some(DynamicSession::open()?),
            leases: vec![],
        })
    }
    pub fn add(&mut self, target: &BlockTarget, expires_at: u64) -> Result<u64> {
        self.expire()?;
        let now = recovery_sample();
        if expires_at <= now.wall_seconds
            || expires_at - now.wall_seconds > 600
            || self.leases.len() >= 3
        {
            anyhow::bail!("Invalid lease");
        }
        let guard =
            vasp_core::recovery::RecoveryGuard::new(now, expires_at - now.wall_seconds, 10_000)
                .map_err(anyhow::Error::msg)?;
        let id = self
            .session
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Session invalidated"))?
            .add(target)?;
        self.leases.push((id, guard, 0));
        Ok(id)
    }
    pub fn expire(&mut self) -> Result<()> {
        use vasp_core::recovery::StopReason;
        let now = recovery_sample();
        let result = (|| -> Result<()> {
            let session = self
                .session
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Session invalidated"))?;
            // Per-lease sequence is advanced only once per poll, including newly added leases.
            for (id, guard, sequence) in &mut self.leases {
                *sequence = sequence
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("Sequence overflow"))?;
                match guard.heartbeat(*sequence, now) {
                    Err(StopReason::Expired) => session.remove(*id)?,
                    Err(reason) => anyhow::bail!(reason),
                    Ok(()) => {}
                }
            }
            self.leases
                .retain_mut(|(_, guard, _)| guard.check(now).is_ok());
            Ok(())
        })();
        if result.is_err() {
            self.leases.clear();
            self.session.take(); // Closing the dynamic session removes every owned filter.
        }
        result
    }
}

#[cfg(all(test, windows, feature = "wfp-recovery-tests"))]
mod recovery_tests {
    use super::*;
    #[test]
    #[ignore = "Creates dynamic WFP filters; disposable elevated VM only"]
    fn expiry_failure_closes_every_filter_and_invalidates_session() -> Result<()> {
        anyhow::ensure!(
            std::env::var("VASP_DISPOSABLE_WFP_TEST").as_deref() == Ok("1"),
            "Explicit disposable-VM opt-in required"
        );
        let target = BlockTarget::Destination {
            application: std::env::current_exe()?.to_string_lossy().into_owned(),
            address: std::net::Ipv4Addr::LOCALHOST.into(),
            port: 49153,
        };
        let inspector = DynamicSession::open()?;
        let mut leases = LeaseSession::open()?;
        let first = leases.add(&target, vasp_core::now() + 2)?;
        let second = leases.add(&target, vasp_core::now() + 30)?;
        let second_key = inspector.key(second)?;
        leases.add(&target, vasp_core::now() + 30)?;
        anyhow::ensure!(
            leases.add(&target, vasp_core::now() + 30).is_err(),
            "Fourth lease accepted"
        );
        // Deterministic native deletion fault: expiry encounters a missing owned filter.
        leases.session.as_ref().unwrap().remove(first)?;
        std::thread::sleep(std::time::Duration::from_millis(2100));
        anyhow::ensure!(leases.expire().is_err(), "Fault was not detected");
        anyhow::ensure!(
            !inspector.contains_key(second_key)?,
            "Other filter survived failed expiry"
        );
        anyhow::ensure!(
            leases.add(&target, vasp_core::now() + 30).is_err(),
            "Invalidated session reopened"
        );
        Ok(())
    }
}
