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

/// Monotonic deadlines bound leases; wall deadlines also catch sleep and clock jumps.
pub struct LeaseSession {
    session: DynamicSession,
    leases: Vec<(u64, std::time::Instant, u64)>,
}
#[cfg(windows)]
impl LeaseSession {
    pub fn open() -> Result<Self> {
        Ok(Self {
            session: DynamicSession::open()?,
            leases: vec![],
        })
    }
    pub fn add(&mut self, target: &BlockTarget, expires_at: u64) -> Result<u64> {
        let now = vasp_core::now();
        if expires_at <= now || expires_at - now > 600 || self.leases.len() >= 3 {
            anyhow::bail!("Invalid lease");
        }
        let id = self.session.add(target)?;
        self.leases.push((
            id,
            std::time::Instant::now() + std::time::Duration::from_secs(expires_at - now),
            expires_at,
        ));
        Ok(id)
    }
    pub fn expire(&mut self) -> Result<()> {
        let now = std::time::Instant::now();
        let wall = vasp_core::now();
        let mut keep = vec![];
        for &(id, deadline, expires) in &self.leases {
            if now >= deadline || wall >= expires {
                self.session.remove(id)?;
            } else {
                keep.push((id, deadline, expires));
            }
        }
        self.leases = keep;
        Ok(())
    }
}
