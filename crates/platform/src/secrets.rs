use anyhow::{Result, bail};
pub fn read(name: &str) -> Result<String> {
    if !matches!(name, "VASP/OpenAI" | "VASP/LAN") {
        bail!("Unknown credential slot");
    }
    #[cfg(windows)]
    {
        native::read(name)
    }
    #[cfg(not(windows))]
    {
        bail!("Windows Credential Manager is required")
    }
}
pub fn write(name: &str, secret: &str) -> Result<()> {
    if !matches!(name, "VASP/OpenAI" | "VASP/LAN") || secret.is_empty() || secret.len() > 2048 {
        bail!("Invalid credential slot or size");
    }
    #[cfg(windows)]
    {
        native::write(name, secret)
    }
    #[cfg(not(windows))]
    {
        bail!("Windows Credential Manager is required")
    }
}
#[cfg(windows)]
mod native {
    use super::*;
    use windows::{
        Win32::Security::Credentials::*,
        core::{PCWSTR, PWSTR},
    };
    pub fn read(name: &str) -> Result<String> {
        let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let mut ptr = std::ptr::null_mut();
        // SAFETY: CredRead owns its returned allocation; freed after bounded copy.
        unsafe {
            CredReadW(PCWSTR(name.as_ptr()), CRED_TYPE_GENERIC, None, &mut ptr)?;
            if ptr.is_null() {
                bail!("Credential not found");
            }
            let size = (*ptr).CredentialBlobSize as usize;
            if size > 2048 {
                CredFree(ptr.cast());
                bail!("Credential exceeds size limit");
            }
            let bytes = std::slice::from_raw_parts((*ptr).CredentialBlob, size).to_vec();
            CredFree(ptr.cast());
            Ok(String::from_utf8(bytes)?)
        }
    }
    pub fn write(name: &str, secret: &str) -> Result<()> {
        let mut name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let mut bytes = secret.as_bytes().to_vec();
        let credential = CREDENTIALW {
            Type: CRED_TYPE_GENERIC,
            TargetName: PWSTR(name.as_mut_ptr()),
            CredentialBlobSize: bytes.len() as u32,
            CredentialBlob: bytes.as_mut_ptr(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            ..Default::default()
        };
        // SAFETY: buffers outlive the synchronous call; Credential Manager copies them.
        let result = unsafe { CredWriteW(&credential, 0) };
        bytes.fill(0);
        result?;
        Ok(())
    }
}
