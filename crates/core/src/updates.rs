//! Verification only. No installer or model-facing update capability.
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateManifest {
    pub schema: u16,
    pub sequence: u64,
    pub expires_at: u64,
    pub version: String,
    pub sha256: String,
    pub size: u64,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedUpdate {
    pub manifest_base64: String,
    pub signatures: Vec<UpdateSignature>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateSignature {
    pub key_id: String,
    pub signature_base64: String,
}

pub fn verify(
    bytes: &[u8],
    trusted: &[(String, [u8; 32])],
    threshold: usize,
    min_sequence: u64,
    now: u64,
) -> Result<UpdateManifest, String> {
    if threshold == 0 || threshold > trusted.len() || bytes.len() > 65536 {
        return Err("Invalid update trust configuration or size".into());
    }
    let envelope: SignedUpdate = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    let payload = STANDARD
        .decode(&envelope.manifest_base64)
        .map_err(|_| "Invalid update payload")?;
    let mut signed = std::collections::BTreeSet::new();
    for s in &envelope.signatures {
        if let Some((id, key)) = trusted.iter().find(|(id, _)| id == &s.key_id) {
            let key = VerifyingKey::from_bytes(key).map_err(|_| "Invalid signing key")?;
            let raw = STANDARD
                .decode(&s.signature_base64)
                .map_err(|_| "Invalid signature encoding")?;
            let sig = Signature::from_slice(&raw).map_err(|_| "Invalid signature")?;
            if key.verify(&payload, &sig).is_ok() {
                signed.insert(id.clone());
            }
        }
    }
    if signed.len() < threshold {
        return Err("Update signature threshold not met".into());
    }
    let m: UpdateManifest = serde_json::from_slice(&payload).map_err(|e| e.to_string())?;
    if m.schema != 1
        || m.sequence <= min_sequence
        || m.expires_at <= now
        || m.size == 0
        || m.size > 512 * 1024 * 1024
        || m.sha256.len() != 64
        || hex::decode(&m.sha256).is_err()
    {
        return Err("Expired, rolled back, or invalid update metadata".into());
    }
    Ok(m)
}
pub fn verify_artifact(m: &UpdateManifest, bytes: &[u8]) -> bool {
    bytes.len() as u64 == m.size && crate::digest(bytes) == m.sha256
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    #[test]
    fn signature_expiry_rollback_and_content() {
        let k = SigningKey::from_bytes(&[42; 32]);
        let keys = vec![("release".into(), k.verifying_key().to_bytes())];
        let m = UpdateManifest {
            schema: 1,
            sequence: 2,
            expires_at: 200,
            version: "1.0.0".into(),
            sha256: crate::digest(b"binary"),
            size: 6,
        };
        let b = serde_json::to_vec(&m).unwrap();
        let e = SignedUpdate {
            manifest_base64: STANDARD.encode(&b),
            signatures: vec![UpdateSignature {
                key_id: "release".into(),
                signature_base64: STANDARD.encode(k.sign(&b).to_bytes()),
            }],
        };
        let raw = serde_json::to_vec(&e).unwrap();
        let m = verify(&raw, &keys, 1, 1, 100).unwrap();
        assert!(verify_artifact(&m, b"binary"));
        assert!(!verify_artifact(&m, b"tamper"));
        assert!(verify(&raw, &keys, 1, 2, 100).is_err());
        assert!(verify(&raw, &keys, 1, 1, 200).is_err());
        assert!(verify(&raw, &keys, 0, 1, 100).is_err());
    }
}
