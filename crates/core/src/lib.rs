#![forbid(unsafe_code)]
pub mod ai;
pub mod broker;
pub mod feeds;
pub mod matching;
pub mod policy;
pub mod protocol;
pub mod scheduler;
pub mod updates;

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn digest(bytes: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(bytes))
}
