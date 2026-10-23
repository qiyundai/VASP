//! Local Windows named-pipe transport. Every pending I/O is completed/cancelled before
//! its OVERLAPPED storage is released. No raw handles escape these wrappers.
#[cfg(windows)]
mod native;
#[cfg(windows)]
pub use native::*;
