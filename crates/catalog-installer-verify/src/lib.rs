//! Pure bounded installer verification. No filesystem, network, process or signing capabilities.
pub mod archive;
mod error;
mod installer;
pub mod policy;
pub use error::AcquireError;
pub use installer::*;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoverPiReleaseRequest {
    pub sequence: u64,
    pub generated_at: String,
    pub expires_at: String,
    pub pi_version: String,
    pub node_version: String,
    pub title: String,
    pub notes: String,
    pub target: String,
    pub installer_policy: Option<crate::PiInstallerDiscoveryPolicy>,
}
