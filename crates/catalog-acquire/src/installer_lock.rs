//! Network discovery adapter for the shared pure installer verifier.
use crate::npm::HttpReleaseDiscoveryTransport;
use crate::{AcquireError, DiscoverPiReleaseRequest, ReleaseDiscoveryTransport};
pub use catalog_installer_verify::{
    InstallerInputSourceV1, PackageInputManifestV2, PiInstallerCandidateV1,
    PiInstallerDiscoveryPolicy, is_installer_asset_url,
};
pub fn discover_pi_installer_release(
    request: DiscoverPiReleaseRequest,
) -> Result<PiInstallerCandidateV1, AcquireError> {
    discover_pi_installer_release_with_transport(request, &HttpReleaseDiscoveryTransport::new()?)
}
#[doc(hidden)]
pub fn discover_pi_installer_release_with_transport(
    request: DiscoverPiReleaseRequest,
    transport: &dyn ReleaseDiscoveryTransport,
) -> Result<PiInstallerCandidateV1, AcquireError> {
    catalog_installer_verify::derive_installer_release(request, &DiscoveryInputs(transport))
}
struct DiscoveryInputs<'a>(&'a dyn ReleaseDiscoveryTransport);
impl catalog_installer_verify::InstallerInputs for DiscoveryInputs<'_> {
    fn read(&self, url: &str, maximum: usize) -> Result<Vec<u8>, AcquireError> {
        self.0.fetch(url, maximum)
    }
}
