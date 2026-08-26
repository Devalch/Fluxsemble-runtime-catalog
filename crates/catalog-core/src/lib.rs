use std::{error::Error, fmt};

mod bundle;
mod canonical;
mod qualification;
mod signature;
mod source;
mod wire;

pub use bundle::*;
pub use canonical::{canonical_catalog_payload, catalog_payload_sha256};
pub use qualification::*;
pub use signature::*;
pub use source::*;
pub use wire::*;

/// Closed, non-echoing failures from the data-only catalog core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreError {
    InvalidCatalog,
}

impl fmt::Display for CoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid catalog")
    }
}

impl Error for CoreError {}

/// Shared catalog package names for bootstrap validation.
pub const PACKAGES: &[&str] = &[
    "catalog-acquire",
    "catalog-core",
    "catalog-publish",
    "catalog-sign",
];

pub fn package_count() -> usize {
    PACKAGES.len()
}

#[cfg(test)]
mod tests {
    use super::{PACKAGES, package_count};

    #[test]
    fn exposes_expected_packages() {
        assert_eq!(package_count(), 4);
        assert_eq!(PACKAGES[0], "catalog-acquire");
        assert_eq!(PACKAGES[3], "catalog-sign");
    }
}
