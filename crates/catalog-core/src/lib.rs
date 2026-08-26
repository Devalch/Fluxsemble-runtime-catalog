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
