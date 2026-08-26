pub fn summary() -> String {
    format!("packages={}", catalog_core::PACKAGES.len())
}

#[cfg(test)]
mod tests {
    use super::summary;

    #[test]
    fn reports_bootstrap_summary() {
        assert_eq!(summary(), "packages=4");
    }
}
