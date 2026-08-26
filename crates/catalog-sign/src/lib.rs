pub fn summary() -> String {
    format!("bootstrap:{}", catalog_core::PACKAGES.join(","))
}

#[cfg(test)]
mod tests {
    use super::summary;

    #[test]
    fn reports_bootstrap_summary() {
        assert!(summary().contains("catalog-sign"));
    }
}
