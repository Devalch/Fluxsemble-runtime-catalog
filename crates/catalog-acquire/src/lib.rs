mod http;

pub use http::*;

pub fn summary() -> String {
    format!("bootstrap:{}", catalog_core::package_count())
}

#[cfg(test)]
mod tests {
    use super::summary;

    #[test]
    fn reports_bootstrap_summary() {
        assert_eq!(summary(), "bootstrap:4");
    }
}
