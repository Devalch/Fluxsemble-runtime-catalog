# Fluxsemble Runtime Catalog

Standalone Rust workspace for acquiring, signing, and publishing Fluxsemble runtime catalog artifacts.

Generated release output is never committed. Owner-private release work stays in ignored paths such as `.release-work/`, `catalog-v1.json`, and `signed-release-bundle/`.

The production private key is never accepted by `catalog-acquire` or `catalog-publish`.
