#!/usr/bin/env bash
set -euo pipefail

packages=$(cargo metadata --offline --locked --no-deps --format-version 1 | \
  python3 -c 'import json,sys; print("\n".join(sorted(p["name"] for p in json.load(sys.stdin)["packages"])))')
test "$packages" = $'catalog-acquire\ncatalog-core\ncatalog-installer-verify\ncatalog-latest-transport\ncatalog-publish\ncatalog-sign\ncatalog-wizard'

cargo fmt --all --check
cargo clippy --offline --locked --workspace --all-targets -- -D warnings
# The launcher tests execute this isolated, nonproduction signer; build it as
# test setup rather than relying on a stale or missing artifact from an earlier run.
RUSTFLAGS='-C target-feature=+crt-static -C relocation-model=static' \
  cargo build --offline --locked --release --target x86_64-unknown-linux-musl \
  -p catalog-sign --features fixture-tools --bin catalog-sign-fixture
cargo test --offline --locked --workspace
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_generate_approved_release_evidence.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_authentic_candidate_oracle.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_catalog_parity_cases.py
./scripts/check-boundaries.sh
git diff --check
