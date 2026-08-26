#!/usr/bin/env bash
set -euo pipefail

packages=$(cargo metadata --no-deps --format-version 1 | \
  python3 -c 'import json,sys; print("\n".join(sorted(p["name"] for p in json.load(sys.stdin)["packages"])))')
test "$packages" = $'catalog-acquire\ncatalog-core\ncatalog-publish\ncatalog-sign'

cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
./scripts/check-boundaries.sh
git diff --check
