#!/usr/bin/env bash
set -euo pipefail

: "${CATALOG_AUTHENTIC_PUBLIC_CORPUS:?set an absolute authenticated public corpus path}"
case "$CATALOG_AUTHENTIC_PUBLIC_CORPUS" in
  /*) ;;
  *) echo "authenticated corpus path must be absolute" >&2; exit 1 ;;
esac

root=$(mktemp -d "${TMPDIR:-/tmp}/catalog-authentic-launcher.XXXXXXXX")
chmod 0700 "$root"
trap 'rm -rf "$root"' EXIT
export CATALOG_AUTHENTIC_JOURNEY_EXPORT="$root/export"
mkdir -m 0700 "$CATALOG_AUTHENTIC_JOURNEY_EXPORT"

cargo test --locked -p catalog-sign \
  signing::tests::environment_supplied_public_corpus_exercises_public_production_assembly_and_finalization \
  -- --ignored --exact
cargo build --locked -p catalog-sign --bin catalog-sign-launcher

static_signer=target/x86_64-unknown-linux-musl/release/catalog-sign
[ -x "$static_signer" ] || {
  echo "build the approved static production signer outside isolation first" >&2
  exit 1
}
cp "$static_signer" "$root/catalog-sign-static"
chmod 0500 "$root/catalog-sign-static"
python3 - "$root" <<'PY'
import hashlib, json, os, pathlib, sys
root = pathlib.Path(sys.argv[1])
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
config = {
    "bwrap_path": "/usr/bin/bwrap",
    "bwrap_sha256": digest(pathlib.Path("/usr/bin/bwrap")),
    "schema_version": 1,
    "signer_path": str(root / "catalog-sign-static"),
    "signer_sha256": digest(root / "catalog-sign-static"),
}
path = root / "launcher-config-v1.json"
path.write_bytes(json.dumps(config, sort_keys=True, separators=(",", ":")).encode())
os.chmod(path, 0o600)
PY

launcher=target/debug/catalog-sign-launcher
"$launcher" assemble-intent --config "$root/launcher-config-v1.json" \
  --input "$root/export/intent-input" --output "$root/assemble-output"
"$launcher" finalize --config "$root/launcher-config-v1.json" \
  --input "$root/export/final-input" --output "$root/finalize-output"

PYTHONDONTWRITEBYTECODE=1 python3 scripts/authentic-candidate-oracle.py \
  "$root/export/intent-input" "$root/oracle-intent-candidate.json"
PYTHONDONTWRITEBYTECODE=1 python3 scripts/authentic-candidate-oracle.py \
  "$root/export/final-input" "$root/oracle-final-candidate.json"
cmp --silent "$root/oracle-intent-candidate.json" "$root/oracle-final-candidate.json" || {
  echo "independent intent/final oracle projections differ" >&2; exit 1
}
expected_candidate_sha256=7dba62c8b44883cbd7b3615fd9fe3b1a08a3aa2c75c7729704c14804d1cc2a2b
actual_oracle_sha256=$(sha256sum "$root/oracle-intent-candidate.json" | cut -d' ' -f1)
[ "$actual_oracle_sha256" = "$expected_candidate_sha256" ] || {
  echo "independent candidate digest drift: $actual_oracle_sha256" >&2; exit 1
}

python3 - "$root" "$expected_candidate_sha256" <<'PY'
import hashlib, json, os, pathlib, stat, sys
root = pathlib.Path(sys.argv[1])
expected_candidate_sha256 = sys.argv[2]
def digest_bytes(data): return hashlib.sha256(data).hexdigest()
def canonical(value): return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
def validate(label, input_root, output_root, mode):
    manifest_path = output_root / "transfer-manifest-v1.json"
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    assert canonical(manifest) == manifest_bytes
    assert set(manifest) == {"entries", "input_transfer_sha256", "isolation_attestation", "kind", "schema_version"}
    assert manifest["schema_version"] == 1 and manifest["kind"] == "signer_output"
    assert manifest["input_transfer_sha256"] == digest_bytes((input_root / "transfer-manifest-v1.json").read_bytes())
    assert manifest["isolation_attestation"]["mode"] == mode
    expected = set()
    inventory = []
    for entry in manifest["entries"]:
        relative = entry["relative_path"]
        parts = pathlib.PurePosixPath(relative).parts
        assert relative and not relative.startswith("/") and ".." not in parts
        path = output_root / relative
        metadata = path.lstat()
        assert stat.S_ISREG(metadata.st_mode) and not path.is_symlink()
        assert stat.S_IMODE(metadata.st_mode) == 0o400
        data = path.read_bytes()
        assert len(data) == entry["size"] and digest_bytes(data) == entry["sha256"]
        expected.add(relative)
        inventory.append({"path": relative, "mode": "0400", "size": len(data), "sha256": digest_bytes(data)})
    actual = set()
    for path in output_root.rglob("*"):
        relative = path.relative_to(output_root).as_posix()
        metadata = path.lstat()
        assert not path.is_symlink()
        if path.is_dir():
            assert stat.S_IMODE(metadata.st_mode) == 0o700
        else:
            actual.add(relative)
    assert actual == expected | {"transfer-manifest-v1.json"}
    candidate = (output_root / "candidate.json").read_bytes()
    assert canonical(json.loads(candidate)) == candidate
    print(json.dumps({"journey": label, "input_transfer_sha256": manifest["input_transfer_sha256"], "entries": inventory}, sort_keys=True))
    return candidate
assemble = validate("assemble-intent", root / "export/intent-input", root / "assemble-output", "assemble-intent")
finalized = validate("finalize", root / "export/final-input", root / "finalize-output", "finalize")
oracle = (root / "oracle-intent-candidate.json").read_bytes()
assert assemble == oracle, "production assemble differs from independent oracle"
assert finalized == oracle, "production finalize differs from independent oracle"
assert digest_bytes(oracle) == expected_candidate_sha256
print(json.dumps({"independent_candidate_sha256": digest_bytes(oracle), "size": len(oracle), "assemble_equal": True, "finalize_equal": True}, sort_keys=True))
for name in ["assemble-output", "finalize-output"]:
    snapshot = {}
    for path in (root / name).rglob("*"):
        if path.is_file(): snapshot[path.relative_to(root / name).as_posix()] = path.read_bytes()
    (root / f"{name}.snapshot").write_bytes(hashlib.sha256(b"".join(k.encode()+b"\0"+v for k,v in sorted(snapshot.items()))).digest())
PY

if "$launcher" assemble-intent --config "$root/launcher-config-v1.json" \
  --input "$root/export/intent-input" --output "$root/assemble-output"; then
  echo "assemble no-clobber retry unexpectedly succeeded" >&2; exit 1
fi
if "$launcher" finalize --config "$root/launcher-config-v1.json" \
  --input "$root/export/final-input" --output "$root/finalize-output"; then
  echo "finalize no-clobber retry unexpectedly succeeded" >&2; exit 1
fi
python3 - "$root" <<'PY'
import hashlib, pathlib, sys
root = pathlib.Path(sys.argv[1])
for name in ["assemble-output", "finalize-output"]:
    snapshot = {}
    for path in (root / name).rglob("*"):
        if path.is_file(): snapshot[path.relative_to(root / name).as_posix()] = path.read_bytes()
    actual = hashlib.sha256(b"".join(k.encode()+b"\0"+v for k,v in sorted(snapshot.items()))).digest()
    assert actual == (root / f"{name}.snapshot").read_bytes()
PY

echo "authentic production assemble/finalize launcher journeys: PASS"
