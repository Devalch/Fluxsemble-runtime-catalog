#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("check-catalog-parity.py")
SPEC = importlib.util.spec_from_file_location("check_catalog_parity", SCRIPT)
assert SPEC and SPEC.loader
parity = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(parity)
CANDIDATE: Path
SYNTHETIC_PAYLOAD = Path(__file__).parents[1] / "conformance/catalog-v1/valid-payload.json"


class CatalogParityCaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global CANDIDATE
        cls.fixture = tempfile.TemporaryDirectory(prefix='synthetic-v1-parity-')
        CANDIDATE = Path(cls.fixture.name) / 'candidate.json'
        CANDIDATE.write_bytes(parity.canonical(json.loads(SYNTHETIC_PAYLOAD.read_bytes())))

    @classmethod
    def tearDownClass(cls):
        cls.fixture.cleanup()

    def test_every_rejection_is_one_exact_pointer_change_from_the_candidate(self):
        _data, candidate = parity.load_candidate(CANDIDATE)
        cases = parity.build_cases(candidate)
        self.assertEqual(len(cases), 8)
        for case, data in cases:
            value = json.loads(data, object_pairs_hook=parity.reject_duplicates)
            self.assertEqual(
                parity.json_differences(candidate, value),
                [(case["pointer"], case["before"], case["after"])],
                case["case"],
            )
        by_name = {case["case"]: case for case, _data in cases}
        self.assertEqual(
            by_name["canonical-decimal"],
            {
                "case": "canonical-decimal",
                "category": "canonical",
                "pointer": "/sequence",
                "before": "42",
                "after": "042",
            },
        )
        self.assertEqual(
            by_name["artifact-size"],
            {
                "case": "artifact-size",
                "category": "artifact",
                "pointer": "/providers/0/releases/0/components/0/artifacts/0/size_bytes",
                "before": "31457280",
                "after": "0",
            },
        )

    def test_driver_emits_the_frozen_matrix_with_runtime_supplied_tools(self):
        with tempfile.TemporaryDirectory(prefix="catalog-parity-test-") as temporary:
            root = Path(temporary)
            old = root / "old-tool"
            new = root / "new-tool"
            old.write_text(
                """#!/usr/bin/env python3
import hashlib, pathlib, sys
expected = 'a0eab9ad1e9741f8cf8cac9968d8d20cddcbee58e237ed7581202b2268488e5c'
command = sys.argv[1]
source = pathlib.Path(sys.argv[3]).read_bytes()
accepted = hashlib.sha256(source).hexdigest() == expected
if command == 'validate':
    if accepted:
        print(f'valid sequence=42 payload_sha256={expected}')
        raise SystemExit(0)
    print('runtime catalog command failed', file=sys.stderr)
    raise SystemExit(2)
if command == 'canonicalize' and accepted:
    pathlib.Path(sys.argv[5]).write_bytes(source)
    print(f'canonical payload_sha256={expected}')
    raise SystemExit(0)
raise SystemExit(2)
""",
                encoding="utf-8",
            )
            new.write_text(
                """#!/usr/bin/env python3
import hashlib, pathlib, sys
expected = 'a0eab9ad1e9741f8cf8cac9968d8d20cddcbee58e237ed7581202b2268488e5c'
source = pathlib.Path(sys.argv[1]).read_bytes()
if hashlib.sha256(source).hexdigest() != expected:
    raise SystemExit(2)
print(f'valid sequence=42 payload_sha256={expected} size=2553')
""",
                encoding="utf-8",
            )
            old.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            new.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            matrix = parity.run_matrix(CANDIDATE, old, new)
        self.assertEqual(len(matrix), 1_430)
        self.assertEqual(
            hashlib.sha256(matrix).hexdigest(),
            "69675d8bcb982d503a1de753b6ae2183a9a5555b1822e52f9135ced5690758ed",
        )

    def test_candidate_identity_and_manifest_before_values_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="catalog-parity-candidate-") as temporary:
            changed = Path(temporary) / "candidate.json"
            changed.write_bytes(CANDIDATE.read_bytes() + b" ")
            with self.assertRaises(parity.ParityError):
                parity.load_candidate(changed)
        _data, candidate = parity.load_candidate(CANDIDATE)
        changed_manifest = dict(parity.CASE_MANIFEST[0])
        changed_manifest["before"] = 9
        with self.assertRaises(parity.ParityError):
            parity.set_pointer(candidate.copy(), changed_manifest)


if __name__ == "__main__":
    unittest.main()
