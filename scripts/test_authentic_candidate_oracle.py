#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).with_name("authentic-candidate-oracle.py")
SPEC = importlib.util.spec_from_file_location("authentic_candidate_oracle", SCRIPT)
assert SPEC and SPEC.loader
oracle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(oracle)


class AuthenticCandidateOracleTests(unittest.TestCase):
    def intent(self):
        return {
            "expires_at": "2026-09-26T00:00:00Z",
            "fluxsemble_requirement": "=0.1.0",
            "generated_at": "2026-08-26T00:00:00Z",
            "release": {
                "allowed_origins": ["https://example.invalid"],
                "provider": "builtin:pi",
                "release": {"components": [], "sequence": "release"},
            },
            "sequence": "1",
            "tag": "catalog-v1-sequence-1",
        }

    def test_projection_is_independently_fixed_byte_for_byte(self):
        candidate = oracle.canonical(oracle.project_intent(self.intent()))
        expected = (
            b'{"compatibility_ranges":["=0.1.0"],'
            b'"expires_at":"2026-09-26T00:00:00Z",'
            b'"generated_at":"2026-08-26T00:00:00Z",'
            b'"providers":[{"allowed_origins":["https://example.invalid"],'
            b'"provider_id":"builtin:pi","releases":[{"components":[],'
            b'"sequence":"release"}]}],"schema_version":1,"sequence":"1"}'
        )
        self.assertEqual(candidate, expected)
        self.assertNotIn(b"tag", candidate)

    def test_wrong_projection_or_approved_tuple_cannot_fall_back_to_peer_comparison(self):
        intent = self.intent()
        intent["release"]["release"]["components"] = [{"wrong": True}]
        wrong = oracle.canonical(oracle.project_intent(intent))
        self.assertNotEqual(
            wrong,
            oracle.canonical(oracle.project_intent(self.intent())),
        )
        intent = self.intent()
        intent["fluxsemble_requirement"] = "=0.1.1"
        with self.assertRaises(oracle.OracleError):
            oracle.project_intent(intent)
        self.assertEqual(
            oracle.EXPECTED_CANDIDATE_SHA256,
            "7dba62c8b44883cbd7b3615fd9fe3b1a08a3aa2c75c7729704c14804d1cc2a2b",
        )

    def test_duplicate_members_floats_and_bounds_fail_closed(self):
        with self.assertRaises(oracle.OracleError):
            oracle.load_json(b'{"a":1,"a":1}', "duplicate")
        with self.assertRaises(oracle.OracleError):
            oracle.canonical({"unsafe": 1.5})
        with self.assertRaises(oracle.OracleError):
            oracle.load_json(b"{}" * (oracle.MAX_MANIFEST_BYTES // 2 + 1), "oversize")


if __name__ == "__main__":
    unittest.main()
