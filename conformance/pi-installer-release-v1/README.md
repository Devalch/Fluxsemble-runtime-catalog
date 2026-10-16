# Immutable public installer inputs

This directory contains public DATA admitted from Fluxsemble's independently replayed capture. It has no Fluxsemble source or runtime dependency. The admission document is 63555 bytes, SHA256 `20b4402e9bedbb2c92caa2b04f4ee7552740c0c2ac2eb8c331c8e3f72f87db07`; its 132 records retain each original public path, URL, length and digest. The source corpus digest is `e13fdcc5ed2823044c5b8fc9e9d081c86bf1cf7dd69e18e72b7524a324a81d4f`.

`generated/` contains inert V2 intent, observed package inputs and evidence emitted by the existing `generate-approved-release-evidence.py` owner with explicit admission identity. The Node checksum cleartext is derived from the retained authenticated signed checksum bytes, not a fresh unsigned transport observation. The original public bytes are unchanged.

`catalog-installer-verify/tests/offline_verification.rs` independently derives the complete profile and observations from these archives, then replays the generated intent through the pure verifier. The independent Python oracle projects the public role and sequence mapping from the admitted source profile. These checks neither create qualification nor authorize signing, publication or activation.

Legacy catalog-v1 parser and signature vectors are explicitly synthetic. Old authentic corpus snapshots and their qualification/signing ceremony are historical; replay requires the original revision and original authenticated inputs. Immutable prior reports remain historical, and do not qualify these inputs.
