# Conformance fixture identity correction

This record documents a nonproduction fixture correction and its immutable conformance tag. It is not a release, production signature, publication receipt, or release-publication claim.

## Immutable v1 evidence

The immutable tag `catalog-v1-conformance-v1` remains at commit `c31d3e747ff5bcc14ed5b82e1f39f37c712591aa`. Its `catalog-test-key-v1` fixture authority used public key `1bd36afee9323f1e3813f68c4d5f2f2b1bae44c0ef6917628ed6afe16aae44a9`. That identity conflicts with Fluxsemble's pre-existing authority for the same key ID, so Fluxsemble fixture trust rejects the v1 envelopes. The v1 tag must not be moved, deleted, or replaced.

## Corrected shared fixture authority

`catalog-test-key-v1` now uses exactly public key `03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8`. The committed nonproduction PKCS#8 fixture derives that public key. Its one-time public test-data source was Fluxsemble commit `f9c107510a84f55282b1c83d63b370f5515127e9`, path `crates/harness-runtime/tests/fixtures/catalog/test-private-key.seed`, with SHA-256 `630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd`. The producer has no continuing source, build, package, test, or runtime dependency on Fluxsemble.

The authorized no-replace correction tag `catalog-v1-conformance-v2` was created and read back at exact commit `d6a1ef91ce596e9d58f83dd01a5f90767baab744`. It is immutable and must not be moved, deleted, or replaced. This tag is nonproduction conformance evidence only; no release or publication is claimed.

## Byte and digest evidence

Only fixture signatures and their dependent manifest/documentation digests changed. Unsigned conformance data remains byte-identical:

- initial exact candidate payload: 55,797 bytes, SHA-256 `7dba62c8b44883cbd7b3615fd9fe3b1a08a3aa2c75c7729704c14804d1cc2a2b`;
- valid payload: 4,224 bytes, SHA-256 `f3e1b4e54a283158c9328ef3f5ffd2dbdb9c441fb4720040e2b7743aec14b640`;
- rejected-fields vector: 1,676 bytes, SHA-256 `dd4d3dfd78312bc02b43d0b7b6766941742ced42c897bd086cf8cf15d4f1bcb4`.

Regenerated signed evidence:

- initial envelope: 55,994 bytes; SHA-256 changed from `036191a94f62afe8a7a547790b1c9d4c54a7c277dc76bfae191601dea5738cac` to `e5e239bf4b3c10841ffc3105f7788782b3376289be3e17b3ae82cef8081d972f`;
- valid envelope: 2,750 bytes; SHA-256 changed from `37e3eb08ec1d9508a02d77b1087c049ab851e6f831d2ee8fe2c3fd63ca8bcc8e` to `716c57e3e361c3f0bcf50ad9eb8c9152eabfa2f0d25fb0dd61430e048616fcc4`;
- conformance manifest: 743 bytes; SHA-256 changed from `91618c929ef725673435347ad9fc3122f338c14030f12e4b90c17618f5d55757` to `fc9808c8228ed4cfeddbab96fb0f0327a8e1eb672c82df230ca021f14f840b7a`.

Production trust, the production key ID and public key, production signing ceremony, schema, source intent, package inputs, candidate semantics, acquisition evidence, and qualification evidence are unchanged. Fixture envelopes continue to be rejected by production verification.
