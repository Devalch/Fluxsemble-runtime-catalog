# V2 Producer Independence Implementation Plan

**Goal:** Build and publish the Pi catalog through the existing V2 producer workflow without consumer qualification.

**Architecture:** Keep V2 source/intent as the producer authority; replace consumer-dependent profile and signing inputs with producer-only facts and versioned signed evidence. Consumer compatibility occurs downstream after publication. Historical on-disk artifacts are preserved and never rewritten.

**Tech Stack:** Rust, canonical JSON, Ed25519, isolated signer and catalog publisher.

**Spec:** `docs/superpowers/specs/2026-11-20-v2-producer-independence.md`

## Constraints and review focus

- Work exclusively in this repository; no other repository builds or tests.
- No fabricated compatibility result, consumer contract or consumer build claim.
- Reject tampered archives, graph, source bytes, metadata, inventory and signatures.
- Preserve source and sequence binding and signing/publication safety gates.
- Publish Pi 1.6.0 as latest; consumer compatibility is checked separately afterward.
- Preserve the old sequence-8 state; do not reinterpret it under new semantics.

## Tasks

1. Define strict producer-only V2 profile, source and signed catalog representation; test closed schemas and immutable subject bindings.
2. Update installer discovery, producer evidence and independent replay to use V2 producer facts, with integrity and graph-negative tests.
3. Update acquisition transfer, isolated signer and publisher to bind the producer-only source and evidence, without requiring a consumer qualification; test real boundary and tampering paths.
4. Update the V2 wizard and resumability to prepare, sign and publish without a qualification pause; test state transitions and preserve earlier work.
5. Update current release documentation; verify all affected repository boundaries, prepare Pi 1.6.0 against a committed clean source, and perform the separately authorized release ceremony.
