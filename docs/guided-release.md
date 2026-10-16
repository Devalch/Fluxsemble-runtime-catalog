# Guided runtime catalog release

For normal releases, run:

```bash
catalog-wizard release
```

The wizard will ask you to choose a Pi version, confirm a Node version, and choose dry-run or guided publish. It prepares a qualification request and pauses while a Fluxsemble maintainer qualifies the exact final profile against its existing supported behavioral contracts and verified consumer build. When the returned qualification directory is ready, continue with:

```bash
catalog-wizard resume
```

The wizard independently verifies the returned canonical `build-binding-v1.json` and `qualification-v1.json`, exact final subject, all required passing results and unchanged contracts before signing or publishing. A compatible later Pi release needs no consumer rebuild or development-reference refresh. A local unsigned candidate is not a signed, published or installed release. See [the wire contract](pi-installer-lock-contract.md) for the exact public handoff; no consumer source checkout is a producer prerequisite.

First-time setup:

```bash
catalog-wizard trust-machine
catalog-wizard check
```

Only when replacing the signing key:

```bash
catalog-wizard rotate-key
```

If a release is interrupted:

```bash
catalog-wizard resume
```

For help:

```bash
catalog-wizard -h
catalog-wizard release --help
```
