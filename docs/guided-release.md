# Guided runtime catalog release

For normal releases, run:

```bash
catalog-wizard release
```

The wizard will ask you to choose a Pi version, confirm a Node version, and choose dry-run or guided publish. It prepares a qualification request and pauses while a Fluxsemble maintainer updates and qualifies that version tuple. When the returned qualification directory is ready, continue with:

```bash
catalog-wizard resume
```

The wizard verifies the handoff and confirms before signing or publishing.

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
