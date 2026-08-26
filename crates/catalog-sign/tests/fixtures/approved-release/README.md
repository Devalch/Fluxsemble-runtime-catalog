# Approved initial release evidence

These files are bounded, canonical, public test evidence for the initial Pi 0.83.0 catalog release. Production `catalog-sign` compiles only the two domain-separated admission digests; it does not read these fixtures or any Fluxsemble checkout.

`package-input-manifest-v1.json` is the exact Task 5 canonical 78,346-byte package-input manifest. `initial-release-intent-v1.json` carries the complete approved immutable release semantic, including both one-entry artifact inventories, all 139 locked package records, immutable release metadata, and tag-bound support URLs. Its timestamps are representative fixture freshness only and are not compiled production authority. `evidence-manifest-v1.json` records source hashes, archive-member derivation, exclusions, and local fixture hashes.

`scripts/generate-approved-release-evidence.py` accepts explicit matrix, approval-report, and authenticated public-corpus paths. It has no built-in external checkout path, network, signing, or publication behavior. Regeneration into a temporary directory followed by a byte comparison proves drift without making Fluxsemble or an artifact repository a test, build, or runtime dependency. The ignored `CATALOG_AUTHENTIC_PUBLIC_CORPUS` test likewise accepts only an environment-supplied public corpus and is run explicitly; ordinary tests remain repository-independent.

Task 7 will exercise the authentic transferred-artifact and publication journey at its own remote/repository boundary. Task 6 retains only enough public evidence to prove exact production admission and the shared assembly/finalization body; it does not commit the external archive corpus, access the production key, sign a production release, or publish anything.
