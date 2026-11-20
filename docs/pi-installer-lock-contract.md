# Pi producer contract V2

The catalog producer records verified Pi and Node inputs. It makes no assertion that a consumer supports or has tested the release. Consumer compatibility is assessed independently.

The source is canonical JSON `{ "schema_version": 2, "intent": ... }`. The intent has exactly `schema_version`, decimal-string `sequence`, sequence-bound `tag`, `generated_at`, `expires_at`, `title`, `notes` and `profile`. The profile contains exact Pi and Node versions, target, component artifacts, installer manifest and lock, Pi package manifest, package identities, locked package graph and archive digests. It has no consumer requirement, contract hashes, build binding or qualification. Unknown fields are rejected. The current Node version is 22.19.0 and the target is `linux_x86_64`.

The three support descriptors point to the exact release tag and have names `pi-installer-package-<sha256>.json`, `pi-installer-lock-<sha256>.json` and `pi-package-<sha256>.json`. Acquisition checks actual upstream bytes and archives against the graph. The signer replays those checks using the transferred objects, rather than trusting the inventory alone.

The subject hash is SHA-256 over `fluxsemble:pi-release-subject:v2\0`, an eight-byte big-endian canonical profile length and the canonical JSON profile. Source and intent digests have separate producer V2 domains. Historical qualified V2 source records have different fields and are rejected instead of being reinterpreted.

The public asset retains the existing name `catalog-v1.json`; its envelope has `envelope_version: 2`, `signature_algorithm: "ed25519"`, `key_id`, the V2 intent as `payload`, and `signature`. The signature covers `fluxsemble:runtime-catalog:v2\0`, the eight-byte big-endian canonical payload length and canonical JSON payload. The separate `signed-release-bundle-manifest-v2.json` binds the source commit and tree digest, exact producer-input digest, tag, catalog envelope and three support assets. Its Ed25519 signature covers `fluxsemble:runtime-catalog-release-bundle:v2\0` followed by canonical JSON of the manifest without its signature. `checksums-sha256.txt` contains the hashes of the other published assets.

The publisher verifies both signatures, canonical payload, inventory, support descriptors, checksums and source bindings before staging. The producer V2 signed envelope requires a consumer that understands this format; publication itself is not a compatibility test. Legacy qualified catalogs remain historical and retain their original signature domains.
