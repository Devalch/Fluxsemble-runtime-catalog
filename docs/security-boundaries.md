# Runtime catalog security boundaries

## Offline signer ceremony

`catalog-sign` is an inner Linux x86_64 signer. Direct execution is unsupported and fails before identity lookup, argument collection, transfer parsing, output preflight, or key access. Its first operation is `enter_signer_isolation()`, whose first process controls set and verify `PR_SET_DUMPABLE=0` and inherited soft/hard `RLIMIT_CORE=0`. The launcher establishes both core limits before opening a key; the inner prctl is separately required because exec may restore dumpability.

A launcher marker is not authority: the inner process also proves no-new-privileges, an already-active launcher seccomp filter, PID 1, zero effective/permitted/inheritable/ambient capabilities, the exact sanitized environment, empty mode-0700 `/home/signer` and `/tmp`, a loopback-only namespace with no route, and the exact mount topology. `/` is the current-owner mode-0555 Bubblewrap `/newroot` tmpfs with exact `rw,nosuid,nodev,relatime` VFS options; task mounts are direct children and device mounts are children only of private `/dev`. Host namespace strings are cross-checks only. PID 1, the private tmpfs root, the loopback-only route state, zero capabilities, and prefilter syscall outcomes provide kernel/outcome authority for the PID, mount, network, and user isolation boundaries.

The actual launcher filter denies socket/network, io_uring setup/entry/registration, fork/vfork/clone/clone3, ptrace, and namespace/mount mutation while permitting the single exec into the static signer. Before installing the inner filter, the signer safely proves the inherited launcher policy: socket/connect/fork/io_uring and selected namespace/mount calls return `EPERM`; an unexpected fork child is reaped; and exec of a fixed nonexistent path returns `ENOENT`, proving the final exec denial is not yet active. The inner signer then installs an architecture-checked classic-BPF filter returning `EPERM` for that family plus `execve` and `execveat`. x32 and non-x86_64 syscall ABIs fail closed. The real-launcher `isolation-probe` ceremony has no key mount, records both prefilter and postfilter results, and cannot select signing behavior.

The only inner task-data mounts are:

- read-only `/input` and writable fresh `/output` for every ceremony;
- read-only `/key/runtime-catalog-private.pem` only for `sign`;
- no `/key` mount or key interface for `assemble-intent` or `finalize`.

The static signer receives no repository, system tree, user home, SSH state, GitHub configuration, credential store, proxy, token, SSH-agent, or ambient file descriptor authority. `/proc` and `/dev` are minimal private Bubblewrap mounts. The repository and production key must never be mounted.

## Launcher configuration and executable identity

The launcher accepts only these exact ordered forms:

```text
catalog-sign-launcher assemble-intent --config CONFIG --input BUNDLE --output FRESH_OUTPUT
catalog-sign-launcher finalize        --config CONFIG --input BUNDLE --output FRESH_OUTPUT
catalog-sign-launcher sign            --config CONFIG --input BUNDLE --key EXPLICIT_KEY --output FRESH_OUTPUT
catalog-sign-launcher recover-sign    --config CONFIG --input BUNDLE --output EXISTING_OUTPUT
catalog-sign-launcher isolation-probe --config CONFIG --input BUNDLE --output FRESH_OUTPUT
```

`CONFIG` is canonical JCS JSON, one-link regular mode `0600`, current-owner, at most 16 KiB, and has exactly:

```json
{"bwrap_path":"/usr/bin/bwrap","bwrap_sha256":"64 lowercase hex","schema_version":1,"signer_path":"/absolute/static/catalog-sign","signer_sha256":"64 lowercase hex"}
```

Paths are canonical absolute paths opened component-by-component without links. `/usr/bin/bwrap` must be root-owned, one-link mode `0755`, executable, bounded, and match its full configured SHA-256. The signer must be current-owner, one-link mode `0500`, bounded, match its full configured SHA-256, and parse as x86_64 ELF64 with load segments and no `PT_INTERP` or `PT_DYNAMIC`. Production ceremony builds it outside isolation with:

```bash
rustup target add x86_64-unknown-linux-musl # public one-time prerequisite when absent
RUSTFLAGS='-C target-feature=+crt-static -C relocation-model=static' \
  cargo build --locked --release --target x86_64-unknown-linux-musl \
  -p catalog-sign --bin catalog-sign
```

The launcher retains exact bwrap, signer, input-root, optional key, output-root, and seccomp descriptors. It hashes and rebinds named executable identities before key open, immediately before output visibility, and immediately before launch; Bubblewrap binds the retained descriptors rather than reopening task paths. Tests synchronize at three private `cfg(test)` checkpoints immediately before signer open, after retained signer authentication, and immediately before the final bind recheck. Those checkpoints have no environment, CLI, feature, or release-binary surface. Output is a missing absolute child of a retained current-owner mode-0700 directory and is created once as mode `0700`. The explicit key is opened only after signer/input admission, without links, and must remain a current-owner one-link regular mode `0400` or `0600` file. No key bytes or key digest enter configuration, output, logs, or attestation.

Bubblewrap is invoked directly, never through a shell, with fixed arguments: `--unshare-all`, `--unshare-net`, `--die-with-parent`, `--new-session`, PID 1, `--clearenv`, capability drop, descriptor binds, private mode-0555 tmpfs root, private home/tmp, minimal proc/dev, fixed cwd, fixed locale/timezone, and the launcher seccomp descriptor. Child stdout/stderr are suppressed and the launcher emits only a fixed success or fixed failure line.

## Authenticated transfer

Before launch, the Task 6 signer verifier reopens the complete online-to-offline `transfer-manifest-v1.json`, all records, and every digest-addressed object through retained descriptors. Extra, missing, linked, replaced, writable, oversize, wrong-mode, wrong-size, wrong-digest, or identity-rebound content fails before key open and before output creation. The SHA-256 of the exact canonical transfer manifest is injected into the isolated process. Isolation verifies `/input` once through `verify_transferred_bundle`, compares that retained manifest digest to the launcher-attested digest, and stores the same retained `VerifiedTransferredBundle` inside a non-constructible `SignerIsolation` capability. Assembly, finalization, and signing consume only that retained bundle and its retained record/object descriptors; they do not reopen `/input` through a path CLI.

After a successful inner command, the signer writes a fresh canonical `transfer-manifest-v1.json` in `/output`. It covers every public output regular file with relative path, exact `0400` mode, size, and SHA-256, contains no host path, and binds the input-transfer digest and complete `IsolationAttestationV1` including both the original operation mode and actual completion mode. The reverse manifest is settled through an unnamed file and one no-clobber link; an exact existing manifest is canonically reopened and accepted, while partial or conflicting bytes are never replaced. The output root and any signed-bundle directory are exact mode `0700`; all publication objects and the reverse manifest are exact mode `0400`, one-link, current-owner files. Existing names are never replaced. Task 8 independently reopens and verifies this reverse bundle before publisher authority is possible.

Signed payload publication has an explicit post-visibility state. Before publication can become visible, the canonical operation binding is durably extended with the exact random stage relative name, device/inode, owner, mode, and cleanup-authorization state. Once the no-clobber payload rename succeeds, every cleanup path first reopens and verifies the exact visible bundle with the appropriate compiled public identity. Parent-fsync failure is reported as durability uncertainty rather than durable success. Recovery opens only that bound name descriptor-relatively without following links, compares its exact identity and owner/mode, requires it to be empty, and never scans for a convenient matching stage. Missing, replaced, unbound, nonempty, invalid-output, or otherwise uncertain evidence is preserved and fails closed. The keyless `recover-sign` ceremony reauthenticates the same config signer, retained input digest, original `sign` operation, isolation boundary, and existing output root, recomputes the expected candidate, verifies the visible production- or fixture-signed bundle through public verification, settles only the exact bound stage, and idempotently completes or accepts reverse manifests whose actual completion mode is schema-authorized as `sign` or `recover-sign`. It never opens a key, resigns, overwrites, or admits a different candidate.

## GitHub CLI credential broker

`catalog-gh-broker` is the publisher's sole authenticated process-launch boundary. It accepts only exact ordered `--config CONFIG`, then one bounded canonical `BrokerRequestV1` on stdin. The request family is closed to `create_tag`, `read_tag`, `create_draft`, `read_draft`, `upload_asset`, `download_asset`, and `publish_draft`; it contains no method, route, host, header, argument, query, template, GraphQL, authentication, token, shell, Git, or environment field. Repository, production/transport tag, full commit, decimal ID, title, notes, prerelease, asset-name, and absolute asset-path fields validate before the broker opens its config or process capabilities.

The canonical owner-private mode-`0600` `PublisherBrokerConfigV1` contains only schema version, canonical absolute `gh_path`, exact lowercase executable SHA-256, and canonical absolute `github_config_dir`. The broker opens every component without links, retains and rebinds the current-owner config and mode-`0700` config directory, and never lists or reads credential files. The configured executable is a retained one-link regular executable owned by root or the current user, is never group/world writable, and is fully rehashed and named-rebound immediately before spawn. ELF executables launch through the retained `/proc/self/fd/N` capability. Script fixtures use the documented same-EUID fallback only after the same final name/identity/hash proof; production does not discover an executable through `PATH`.

Each invocation creates a new empty mode-`0700` HOME and clears the entire child environment. The only child variables are `HOME`, retained `/proc/self/fd/N` `GH_CONFIG_DIR`, `LANG=C`, `LC_ALL=C`, and `TZ=UTC`. No token, proxy, SSH-agent, Git, Cargo/Rust, XDG, `PATH`, repository, user home, or SSH directory is inherited. The broker maps typed requests to fixed no-shell `gh api` REST argument arrays and fixed canonical JSON bodies. It never invokes authentication/token commands or accepts arbitrary arguments, routes, methods, hosts, or headers.

Child stdout and stderr are drained concurrently under hard ceilings and a deadline; overflow, timeout, signal, nonzero exit, malformed/duplicate/oversize output, or projection mismatch kills and reaps the child process group and produces only `github broker failed`. Successful JSON is explicitly projected to safe tag/commit/type, release ID/tag/target/draft/prerelease, asset ID/name/size/SHA-256, or published status fields. Uploads pass only a retained mode-`0400` asset descriptor. Downloads write only to a fresh no-clobber mode-`0600` descriptor beneath a retained owner-private directory, then fsync, chmod to `0400`, hash, read back, and named-rebind it; failures unlink only the exact retained fresh inode. Neither child bytes, credential/config canaries, request content, nor host paths are echoed.

## Capability split

- `catalog-acquire`: public credential-free network acquisition; no signing-key interface.
- `catalog-sign-launcher`: the sole signer-side process-launch capability; fixed Bubblewrap only.
- inner `catalog-sign`: private-key parsing/signing requires the non-deserializable, non-constructible `SignerIsolation` capability returned only after every inner check and final-filter installation; raw signing and raw CLI entry points are not exported. Public library APIs retain only inert transfer verification and unsigned assembly/finalization contracts. The denied-syscall probe also requires the capability and has no key mount.
- `catalog-publish`: public bundle verification and publication; no private-key parser or key interface.

Committed fixture keys remain nonproduction test authority only. `catalog-sign-fixture` is a separately named static binary behind the nondefault `fixture-tools` feature. It reads only the committed fixture key identity, emits `catalog-test-key-v1`, verifies through the fixture public identity, and is rejected by production public verification; neither its entry point nor fixture identity is present in the default production signer binary. Its real Bubblewrap journey uses the same retained transfer, domain-separated catalog/release signatures, staging writer, reverse emitter, launcher, mounts, seccomp, recovery, and no-clobber implementation. Boundary mutations fail if fixture authority enters the production main or launcher surface.

The exact approved public assemble/finalize journey is intentionally ignored unless `CATALOG_AUTHENTIC_PUBLIC_CORPUS` names an explicit authenticated public corpus. `scripts/authentic-candidate-oracle.py` independently verifies the complete duplicate-free, bounded public transfer and constructs the catalog-v1 projection directly from its committed release intent without importing or invoking catalog-sign; its frozen expected candidate is 55,797 bytes with SHA-256 `7dba62c8b44883cbd7b3615fd9fe3b1a08a3aa2c75c7729704c14804d1cc2a2b`. `scripts/run-authentic-signing-journey.sh` exports retained transfers through the existing ignored reader, runs both normal production static-signer launcher ceremonies, and requires both real Bubblewrap candidates to equal the independent oracle byte-for-byte and match that digest before proving no-clobber. The producer has no Fluxsemble code, build, test, or runtime dependency. The production private key, SSH directories, remote publication credentials, and repository mutation are outside this boundary and are never used by automated tests.
