# Runtime catalog security boundaries

## Offline signer ceremony

`catalog-sign` is an inner Linux x86_64 signer. Direct execution is unsupported and fails before identity lookup, argument collection, transfer parsing, output preflight, or key access. Its first operation is `enter_signer_isolation()`. A launcher marker is not authority: the inner process also proves no-new-privileges, an already-active launcher seccomp filter, distinct PID/user/mount/network namespaces, PID 1, zero effective/permitted/inheritable/ambient capabilities, the exact sanitized environment, empty mode-0700 `/home/signer` and `/tmp`, a loopback-only namespace with no route, the exact mount inventory, and the authenticated input-manifest digest.

The launcher filter denies socket/network, fork/vfork/clone/clone3, ptrace, and namespace/mount mutation while permitting the single exec into the static signer. The inner signer then installs an architecture-checked classic-BPF filter returning `EPERM` for that family plus `execve` and `execveat`. x32 and non-x86_64 syscall ABIs fail closed. The integration probe uses raw syscalls only after successful isolation and cannot select a signing ceremony.

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

The launcher retains exact bwrap, signer, input-root, optional key, output-root, and seccomp descriptors. It hashes and rebinds named executable identities before key open, immediately before output visibility, and immediately before launch; Bubblewrap binds the retained descriptors rather than reopening task paths. Output is a missing absolute child of a retained current-owner mode-0700 directory and is created once as mode `0700`. The explicit key is opened only after signer/input admission, without links, and must remain a current-owner one-link regular mode `0400` or `0600` file. No key bytes or key digest enter configuration, output, logs, or attestation.

Bubblewrap is invoked directly, never through a shell, with fixed arguments: `--unshare-all`, `--unshare-net`, `--die-with-parent`, `--new-session`, PID 1, `--clearenv`, capability drop, descriptor binds, private home/tmp, minimal proc/dev, fixed cwd, fixed locale/timezone, and the launcher seccomp descriptor. Child stdout/stderr are suppressed and the launcher emits only a fixed success or fixed failure line.

## Authenticated transfer

Before launch, the Task 6 signer verifier reopens the complete online-to-offline `transfer-manifest-v1.json`, all records, and every digest-addressed object through retained descriptors. Extra, missing, linked, replaced, writable, oversize, wrong-mode, wrong-size, wrong-digest, or identity-rebound content fails before key open and before output creation. The SHA-256 of the exact canonical transfer manifest is injected into and independently rehashed by the isolated process.

After a successful inner command, the signer writes a fresh canonical `transfer-manifest-v1.json` in `/output`. It covers every public output regular file with relative path, exact `0400` mode, size, and SHA-256, contains no host path, and binds the input-transfer digest and complete `IsolationAttestationV1` including mode. The output root and any signed-bundle directory are exact mode `0700`; all publication objects and the reverse manifest are exact mode `0400`, one-link, current-owner files. Existing names are never replaced. Task 8 independently reopens and verifies this reverse bundle before publisher authority is possible.

## Capability split

- `catalog-acquire`: public credential-free network acquisition; no signing-key interface.
- `catalog-sign-launcher`: the sole signer-side process-launch capability; fixed Bubblewrap only.
- inner `catalog-sign`: private-key parsing/signing and denied-syscall probe after isolation; no network client or usable process-launch capability.
- `catalog-publish`: public bundle verification and publication; no private-key parser or key interface.

Committed fixture keys remain nonproduction test authority only. The production private key, SSH directories, remote publication credentials, and repository mutation are outside this boundary and are never used by automated tests.
