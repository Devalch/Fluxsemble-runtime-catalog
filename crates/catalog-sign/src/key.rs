use std::{
    ffi::CString,
    fs,
    io::Read,
    os::{
        fd::FromRawFd,
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::Path,
};

use catalog_core::{ProductionKeyIdentity, derive_runtime_catalog_key_id, production_key_identity};
use ed25519_dalek::SigningKey as DalekSigningKey;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::SignError;

const MAX_KEY_BYTES: u64 = 16 * 1024;
const MAX_KEY_PATH_BYTES: usize = 4_096;
const PEM_BEGIN: &[u8] = b"-----BEGIN PRIVATE KEY-----";
const PEM_END: &[u8] = b"-----END PRIVATE KEY-----";
const ED25519_PRIVATE_KEY_INFO_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

#[cfg(test)]
std::thread_local! {
    static KEY_OPEN_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Local zeroizable wrapper. Dalek zeroizes its secret on drop; replacement makes that drop
/// happen when `Zeroizing` invokes this wrapper's `Zeroize` implementation.
pub(crate) struct SigningKey(DalekSigningKey);

impl SigningKey {
    fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(DalekSigningKey::from_bytes(bytes))
    }

    pub(crate) fn as_dalek(&self) -> &DalekSigningKey {
        &self.0
    }

    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.0.verifying_key()
    }
}

impl Zeroize for SigningKey {
    fn zeroize(&mut self) {
        self.0 = DalekSigningKey::from_bytes(&[0_u8; 32]);
    }
}

struct ExpectedIdentity<'a> {
    key_id: &'a str,
    public_key: &'a [u8; 32],
}

impl<'a> From<&'a ProductionKeyIdentity> for ExpectedIdentity<'a> {
    fn from(identity: &'a ProductionKeyIdentity) -> Self {
        Self {
            key_id: identity.key_id(),
            public_key: identity.public_key_bytes(),
        }
    }
}

/// Reads the one production key form. This capability deliberately remains crate-private.
pub(crate) fn read_production_signing_key(path: &Path) -> Result<Zeroizing<SigningKey>, SignError> {
    read_signing_key(path, production_key_identity())
}

fn read_signing_key(
    path: &Path,
    expected: &ProductionKeyIdentity,
) -> Result<Zeroizing<SigningKey>, SignError> {
    read_signing_key_for_identity(path, ExpectedIdentity::from(expected), || {})
}

fn read_signing_key_for_identity(
    path: &Path,
    expected: ExpectedIdentity<'_>,
    before_named_reopen: impl FnOnce(),
) -> Result<Zeroizing<SigningKey>, SignError> {
    validate_key_path(path)?;
    #[cfg(test)]
    KEY_OPEN_COUNT.set(KEY_OPEN_COUNT.get() + 1);

    let mut file = open_key(path)?;
    let before = MetadataFacts::from_metadata(&file.metadata().map_err(|_| rejected())?);
    before.require_secure()?;
    let mut pem = Zeroizing::new(Vec::with_capacity(
        usize::try_from(before.len).map_err(|_| rejected())?,
    ));
    (&mut file)
        .take(MAX_KEY_BYTES + 1)
        .read_to_end(&mut pem)
        .map_err(|_| rejected())?;
    let after = MetadataFacts::from_metadata(&file.metadata().map_err(|_| rejected())?);
    if pem.len() as u64 != before.len || before != after {
        return Err(rejected());
    }

    before_named_reopen();
    let rebound = open_key(path)?;
    let rebound = MetadataFacts::from_metadata(&rebound.metadata().map_err(|_| rejected())?);
    if before != rebound {
        return Err(rejected());
    }

    let der = decode_one_private_key_pem(&pem)?;
    let mut seed = Zeroizing::new([0_u8; 32]);
    seed.copy_from_slice(
        der.get(ED25519_PRIVATE_KEY_INFO_PREFIX.len()..)
            .ok_or_else(rejected)?,
    );
    let key = Zeroizing::new(SigningKey::from_bytes(&seed));
    seed.zeroize();

    let actual_public = key.verifying_key().to_bytes();
    let actual_key_id = derive_runtime_catalog_key_id(&actual_public);
    let public_match = actual_public.ct_eq(expected.public_key);
    let id_match = actual_key_id.len() == expected.key_id.len()
        && bool::from(actual_key_id.as_bytes().ct_eq(expected.key_id.as_bytes()));
    if !bool::from(public_match) || !id_match {
        return Err(rejected());
    }
    Ok(key)
}

fn validate_key_path(path: &Path) -> Result<(), SignError> {
    let bytes = path.as_os_str().as_bytes();
    if !path.is_absolute()
        || bytes.is_empty()
        || bytes.len() > MAX_KEY_PATH_BYTES
        || bytes.contains(&0)
    {
        return Err(rejected());
    }
    Ok(())
}

fn open_key(path: &Path) -> Result<fs::File, SignError> {
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| rejected())?;
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
        mode: 0,
        // RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS.
        resolve: 0x02 | 0x04,
    };
    // SAFETY: pointers refer to initialized values for the duration of the syscall.
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            path.as_ptr(),
            &raw const how,
            std::mem::size_of::<OpenHow>(),
        )
    } as i32;
    if descriptor < 0 {
        return Err(rejected());
    }
    // SAFETY: successful openat2 returns one newly owned descriptor.
    Ok(unsafe { fs::File::from_raw_fd(descriptor) })
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MetadataFacts {
    device: u64,
    inode: u64,
    len: u64,
    uid: u32,
    nlink: u64,
    mode: u32,
    regular: bool,
}

impl MetadataFacts {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            len: metadata.len(),
            uid: metadata.uid(),
            nlink: metadata.nlink(),
            mode: metadata.mode() & 0o7777,
            regular: metadata.is_file() && !metadata.file_type().is_symlink(),
        }
    }

    fn require_secure(self) -> Result<(), SignError> {
        if !self.regular
            || self.uid != current_euid()
            || self.nlink != 1
            || !matches!(self.mode, 0o400 | 0o600)
            || self.len == 0
            || self.len > MAX_KEY_BYTES
        {
            return Err(rejected());
        }
        Ok(())
    }
}

#[cfg(feature = "fixture-tools")]
const FIXTURE_RUNTIME_KEY_ID: &str = "runtime-catalog-ed25519-56475aa75463474c";
#[cfg(feature = "fixture-tools")]
const FIXTURE_PUBLIC: [u8; 32] = [
    0x03, 0xa1, 0x07, 0xbf, 0xf3, 0xce, 0x10, 0xbe, 0x1d, 0x70, 0xdd, 0x18, 0xe7, 0x4b, 0xc0, 0x99,
    0x67, 0xe4, 0xd6, 0x30, 0x9b, 0xa5, 0x0d, 0x5f, 0x1d, 0xdc, 0x86, 0x64, 0x12, 0x55, 0x31, 0xb8,
];

#[cfg(feature = "fixture-tools")]
pub(crate) fn read_fixture_signing_key(path: &Path) -> Result<Zeroizing<SigningKey>, SignError> {
    read_signing_key_for_identity(
        path,
        ExpectedIdentity {
            key_id: FIXTURE_RUNTIME_KEY_ID,
            public_key: &FIXTURE_PUBLIC,
        },
        || {},
    )
}

#[cfg(feature = "fixture-tools")]
pub(crate) fn fixture_signing_key() -> Result<Zeroizing<SigningKey>, SignError> {
    let pem = Zeroizing::new(
        include_bytes!("../tests/fixtures/nonproduction-ed25519-pkcs8.pem").to_vec(),
    );
    let der = decode_one_private_key_pem(&pem)?;
    let mut seed = Zeroizing::new([0_u8; 32]);
    seed.copy_from_slice(&der[ED25519_PRIVATE_KEY_INFO_PREFIX.len()..]);
    let key = Zeroizing::new(SigningKey::from_bytes(&seed));
    seed.zeroize();
    if !bool::from(key.verifying_key().to_bytes().ct_eq(&FIXTURE_PUBLIC)) {
        return Err(rejected());
    }
    Ok(key)
}

fn decode_one_private_key_pem(pem: &[u8]) -> Result<Zeroizing<Vec<u8>>, SignError> {
    let (newline, mut cursor) = if pem.starts_with(&[PEM_BEGIN, b"\n"].concat()) {
        (b"\n".as_slice(), PEM_BEGIN.len() + 1)
    } else if pem.starts_with(&[PEM_BEGIN, b"\r\n"].concat()) {
        (b"\r\n".as_slice(), PEM_BEGIN.len() + 2)
    } else {
        return Err(rejected());
    };

    let mut encoded = Zeroizing::new(Vec::with_capacity(128));
    let mut body_lines = 0_usize;
    loop {
        let line_end = find_subslice(&pem[cursor..], newline)
            .map(|offset| cursor + offset)
            .unwrap_or(pem.len());
        let line = &pem[cursor..line_end];
        cursor = line_end.saturating_add(newline.len());
        if line == PEM_END {
            if cursor != pem.len() || body_lines == 0 {
                return Err(rejected());
            }
            break;
        }
        if line.is_empty() || line.len() > 64 || (body_lines > 0 && encoded.len() % 64 != 0) {
            return Err(rejected());
        }
        encoded.extend_from_slice(line);
        body_lines += 1;
        if line_end == pem.len() {
            return Err(rejected());
        }
    }

    let der = decode_standard_base64(&encoded)?;
    if der.len() != ED25519_PRIVATE_KEY_INFO_PREFIX.len() + 32
        || !bool::from(
            der[..ED25519_PRIVATE_KEY_INFO_PREFIX.len()].ct_eq(&ED25519_PRIVATE_KEY_INFO_PREFIX),
        )
    {
        return Err(rejected());
    }
    Ok(der)
}

fn decode_standard_base64(encoded: &[u8]) -> Result<Zeroizing<Vec<u8>>, SignError> {
    if encoded.is_empty() || encoded.len() % 4 != 0 {
        return Err(rejected());
    }
    let mut output = Zeroizing::new(Vec::with_capacity(encoded.len() / 4 * 3));
    for (index, chunk) in encoded.chunks_exact(4).enumerate() {
        let final_chunk = index + 1 == encoded.len() / 4;
        let a = standard_base64_value(chunk[0]).ok_or_else(rejected)?;
        let b = standard_base64_value(chunk[1]).ok_or_else(rejected)?;
        output.push((a << 2) | (b >> 4));
        match (chunk[2], chunk[3]) {
            (b'=', b'=') if final_chunk && b & 0x0f == 0 => {}
            (c, b'=') if final_chunk => {
                let c = standard_base64_value(c).ok_or_else(rejected)?;
                if c & 0x03 != 0 {
                    return Err(rejected());
                }
                output.push((b << 4) | (c >> 2));
            }
            (c, d) => {
                let c = standard_base64_value(c).ok_or_else(rejected)?;
                let d = standard_base64_value(d).ok_or_else(rejected)?;
                output.push((b << 4) | (c >> 2));
                output.push((c << 6) | d);
            }
        }
    }
    let canonical = encode_standard_base64(&output);
    if canonical.as_bytes() != encoded {
        return Err(rejected());
    }
    Ok(output)
}

/// Canonical re-encoding remains zeroizing because its input can be private-key DER.
fn encode_standard_base64(bytes: &[u8]) -> Zeroizing<String> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = Zeroizing::new(String::with_capacity(bytes.len().div_ceil(3) * 4));
    for chunk in bytes.chunks(3) {
        output.push(char::from(ALPHABET[usize::from(chunk[0] >> 2)]));
        output.push(char::from(
            ALPHABET
                [usize::from(((chunk[0] & 3) << 4) | (chunk.get(1).copied().unwrap_or(0) >> 4))],
        ));
        match chunk {
            [_, second, third] => {
                output.push(char::from(
                    ALPHABET[usize::from(((second & 15) << 2) | (third >> 6))],
                ));
                output.push(char::from(ALPHABET[usize::from(third & 63)]));
            }
            [_, second] => {
                output.push(char::from(ALPHABET[usize::from((second & 15) << 2)]));
                output.push('=');
            }
            [_] => output.push_str("=="),
            _ => unreachable!(),
        }
    }
    output
}

fn standard_base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn current_euid() -> u32 {
    // SAFETY: geteuid has no preconditions or memory effects.
    unsafe { libc::geteuid() }
}

const fn rejected() -> SignError {
    SignError::SigningKeyRejected
}

#[cfg(test)]
pub(crate) fn fixture_signing_key_for_test() -> Zeroizing<SigningKey> {
    let der = decode_one_private_key_pem(include_bytes!(
        "../tests/fixtures/nonproduction-ed25519-pkcs8.pem"
    ))
    .expect("committed fixture PKCS#8");
    let mut seed = Zeroizing::new([0_u8; 32]);
    seed.copy_from_slice(&der[ED25519_PRIVATE_KEY_INFO_PREFIX.len()..]);
    let key = Zeroizing::new(SigningKey::from_bytes(&seed));
    seed.zeroize();
    key
}

#[cfg(test)]
pub(crate) fn key_open_count() -> usize {
    KEY_OPEN_COUNT.get()
}

#[cfg(test)]
pub(crate) fn reset_key_open_count() {
    KEY_OPEN_COUNT.set(0);
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{DirBuilderExt, PermissionsExt, symlink},
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

    const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/nonproduction-ed25519-pkcs8.pem");
    const FIXTURE_RUNTIME_KEY_ID: &str = "runtime-catalog-ed25519-56475aa75463474c";
    const FIXTURE_PUBLIC: [u8; 32] = [
        0x03, 0xa1, 0x07, 0xbf, 0xf3, 0xce, 0x10, 0xbe, 0x1d, 0x70, 0xdd, 0x18, 0xe7, 0x4b, 0xc0,
        0x99, 0x67, 0xe4, 0xd6, 0x30, 0x9b, 0xa5, 0x0d, 0x5f, 0x1d, 0xdc, 0x86, 0x64, 0x12, 0x55,
        0x31, 0xb8,
    ];

    fn fixture_identity() -> ExpectedIdentity<'static> {
        ExpectedIdentity {
            key_id: FIXTURE_RUNTIME_KEY_ID,
            public_key: &FIXTURE_PUBLIC,
        }
    }

    #[test]
    fn pkcs8_reader_accepts_only_exact_owner_private_ed25519_pem() {
        let temp = TempDirectory::new();
        let valid = temp.write("valid.pem", FIXTURE, 0o600);
        assert!(
            read_signing_key_for_identity(&valid, fixture_identity(), || {}).is_ok(),
            "committed fixture must be accepted"
        );

        let generic_ec = pem_with_der(&mutated_der(8, 0x2a));
        let wrong_oid = pem_with_der(&mutated_der(10, 0x71));
        let mut multiple = Zeroizing::new(Vec::with_capacity(FIXTURE.len() * 2));
        multiple.extend_from_slice(FIXTURE);
        multiple.extend_from_slice(FIXTURE);
        let mut trailing = Zeroizing::new(Vec::with_capacity(FIXTURE.len() + 8));
        trailing.extend_from_slice(FIXTURE);
        trailing.extend_from_slice(b"trailing");
        let replacements: &[(&str, &[u8])] = &[
            (
                "encrypted.pem",
                b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n",
            ),
            (
                "openssh.pem",
                b"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
            ),
            (
                "sec1.pem",
                b"-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n",
            ),
            ("generic-ec.pem", &generic_ec),
            ("wrong-oid.pem", &wrong_oid),
            ("truncated.pem", &FIXTURE[..FIXTURE.len() - 8]),
            ("multiple.pem", &multiple),
            ("trailing.pem", &trailing),
            (
                "malformed-base64.pem",
                b"-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----\n",
            ),
        ];
        for (name, bytes) in replacements {
            let path = temp.write(name, bytes, 0o600);
            assert!(
                read_signing_key_for_identity(&path, fixture_identity(), || {}).is_err(),
                "accepted {name}"
            );
        }

        let wrong_public_key = ExpectedIdentity {
            key_id: fixture_identity().key_id,
            public_key: production_key_identity().public_key_bytes(),
        };
        assert!(read_signing_key_for_identity(&valid, wrong_public_key, || {}).is_err());
        let wrong_key_id = ExpectedIdentity {
            key_id: "runtime-catalog-ed25519-0000000000000000",
            public_key: &FIXTURE_PUBLIC,
        };
        assert!(read_signing_key_for_identity(&valid, wrong_key_id, || {}).is_err());

        assert!(
            read_signing_key_for_identity(Path::new("relative.pem"), fixture_identity(), || {})
                .is_err()
        );
        let overly_long = PathBuf::from(format!("/{}", "a".repeat(MAX_KEY_PATH_BYTES)));
        assert!(read_signing_key_for_identity(&overly_long, fixture_identity(), || {}).is_err());
        assert!(
            read_signing_key_for_identity(&temp.path, fixture_identity(), || {}).is_err(),
            "directory was accepted as a regular key file"
        );

        for mode in [0o000, 0o200, 0o640, 0o604, 0o700, 0o1000, 0o2400, 0o4600] {
            let path = temp.write(&format!("mode-{mode:o}.pem"), FIXTURE, mode);
            assert!(
                read_signing_key_for_identity(&path, fixture_identity(), || {}).is_err(),
                "accepted mode {mode:o}"
            );
        }
        let read_only = temp.write("read-only.pem", FIXTURE, 0o400);
        assert!(read_signing_key_for_identity(&read_only, fixture_identity(), || {}).is_ok());

        let hardlink = temp.write("hardlink.pem", FIXTURE, 0o600);
        fs::hard_link(&hardlink, temp.path.join("other-link.pem")).unwrap();
        assert!(read_signing_key_for_identity(&hardlink, fixture_identity(), || {}).is_err());

        let symlink_target = temp.write("symlink-target.pem", FIXTURE, 0o600);
        let linked = temp.path.join("linked.pem");
        symlink(&symlink_target, &linked).unwrap();
        assert!(read_signing_key_for_identity(&linked, fixture_identity(), || {}).is_err());

        let oversized = temp.write(
            "oversized.pem",
            &vec![b'A'; MAX_KEY_BYTES as usize + 1],
            0o600,
        );
        assert!(read_signing_key_for_identity(&oversized, fixture_identity(), || {}).is_err());
    }

    #[test]
    fn key_open_instrumentation_is_isolated_between_executing_test_threads() {
        reset_key_open_count();
        let temp = TempDirectory::new();
        let path = temp.write("thread-isolated.pem", FIXTURE, 0o600);
        let (opened_sender, opened_receiver) = std::sync::mpsc::channel();
        let (reset_sender, reset_receiver) = std::sync::mpsc::channel();

        let reader = std::thread::spawn(move || {
            reset_key_open_count();
            assert_eq!(key_open_count(), 0);
            assert!(read_signing_key_for_identity(&path, fixture_identity(), || {}).is_ok());
            assert_eq!(key_open_count(), 1);
            opened_sender.send(()).unwrap();
            reset_receiver.recv().unwrap();
            assert_eq!(
                key_open_count(),
                1,
                "another test thread altered this thread's key-open count"
            );
        });
        opened_receiver.recv().unwrap();
        let resetter = std::thread::spawn(|| {
            reset_key_open_count();
            assert_eq!(key_open_count(), 0);
        });
        resetter.join().unwrap();
        reset_sender.send(()).unwrap();
        reader.join().unwrap();
        assert_eq!(
            key_open_count(),
            0,
            "worker-thread key reads leaked into the executing test thread"
        );
    }

    #[test]
    fn replacement_and_truncation_between_read_and_named_binding_are_rejected() {
        for truncate in [false, true] {
            let temp = TempDirectory::new();
            let path = temp.write("raced.pem", FIXTURE, 0o600);
            let replacement = path.clone();
            let result = read_signing_key_for_identity(&path, fixture_identity(), move || {
                if truncate {
                    fs::OpenOptions::new()
                        .write(true)
                        .truncate(true)
                        .open(&replacement)
                        .unwrap();
                } else {
                    let moved = replacement.with_extension("moved");
                    fs::rename(&replacement, moved).unwrap();
                    fs::write(&replacement, FIXTURE).unwrap();
                    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
                }
            });
            assert!(result.is_err());
        }
    }

    #[test]
    fn simulated_foreign_owner_is_rejected() {
        let facts = MetadataFacts {
            device: 1,
            inode: 1,
            len: FIXTURE.len() as u64,
            uid: current_euid().wrapping_add(1),
            nlink: 1,
            mode: 0o600,
            regular: true,
        };
        assert_eq!(facts.require_secure(), Err(SignError::SigningKeyRejected));
    }

    fn mutated_der(index: usize, value: u8) -> Zeroizing<Vec<u8>> {
        let mut der = decode_one_private_key_pem(FIXTURE).unwrap();
        der[index] = value;
        der
    }

    fn pem_with_der(der: &[u8]) -> Zeroizing<Vec<u8>> {
        let encoded = encode_standard_base64(der);
        let mut pem = Zeroizing::new(Vec::with_capacity(
            PEM_BEGIN.len() + encoded.len() + PEM_END.len() + 3,
        ));
        pem.extend_from_slice(PEM_BEGIN);
        pem.push(b'\n');
        pem.extend_from_slice(encoded.as_bytes());
        pem.push(b'\n');
        pem.extend_from_slice(PEM_END);
        pem.push(b'\n');
        pem
    }

    struct TempDirectory {
        path: PathBuf,
    }

    impl TempDirectory {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "catalog-sign-key-test-{}-{nonce}",
                std::process::id()
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self { path }
        }

        fn write(&self, name: &str, bytes: &[u8], mode: u32) -> PathBuf {
            let path = self.path.join(name);
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            path
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
