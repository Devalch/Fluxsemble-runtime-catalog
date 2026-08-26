use std::{
    ffi::CString,
    fs,
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
        },
    },
    path::{Path, PathBuf},
};

use catalog_acquire::{
    AcquireError, AcquireReleaseRequest, AcquireReleaseSource, AcquisitionCancellation,
    CredentialFreeFetcher, DiscoverInputsRequest, FetchRequest, PackageInputManifestV1,
    acquire_release, discover_inputs, export_transfer_bundle, verify_transferred_bundle,
};
use catalog_core::{CatalogSourceV1, CompatibilityQualificationV1, InitialPiReleaseIntentV1};
use sha2::{Digest, Sha256};

const MAX_ARGUMENTS: usize = 11;
const MAX_ARGUMENT_BYTES: usize = 16 * 1024;
const MAX_PATH_BYTES: usize = 4096;
const MAX_INPUT_BYTES: u64 = 8 * 1024 * 1024;

fn main() {
    match run() {
        Ok(summary) => println!(
            "verified bundle_sha256={} objects={} bytes={}",
            summary.digest, summary.objects, summary.bytes
        ),
        Err(_) => {
            eprintln!("catalog acquisition failed");
            std::process::exit(1);
        }
    }
}

struct Summary {
    digest: String,
    objects: usize,
    bytes: u64,
}

fn run() -> Result<Summary, AcquireError> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    validate_args(&args)?;
    let command = args.first().ok_or(AcquireError::Input)?.as_str();
    match command {
        "verify-bundle" => {
            let bundle = exact_flags(&args[1..], &["--bundle"])?;
            summary(verify_transferred_bundle(Path::new(&bundle[0]))?)
        }
        "export-transfer" => {
            let values = exact_flags(&args[1..], &["--bundle", "--output"])?;
            summary(export_transfer_bundle(
                Path::new(&values[0]),
                Path::new(&values[1]),
            )?)
        }
        "verify-public-object" => {
            let values = exact_flags(&args[1..], &["--url", "--size", "--sha256"])?;
            let size = parse_decimal(&values[1])?;
            let request = FetchRequest::for_public_object(&values[0], size, &values[2])?;
            let cache = TemporaryCache::new()?;
            let fetcher = CredentialFreeFetcher::new(cache.path())?;
            let fetched = runtime()?
                .block_on(fetcher.fetch_exact(request, &AcquisitionCancellation::new()))?;
            Ok(Summary {
                digest: fetched.sha256().as_str().to_owned(),
                objects: 1,
                bytes: fetched.size(),
            })
        }
        "discover-inputs" => {
            let values = exact_flags(&args[1..], &["--intent", "--output"])?;
            let intent = InitialPiReleaseIntentV1::from_json(&read_input(Path::new(&values[0]))?)
                .map_err(|_| AcquireError::Input)?;
            let cache = TemporaryCache::new()?;
            let manifest = runtime()?.block_on(discover_inputs(DiscoverInputsRequest {
                intent,
                cache_root: cache.path().to_owned(),
                output: PathBuf::from(&values[1]),
                cancellation: AcquisitionCancellation::new(),
            }))?;
            let bytes = manifest.canonical_bytes()?;
            Ok(Summary {
                digest: format!("{:x}", Sha256::digest(&bytes)),
                objects: manifest.locked_package_count() + 1,
                bytes: bytes.len() as u64,
            })
        }
        "acquire-intent" => {
            let values = exact_flags(&args[1..], &["--intent", "--package-inputs", "--output"])?;
            let intent = InitialPiReleaseIntentV1::from_json(&read_input(Path::new(&values[0]))?)
                .map_err(|_| AcquireError::Input)?;
            let package_inputs =
                PackageInputManifestV1::from_json(&read_input(Path::new(&values[1]))?)?;
            run_acquire(
                AcquireReleaseSource::Intent { intent },
                package_inputs,
                PathBuf::from(&values[2]),
            )
        }
        "acquire-source" => {
            let values = exact_flags(
                &args[1..],
                &[
                    "--source",
                    "--package-inputs",
                    "--source-commit",
                    "--source-tree-sha256",
                    "--output",
                ],
            )?;
            let source_path = Path::new(&values[0]);
            let source_root = RetainedInputRoot::open(source_path)?;
            let source = CatalogSourceV1::from_json(&source_root.read_source()?)
                .map_err(|_| AcquireError::Input)?;
            let qualification = CompatibilityQualificationV1::from_json(
                &source_root.read_relative(source.qualification().relative_path().as_str())?,
            )
            .map_err(|_| AcquireError::Input)?;
            let package_inputs =
                PackageInputManifestV1::from_json(&read_input(Path::new(&values[1]))?)?;
            run_acquire(
                AcquireReleaseSource::Final {
                    source: Box::new(source),
                    qualification: Box::new(qualification),
                    source_commit: values[2].clone(),
                    source_tree_sha256: values[3].clone(),
                },
                package_inputs,
                PathBuf::from(&values[4]),
            )
        }
        _ => Err(AcquireError::Input),
    }
}

fn run_acquire(
    source: AcquireReleaseSource,
    package_inputs: PackageInputManifestV1,
    output: PathBuf,
) -> Result<Summary, AcquireError> {
    let cache = TemporaryCache::new()?;
    runtime()?.block_on(acquire_release(AcquireReleaseRequest {
        source,
        package_inputs,
        cache_root: cache.path().to_owned(),
        output: output.clone(),
        cancellation: AcquisitionCancellation::new(),
    }))?;
    summary(verify_transferred_bundle(&output)?)
}

fn summary(bundle: catalog_acquire::VerifiedTransferredBundle) -> Result<Summary, AcquireError> {
    Ok(Summary {
        digest: bundle.bundle_sha256().to_owned(),
        objects: bundle.object_count(),
        bytes: bundle.total_bytes(),
    })
}

fn runtime() -> Result<tokio::runtime::Runtime, AcquireError> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| AcquireError::Input)
}

fn validate_args(args: &[String]) -> Result<(), AcquireError> {
    if args.is_empty()
        || args.len() > MAX_ARGUMENTS
        || args.iter().map(String::len).sum::<usize>() > MAX_ARGUMENT_BYTES
        || args.iter().any(|value| value.as_bytes().contains(&0))
    {
        return Err(AcquireError::Input);
    }
    Ok(())
}

fn exact_flags(args: &[String], flags: &[&str]) -> Result<Vec<String>, AcquireError> {
    if args.len() != flags.len() * 2 {
        return Err(AcquireError::Input);
    }
    let mut values = Vec::with_capacity(flags.len());
    for (pair, expected) in args.chunks_exact(2).zip(flags) {
        if pair[0] != *expected || pair[1].is_empty() {
            return Err(AcquireError::Input);
        }
        if *expected != "--url" && pair[1].len() > MAX_PATH_BYTES {
            return Err(AcquireError::Input);
        }
        values.push(pair[1].clone());
    }
    Ok(values)
}

fn parse_decimal(value: &str) -> Result<u64, AcquireError> {
    let parsed = value.parse::<u64>().map_err(|_| AcquireError::Input)?;
    if value != parsed.to_string() || parsed == 0 {
        return Err(AcquireError::Input);
    }
    Ok(parsed)
}

struct RetainedInputRoot {
    directory: fs::File,
    source_name: String,
}

impl RetainedInputRoot {
    fn open(source_path: &Path) -> Result<Self, AcquireError> {
        if source_path.as_os_str().as_bytes().len() > MAX_PATH_BYTES {
            return Err(AcquireError::Input);
        }
        let source_name = source_path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| safe_relative(name))
            .ok_or(AcquireError::Input)?
            .to_owned();
        let parent = source_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent =
            CString::new(parent.as_os_str().as_bytes()).map_err(|_| AcquireError::Input)?;
        let directory = openat2_input(
            libc::AT_FDCWD,
            &parent,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            // RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS.
            0x02 | 0x04,
        )?;
        let root = Self {
            directory,
            source_name,
        };
        let _ = root.read_source()?;
        Ok(root)
    }

    fn read_source(&self) -> Result<Vec<u8>, AcquireError> {
        self.read_relative(&self.source_name)
    }

    fn read_relative(&self, relative: &str) -> Result<Vec<u8>, AcquireError> {
        if !safe_relative(relative) {
            return Err(AcquireError::Input);
        }
        let name = CString::new(relative).map_err(|_| AcquireError::Input)?;
        let mut file = openat2_input(
            self.directory.as_raw_fd(),
            &name,
            libc::O_RDONLY | libc::O_CLOEXEC,
            // RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH.
            0x02 | 0x04 | 0x08,
        )?;
        let before = file.metadata().map_err(|_| AcquireError::Input)?;
        if !before.is_file() || before.len() == 0 || before.len() > MAX_INPUT_BYTES {
            return Err(AcquireError::Input);
        }
        let mut bytes = Vec::with_capacity(before.len() as usize);
        (&mut file)
            .take(MAX_INPUT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| AcquireError::Input)?;
        let after = file.metadata().map_err(|_| AcquireError::Input)?;
        let named = openat2_input(
            self.directory.as_raw_fd(),
            &name,
            libc::O_RDONLY | libc::O_CLOEXEC,
            0x02 | 0x04 | 0x08,
        )?
        .metadata()
        .map_err(|_| AcquireError::Input)?;
        if bytes.len() as u64 != before.len()
            || before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
            || before.dev() != named.dev()
            || before.ino() != named.ino()
        {
            return Err(AcquireError::Input);
        }
        Ok(bytes)
    }
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn openat2_input(
    directory: i32,
    name: &CString,
    flags: i32,
    resolve: u64,
) -> Result<fs::File, AcquireError> {
    let how = OpenHow {
        flags: flags as u64,
        mode: 0,
        resolve,
    };
    // SAFETY: all pointers reference initialized values for the duration of the syscall.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            directory,
            name.as_ptr(),
            &raw const how,
            std::mem::size_of::<OpenHow>(),
        )
    } as i32;
    if fd < 0 {
        return Err(AcquireError::Input);
    }
    // SAFETY: successful openat2 returns one owned descriptor.
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

fn safe_relative(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PATH_BYTES
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.bytes().any(|byte| byte.is_ascii_control())
        && value
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn read_input(path: &Path) -> Result<Vec<u8>, AcquireError> {
    if path.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES {
        return Err(AcquireError::Input);
    }
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(path).map_err(|_| AcquireError::Input)?;
    let metadata = file.metadata().map_err(|_| AcquireError::Input)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_INPUT_BYTES {
        return Err(AcquireError::Input);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|_| AcquireError::Input)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(AcquireError::Input);
    }
    Ok(bytes)
}

struct TemporaryCache {
    path: PathBuf,
}

impl TemporaryCache {
    fn new() -> Result<Self, AcquireError> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "catalog-acquire-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new()
            .recursive(false)
            .mode(0o700)
            .create(&path)
            .map_err(|_| AcquireError::Input)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryCache {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{DirBuilderExt, symlink},
        path::PathBuf,
        sync::{Mutex, MutexGuard},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::RetainedInputRoot;

    static CWD_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn qualification_is_read_beneath_the_source_directory_not_cwd() {
        let _lock = lock_cwd();
        let temp = TempDirectory::new();
        let source_directory = temp.path.join("source-root");
        let other_cwd = temp.path.join("other-cwd");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&source_directory)
            .unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&other_cwd)
            .unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(source_directory.join("qualifications"))
            .unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(other_cwd.join("qualifications"))
            .unwrap();
        fs::write(source_directory.join("source.json"), b"source").unwrap();
        fs::write(
            source_directory.join("qualifications/record.json"),
            b"source-relative",
        )
        .unwrap();
        fs::write(
            other_cwd.join("qualifications/record.json"),
            b"cwd-controlled",
        )
        .unwrap();
        let original_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&other_cwd).unwrap();
        let _restore = RestoreCwd(original_cwd);

        let root = RetainedInputRoot::open(&source_directory.join("source.json")).unwrap();
        assert_eq!(root.read_source().unwrap(), b"source");
        assert_eq!(
            root.read_relative("qualifications/record.json").unwrap(),
            b"source-relative"
        );
    }

    #[test]
    fn qualification_rejects_traversal_absolute_empty_and_symlink_paths() {
        let temp = TempDirectory::new();
        let root_path = temp.path.join("root");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&root_path)
            .unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(root_path.join("qualifications"))
            .unwrap();
        fs::write(root_path.join("source.json"), b"source").unwrap();
        fs::write(temp.path.join("outside.json"), b"outside").unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(temp.path.join("outside-directory"))
            .unwrap();
        fs::write(temp.path.join("outside-directory/record.json"), b"outside").unwrap();
        symlink(
            temp.path.join("outside.json"),
            root_path.join("qualifications/link.json"),
        )
        .unwrap();
        symlink(
            temp.path.join("outside-directory"),
            root_path.join("linked-directory"),
        )
        .unwrap();
        let root = RetainedInputRoot::open(&root_path.join("source.json")).unwrap();

        for relative in [
            "",
            "/absolute.json",
            "../outside.json",
            "qualifications/../source.json",
            "qualifications//record.json",
            "qualifications/./record.json",
            "qualifications/link.json",
            "linked-directory/record.json",
        ] {
            assert!(root.read_relative(relative).is_err(), "{relative}");
        }
    }

    fn lock_cwd() -> MutexGuard<'static, ()> {
        CWD_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    struct RestoreCwd(PathBuf);

    impl Drop for RestoreCwd {
        fn drop(&mut self) {
            std::env::set_current_dir(&self.0).unwrap();
        }
    }

    struct TempDirectory {
        path: PathBuf,
    }

    impl TempDirectory {
        fn new() -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "catalog-source-input-test-{}-{nanos}",
                std::process::id()
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
