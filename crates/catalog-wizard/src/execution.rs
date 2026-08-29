use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::Path,
    process::{Command, ExitStatus, Output, Stdio},
};

use sha2::{Digest, Sha256};

use crate::{WizardError, commands::AuthoritativeProgram};

const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;

pub fn run_status(
    program: AuthoritativeProgram,
    args: &[String],
    current_dir: &Path,
) -> Result<ExitStatus, WizardError> {
    let mut executable = TrustedExecutable::resolve(program)?;
    let status = sanitized_command(&executable, args)
        .current_dir(current_dir)
        .status()
        .map_err(|_| WizardError::ExternalCommand)?;
    executable.verify_unchanged()?;
    Ok(status)
}

pub fn run_output(program: AuthoritativeProgram, args: &[String]) -> Result<Output, WizardError> {
    let mut executable = TrustedExecutable::resolve(program)?;
    let output = sanitized_command(&executable, args)
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()
        .map_err(|_| WizardError::ExternalCommand)?;
    executable.verify_unchanged()?;
    Ok(output)
}

struct TrustedExecutable {
    file: File,
    device: u64,
    inode: u64,
    len: u64,
    sha256: [u8; 32],
}

impl TrustedExecutable {
    fn resolve(program: AuthoritativeProgram) -> Result<Self, WizardError> {
        let current = std::env::current_exe()
            .and_then(fs::canonicalize)
            .map_err(|_| WizardError::ExternalCommand)?;
        let directory = current.parent().ok_or(WizardError::ExternalCommand)?;
        Self::open_in(directory, program.executable_name())
    }

    fn open_in(directory: &Path, name: &str) -> Result<Self, WizardError> {
        if name.is_empty()
            || name.contains('/')
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(WizardError::ExternalCommand);
        }
        let directory = fs::canonicalize(directory).map_err(|_| WizardError::ExternalCommand)?;
        let directory_metadata =
            fs::symlink_metadata(&directory).map_err(|_| WizardError::ExternalCommand)?;
        if !directory_metadata.is_dir()
            || directory_metadata.file_type().is_symlink()
            || directory_metadata.permissions().mode() & 0o022 != 0
        {
            return Err(WizardError::ExternalCommand);
        }
        let path = directory.join(name);
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let mut file = options
            .open(&path)
            .map_err(|_| WizardError::ExternalCommand)?;
        let metadata = file.metadata().map_err(|_| WizardError::ExternalCommand)?;
        if !metadata.is_file()
            || metadata.uid() != current_euid()
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o022 != 0
            || metadata.permissions().mode() & 0o111 == 0
            || metadata.len() == 0
            || metadata.len() > MAX_EXECUTABLE_BYTES
        {
            return Err(WizardError::ExternalCommand);
        }
        let sha256 = hash_file(&mut file, metadata.len())?;
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
        if flags < 0
            // SAFETY: fcntl only updates descriptor flags on this retained descriptor.
            || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0
        {
            return Err(WizardError::ExternalCommand);
        }
        Ok(Self {
            file,
            device: metadata.dev(),
            inode: metadata.ino(),
            len: metadata.len(),
            sha256,
        })
    }

    fn verify_unchanged(&mut self) -> Result<(), WizardError> {
        let metadata = self
            .file
            .metadata()
            .map_err(|_| WizardError::ExternalCommand)?;
        if metadata.dev() != self.device
            || metadata.ino() != self.inode
            || metadata.len() != self.len
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o022 != 0
            || hash_file(&mut self.file, self.len)? != self.sha256
        {
            return Err(WizardError::ExternalCommand);
        }
        Ok(())
    }

    fn proc_path(&self) -> String {
        format!("/proc/self/fd/{}", self.file.as_raw_fd())
    }
}

fn sanitized_command(executable: &TrustedExecutable, args: &[String]) -> Command {
    let mut command = Command::new(executable.proc_path());
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .env("LC_ALL", "C");
    command
}

fn hash_file(file: &mut File, expected_len: u64) -> Result<[u8; 32], WizardError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| WizardError::ExternalCommand)?;
    let mut hasher = Sha256::new();
    let mut bounded = file.take(MAX_EXECUTABLE_BYTES + 1);
    let copied =
        std::io::copy(&mut bounded, &mut hasher).map_err(|_| WizardError::ExternalCommand)?;
    if copied != expected_len {
        return Err(WizardError::ExternalCommand);
    }
    Ok(hasher.finalize().into())
}

fn current_euid() -> u32 {
    // SAFETY: geteuid has no preconditions or side effects.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::{PermissionsExt, symlink},
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn authoritative_resolution_ignores_path_and_rejects_substitution_links() {
        let root = temporary_directory();
        let trusted = root.join("trusted");
        let shadow = root.join("shadow");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&trusted).unwrap();
        fs::create_dir(&shadow).unwrap();
        fs::set_permissions(&trusted, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&shadow, fs::Permissions::from_mode(0o700)).unwrap();
        let shadow_binary = shadow.join("catalog-sign-launcher");
        fs::write(&shadow_binary, b"shadow executable").unwrap();
        fs::set_permissions(&shadow_binary, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&shadow_binary, trusted.join("catalog-sign-launcher")).unwrap();
        assert!(TrustedExecutable::open_in(&trusted, "catalog-sign-launcher").is_err());
        fs::remove_file(trusted.join("catalog-sign-launcher")).unwrap();
        let trusted_binary = trusted.join("catalog-sign-launcher");
        fs::write(&trusted_binary, b"trusted executable").unwrap();
        fs::set_permissions(&trusted_binary, fs::Permissions::from_mode(0o700)).unwrap();
        TrustedExecutable::open_in(&trusted, "catalog-sign-launcher").unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn world_writable_authoritative_binary_is_rejected() {
        let root = temporary_directory();
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let binary = root.join("catalog-acquire");
        fs::write(&binary, b"executable").unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(TrustedExecutable::open_in(&root, "catalog-acquire").is_err());
        fs::remove_dir_all(root).unwrap();
    }

    fn temporary_directory() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("catalog-wizard-execution-{unique}"))
    }
}
