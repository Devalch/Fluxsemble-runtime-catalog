use crate::AcquireError;
pub(crate) use catalog_installer_verify::archive::{
    NodeArchiveInspection, NpmArchiveInspection, require_pinned_node_identity,
};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
};

/// One exact, fully rehashed archive descriptor. It carries no pathname authority.
pub struct VerifiedArchive {
    inner: catalog_installer_verify::archive::VerifiedArchive<fs::File>,
}

impl std::fmt::Debug for VerifiedArchive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

impl VerifiedArchive {
    pub fn verify(
        file: fs::File,
        source_url: String,
        expected_size: u64,
        expected_sha256: String,
        expected_sri: Option<String>,
    ) -> Result<Self, AcquireError> {
        let before = file.metadata().map_err(|_| AcquireError::Archive)?;
        if !before.is_file()
            || before.uid() != current_euid()
            || before.nlink() != 1
            || before.permissions().mode() & 0o777 != 0o400
            || before.len() != expected_size
        {
            return Err(AcquireError::Archive);
        }
        let inner = catalog_installer_verify::archive::VerifiedArchive::verify(
            file,
            source_url,
            expected_size,
            expected_sha256,
            expected_sri,
        )?;
        let mut inner = inner;
        let after = inner
            .file_mut()
            .metadata()
            .map_err(|_| AcquireError::Archive)?;
        if before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
            || after.nlink() != 1
            || after.uid() != current_euid()
            || after.permissions().mode() & 0o777 != 0o400
        {
            return Err(AcquireError::Archive);
        }
        Ok(Self { inner })
    }

    #[must_use]
    pub fn source_url(&self) -> &str {
        self.inner.source_url()
    }

    #[must_use]
    pub fn size(&self) -> u64 {
        self.inner.size()
    }

    #[must_use]
    pub fn sha256(&self) -> &str {
        self.inner.sha256()
    }

    #[must_use]
    pub fn sri(&self) -> Option<&str> {
        self.inner.sri()
    }

    pub(crate) fn into_file(self) -> fs::File {
        self.inner.into_file()
    }
}

pub fn verify_npm_archive_shape(
    archive: &mut VerifiedArchive,
    root: bool,
) -> Result<usize, AcquireError> {
    inspect_npm_archive(archive, root).map(|v| v.member_count)
}
pub fn verify_node_archive_shape(archive: &mut VerifiedArchive) -> Result<usize, AcquireError> {
    inspect_node_archive(archive).map(|v| v.member_count)
}
pub(crate) fn inspect_npm_archive(
    archive: &mut VerifiedArchive,
    root: bool,
) -> Result<NpmArchiveInspection, AcquireError> {
    catalog_installer_verify::archive::inspect_npm_archive(&mut archive.inner, root)
}
pub(crate) fn inspect_node_archive(
    archive: &mut VerifiedArchive,
) -> Result<NodeArchiveInspection, AcquireError> {
    catalog_installer_verify::archive::inspect_node_archive(&mut archive.inner)
}
fn current_euid() -> u32 {
    // SAFETY: geteuid has no preconditions and no side effects.
    unsafe { libc::geteuid() }
}
