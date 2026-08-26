use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, BufReader, Read, Seek, SeekFrom},
    os::unix::fs::{MetadataExt, PermissionsExt},
};

use base64::Engine as _;
use flate2::bufread::GzDecoder;
use sha2::{Digest, Sha256, Sha512};
use xz2::bufread::XzDecoder;

use crate::AcquireError;

const BLOCK: usize = 512;
const MAX_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_TAR_MEMBERS: usize = 32_768;
const MAX_TAR_HEADERS: usize = 65_536;
const MAX_TAR_PATH_BYTES: usize = 512;
const MAX_TAR_MEMBER_BYTES: u64 = 512 * 1024 * 1024;
const MAX_TAR_EXPANDED_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_PAX_BYTES: u64 = 256 * 1024;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_SHRINKWRAP_BYTES: u64 = 1024 * 1024;

const NODE_ROOT: &str = "node-v22.19.0-linux-x64";
const PINNED_NODE_SHA256: &str = "c0649af18e6a24f6fe5535a3e86b341dd49a8e71117c8b68bde973ef834f16f2";
const PINNED_NODE_SIZE: u64 = 30_479_988;
const LEGACY_STAR_NODE_TYPES_SHA256: &str =
    "c32937b40ab720ef6242de0bf4c8b8e48f1e4a29fbb4cb9d9f596471ee58d5c4";
const LEGACY_STAR_NODE_TYPES_SIZE: u64 = 445_223;
const LEGACY_NODETAR_SHA256: &str =
    "8f455159e342103e7854ed6a4cc73edbab144d857917c88edefea862f09fe75a";
const LEGACY_NODETAR_SIZE: u64 = 3_125;
const CANONICAL_PAX_SHA256: &str =
    "972976d054d30dfcdc6bc537b1712e28860cef38ab9e3da09b5846e5a59ef43c";
const CANONICAL_PAX_SIZE: u64 = 1_048_048;
const NODE_LINKS: [(&str, &str); 3] = [
    (
        "node-v22.19.0-linux-x64/bin/corepack",
        "../lib/node_modules/corepack/dist/corepack.js",
    ),
    (
        "node-v22.19.0-linux-x64/bin/npm",
        "../lib/node_modules/npm/bin/npm-cli.js",
    ),
    (
        "node-v22.19.0-linux-x64/bin/npx",
        "../lib/node_modules/npm/bin/npx-cli.js",
    ),
];

/// One exact, fully rehashed archive descriptor. It carries no pathname authority.
pub struct VerifiedArchive {
    file: fs::File,
    source_url: String,
    size: u64,
    sha256: String,
    sri: Option<String>,
}

impl std::fmt::Debug for VerifiedArchive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedArchive")
            .field("size", &self.size)
            .field("sha256", &self.sha256)
            .finish_non_exhaustive()
    }
}

impl VerifiedArchive {
    pub fn verify(
        mut file: fs::File,
        source_url: String,
        expected_size: u64,
        expected_sha256: String,
        expected_sri: Option<String>,
    ) -> Result<Self, AcquireError> {
        if expected_size == 0
            || expected_size > MAX_ARCHIVE_BYTES
            || !valid_sha256(&expected_sha256)
            || !safe_https_url(&source_url)
            || expected_sri.as_ref().is_some_and(|value| !valid_sri(value))
        {
            return Err(AcquireError::InvalidPolicy);
        }
        let before = file.metadata().map_err(|_| AcquireError::Archive)?;
        if !before.is_file()
            || before.uid() != current_euid()
            || before.nlink() != 1
            || before.permissions().mode() & 0o777 != 0o400
            || before.len() != expected_size
        {
            return Err(AcquireError::Archive);
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|_| AcquireError::Archive)?;
        let mut sha256 = Sha256::new();
        let mut sha512 = Sha512::new();
        let mut size = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer).map_err(|_| AcquireError::Archive)?;
            if read == 0 {
                break;
            }
            size = size.checked_add(read as u64).ok_or(AcquireError::Archive)?;
            if size > expected_size {
                return Err(AcquireError::Archive);
            }
            sha256.update(&buffer[..read]);
            sha512.update(&buffer[..read]);
        }
        let actual_sha256 = hex_lower(&sha256.finalize());
        let actual_sri = format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(sha512.finalize())
        );
        let after = file.metadata().map_err(|_| AcquireError::Archive)?;
        if size != expected_size
            || actual_sha256 != expected_sha256
            || expected_sri
                .as_ref()
                .is_some_and(|value| value != &actual_sri)
            || before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
            || after.nlink() != 1
            || after.uid() != current_euid()
            || after.permissions().mode() & 0o777 != 0o400
        {
            return Err(AcquireError::Archive);
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|_| AcquireError::Archive)?;
        Ok(Self {
            file,
            source_url,
            size,
            sha256: expected_sha256,
            sri: expected_sri,
        })
    }

    #[must_use]
    pub fn source_url(&self) -> &str {
        &self.source_url
    }

    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    #[must_use]
    pub fn sri(&self) -> Option<&str> {
        self.sri.as_deref()
    }

    pub(crate) fn file_mut(&mut self) -> &mut fs::File {
        &mut self.file
    }

    pub(crate) fn into_file(self) -> fs::File {
        self.file
    }
}

#[derive(Debug)]
pub(crate) struct NpmArchiveInspection {
    pub declaration: Vec<u8>,
    pub shrinkwrap: Option<Vec<u8>>,
    pub member_count: usize,
}

#[derive(Debug)]
pub(crate) struct NodeArchiveInspection {
    pub member_count: usize,
}

pub fn verify_npm_archive_shape(
    archive: &mut VerifiedArchive,
    root: bool,
) -> Result<usize, AcquireError> {
    inspect_npm_archive(archive, root).map(|inspection| inspection.member_count)
}

pub fn verify_node_archive_shape(archive: &mut VerifiedArchive) -> Result<usize, AcquireError> {
    inspect_node_archive(archive).map(|inspection| inspection.member_count)
}

pub(crate) fn inspect_npm_archive(
    archive: &mut VerifiedArchive,
    root: bool,
) -> Result<NpmArchiveInspection, AcquireError> {
    let policy = if root {
        ArchivePolicy::RootNpm
    } else if archive.sha256() == LEGACY_STAR_NODE_TYPES_SHA256 {
        if archive.size() != LEGACY_STAR_NODE_TYPES_SIZE {
            return Err(AcquireError::Archive);
        }
        ArchivePolicy::LegacyStarNpm
    } else if archive.sha256() == LEGACY_NODETAR_SHA256 {
        if archive.size() != LEGACY_NODETAR_SIZE {
            return Err(AcquireError::Archive);
        }
        ArchivePolicy::LegacyNodeTarNpm
    } else if archive.sha256() == CANONICAL_PAX_SHA256 {
        if archive.size() != CANONICAL_PAX_SIZE {
            return Err(AcquireError::Archive);
        }
        ArchivePolicy::CanonicalPaxNpm
    } else {
        ArchivePolicy::TransitiveNpm
    };
    let parsed = read_compressed_tar(archive, Compression::Gzip, policy)?;
    if (policy == ArchivePolicy::LegacyStarNpm
        && (parsed.physical_header_count != 83
            || parsed.member_count != 83
            || parsed.regular_count != 73
            || parsed.directory_count != 10
            || parsed.gnu_long_name_count != 0
            || parsed.symlink_count != 0))
        || (policy == ArchivePolicy::LegacyNodeTarNpm
            && (parsed.physical_header_count != 14
                || parsed.member_count != 7
                || parsed.pax_header_count != 7
                || parsed.regular_count != 7))
        || (policy == ArchivePolicy::CanonicalPaxNpm && parsed.pax_header_count != 3)
    {
        return Err(AcquireError::Archive);
    }
    let declaration = parsed
        .captured
        .get("package.json")
        .cloned()
        .ok_or(AcquireError::Archive)?;
    let shrinkwrap = parsed.captured.get("npm-shrinkwrap.json").cloned();
    if root != shrinkwrap.is_some() {
        return Err(AcquireError::Archive);
    }
    Ok(NpmArchiveInspection {
        declaration,
        shrinkwrap,
        member_count: parsed.member_count,
    })
}

pub(crate) fn inspect_node_archive(
    archive: &mut VerifiedArchive,
) -> Result<NodeArchiveInspection, AcquireError> {
    let parsed = read_compressed_tar(archive, Compression::Xz, ArchivePolicy::ExactNode)?;
    if archive.sha256() == PINNED_NODE_SHA256
        && (archive.size() != PINNED_NODE_SIZE
            || parsed.physical_header_count != 7_013
            || parsed.member_count != 5_780
            || parsed.gnu_long_name_count != 1_233
            || parsed.regular_count != 4_673
            || parsed.directory_count != 1_104
            || parsed.symlink_count != 3)
    {
        return Err(AcquireError::Archive);
    }
    Ok(NodeArchiveInspection {
        member_count: parsed.member_count,
    })
}

#[derive(Clone, Copy)]
enum Compression {
    Gzip,
    Xz,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ArchivePolicy {
    RootNpm,
    TransitiveNpm,
    LegacyStarNpm,
    LegacyNodeTarNpm,
    CanonicalPaxNpm,
    ExactNode,
}

impl ArchivePolicy {
    const fn is_npm(self) -> bool {
        matches!(
            self,
            Self::RootNpm
                | Self::TransitiveNpm
                | Self::LegacyStarNpm
                | Self::LegacyNodeTarNpm
                | Self::CanonicalPaxNpm
        )
    }
}

struct ParsedTar {
    captured: BTreeMap<String, Vec<u8>>,
    member_count: usize,
    physical_header_count: usize,
    gnu_long_name_count: usize,
    pax_header_count: usize,
    regular_count: usize,
    directory_count: usize,
    symlink_count: usize,
}

fn read_compressed_tar(
    archive: &mut VerifiedArchive,
    compression: Compression,
    policy: ArchivePolicy,
) -> Result<ParsedTar, AcquireError> {
    archive
        .file_mut()
        .seek(SeekFrom::Start(0))
        .map_err(|_| AcquireError::Archive)?;
    let mut buffered = BufReader::with_capacity(64 * 1024, archive.file_mut());
    let parsed = match compression {
        Compression::Gzip => {
            let mut decoder = GzDecoder::new(&mut buffered);
            let parsed = parse_tar(&mut decoder, policy)?;
            require_decoder_eof(&mut decoder)?;
            parsed
        }
        Compression::Xz => {
            let mut decoder = XzDecoder::new(&mut buffered);
            let parsed = parse_tar(&mut decoder, policy)?;
            require_decoder_eof(&mut decoder)?;
            parsed
        }
    };
    let buffered_unread = buffered.buffer().len() as u64;
    let cursor = buffered
        .stream_position()
        .map_err(|_| AcquireError::Archive)?;
    if cursor.checked_sub(buffered_unread) != Some(archive.size()) {
        return Err(AcquireError::Archive);
    }
    archive
        .file_mut()
        .seek(SeekFrom::Start(0))
        .map_err(|_| AcquireError::Archive)?;
    Ok(parsed)
}

fn require_decoder_eof(reader: &mut impl Read) -> Result<(), AcquireError> {
    let mut byte = [0_u8; 1];
    if reader.read(&mut byte).map_err(|_| AcquireError::Archive)? != 0 {
        return Err(AcquireError::Archive);
    }
    Ok(())
}

fn parse_tar(reader: &mut impl Read, policy: ArchivePolicy) -> Result<ParsedTar, AcquireError> {
    let mut header = [0_u8; BLOCK];
    let mut raw_paths = BTreeSet::new();
    let mut regular_paths = BTreeSet::new();
    let mut regular_facts = BTreeMap::new();
    let mut aliases = Vec::new();
    let mut links = BTreeMap::new();
    let mut captured = BTreeMap::new();
    let mut npm_root: Option<String> = None;
    let mut pending_pax: Option<PaxHeader> = None;
    let mut pending_long_name: Option<String> = None;
    let mut headers = 0_usize;
    let mut gnu_long_names = 0_usize;
    let mut pax_headers = 0_usize;
    let mut members = 0_usize;
    let mut regular_count = 0_usize;
    let mut directory_count = 0_usize;
    let mut symlink_count = 0_usize;
    let mut star_alternate_times = 0_usize;
    let mut expanded = 0_u64;
    let mut zero_blocks = 0_u8;
    let mut ended = false;
    loop {
        match reader.read_exact(&mut header) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof && ended => break,
            Err(_) => return Err(AcquireError::Archive),
        }
        if header.iter().all(|byte| *byte == 0) {
            zero_blocks = zero_blocks.saturating_add(1);
            if zero_blocks >= 2 {
                ended = true;
            }
            continue;
        }
        if ended || zero_blocks != 0 {
            return Err(AcquireError::Archive);
        }
        headers += 1;
        if headers > MAX_TAR_HEADERS || !valid_tar_checksum(&header) {
            return Err(AcquireError::Archive);
        }
        let header_size = parse_tar_number(&header[124..136])?;
        let type_flag = header[156];
        validate_numeric_header(&header, policy)?;
        if type_flag == b'x' {
            if !matches!(
                policy,
                ArchivePolicy::LegacyNodeTarNpm | ArchivePolicy::CanonicalPaxNpm
            ) || pending_pax.is_some()
                || pending_long_name.is_some()
                || header_size > MAX_PAX_BYTES
            {
                return Err(AcquireError::Archive);
            }
            let bytes = read_member_bytes(reader, header_size, MAX_PAX_BYTES)?;
            pending_pax = Some(parse_pax(&bytes, policy, pax_headers)?);
            pax_headers += 1;
            continue;
        }
        if type_flag == b'L' {
            if policy != ArchivePolicy::ExactNode
                || pending_pax.is_some()
                || pending_long_name.is_some()
                || tar_path(&header)? != "././@LongLink"
                || header_size == 0
                || header_size > MAX_TAR_PATH_BYTES as u64 + 1
            {
                return Err(AcquireError::Archive);
            }
            let bytes = read_member_bytes(reader, header_size, MAX_TAR_PATH_BYTES as u64 + 1)?;
            let (terminal, path) = bytes.split_last().ok_or(AcquireError::Archive)?;
            if *terminal != 0 || path.contains(&0) {
                return Err(AcquireError::Archive);
            }
            let path = std::str::from_utf8(path).map_err(|_| AcquireError::Archive)?;
            if path.is_empty()
                || path.starts_with('/')
                || path.contains('\\')
                || path.bytes().any(|byte| byte.is_ascii_control())
            {
                return Err(AcquireError::Archive);
            }
            pending_long_name = Some(path.to_owned());
            gnu_long_names += 1;
            continue;
        }
        let pax = pending_pax.take().unwrap_or_default();
        let raw_path = if let Some(long_name) = pending_long_name.take() {
            validate_gnu_long_name_header(&header, &long_name)?;
            long_name
        } else if policy == ArchivePolicy::LegacyStarNpm {
            star_alternate_times += validate_legacy_star_header(&header)?;
            tar_path_legacy_star(&header)?
        } else if let Some(pax_path) = pax.path {
            validate_pax_following_header(policy, &header, &pax_path)?;
            pax_path
        } else {
            tar_path(&header)?
        };
        let size = pax.size.unwrap_or(header_size);
        if size != header_size || !raw_paths.insert(raw_path.clone()) {
            return Err(AcquireError::Archive);
        }
        let path_input = if type_flag == b'5' {
            raw_path.strip_suffix('/').unwrap_or(&raw_path)
        } else {
            &raw_path
        };
        let (path, alias) = if policy.is_npm() {
            normalize_npm_path(path_input)?
        } else {
            if !safe_archive_path(path_input) {
                return Err(AcquireError::Archive);
            }
            (path_input.to_owned(), false)
        };
        if policy.is_npm() {
            let root = path.split('/').next().ok_or(AcquireError::Archive)?;
            if root.is_empty()
                || npm_root.as_deref().is_some_and(|observed| observed != root)
                || (policy == ArchivePolicy::RootNpm && root != "package")
            {
                return Err(AcquireError::Archive);
            }
            npm_root.get_or_insert_with(|| root.to_owned());
        } else if path != NODE_ROOT && !path.starts_with(&format!("{NODE_ROOT}/")) {
            return Err(AcquireError::Archive);
        }
        members += 1;
        if members > MAX_TAR_MEMBERS || size > MAX_TAR_MEMBER_BYTES {
            return Err(AcquireError::Archive);
        }
        expanded = expanded.checked_add(size).ok_or(AcquireError::Archive)?;
        if expanded > MAX_TAR_EXPANDED_BYTES {
            return Err(AcquireError::Archive);
        }
        let mode = parse_tar_number(&header[100..108])?;
        if mode > 0o777 || mode & 0o7000 != 0 {
            return Err(AcquireError::Archive);
        }
        match type_flag {
            0 | b'0' => {
                regular_count += 1;
                let capture = if policy.is_npm() {
                    capture_limit(&path)
                } else {
                    None
                };
                let (fact, bytes) = read_regular_member(reader, size, mode as u32, capture)?;
                if alias {
                    aliases.push((path, fact));
                } else {
                    if regular_facts.insert(path.clone(), fact).is_some() {
                        return Err(AcquireError::Archive);
                    }
                    regular_paths.insert(path.clone());
                    if let Some((role, bytes)) = bytes
                        && captured.insert(role.to_owned(), bytes).is_some()
                    {
                        return Err(AcquireError::Archive);
                    }
                }
            }
            b'5' if size == 0 && !alias => {
                directory_count += 1;
            }
            b'2' if policy == ArchivePolicy::ExactNode && size == 0 && !alias => {
                symlink_count += 1;
                let target = tar_string(&header[157..257])?;
                if target.is_empty() || target.starts_with('/') || target.contains('\\') {
                    return Err(AcquireError::Archive);
                }
                links.insert(path, target);
            }
            _ => return Err(AcquireError::Archive),
        }
    }
    if pending_pax.is_some() || pending_long_name.is_some() || zero_blocks < 2 || members == 0 {
        return Err(AcquireError::Archive);
    }
    if policy.is_npm() {
        if npm_root.is_none()
            || !captured.contains_key("package.json")
            || (policy == ArchivePolicy::LegacyStarNpm && star_alternate_times != 2)
        {
            return Err(AcquireError::Archive);
        }
        if policy == ArchivePolicy::RootNpm && !aliases.is_empty() {
            return Err(AcquireError::Archive);
        }
        let mut alias_targets = BTreeSet::new();
        for (target, fact) in aliases {
            if !alias_targets.insert(target.clone()) || regular_facts.get(&target) != Some(&fact) {
                return Err(AcquireError::Archive);
            }
        }
    }
    if policy == ArchivePolicy::ExactNode {
        let expected = NODE_LINKS
            .into_iter()
            .map(|(path, target)| (path.to_owned(), target.to_owned()))
            .collect::<BTreeMap<_, _>>();
        if links != expected {
            return Err(AcquireError::Archive);
        }
        for (path, target) in &links {
            let resolved = resolve_link(path, target)?;
            if !resolved.starts_with(&format!("{NODE_ROOT}/"))
                || !regular_paths.contains(&resolved)
                || links.contains_key(&resolved)
            {
                return Err(AcquireError::Archive);
            }
        }
    }
    Ok(ParsedTar {
        captured,
        member_count: members,
        physical_header_count: headers,
        gnu_long_name_count: gnu_long_names,
        pax_header_count: pax_headers,
        regular_count,
        directory_count,
        symlink_count,
    })
}

fn validate_pax_following_header(
    policy: ArchivePolicy,
    header: &[u8; BLOCK],
    path: &str,
) -> Result<(), AcquireError> {
    match policy {
        ArchivePolicy::LegacyNodeTarNpm if tar_path(header)? == path => Ok(()),
        ArchivePolicy::CanonicalPaxNpm => {
            let (dirname, basename) = path.rsplit_once('/').ok_or(AcquireError::Archive)?;
            let prefix = tar_string(&header[345..500])?;
            let name = &header[..100];
            let valid_name = if name[99] == 0 {
                basename.len() > 99
                    && std::str::from_utf8(&basename.as_bytes()[..99]).is_ok()
                    && name[..99] == basename.as_bytes()[..99]
            } else {
                basename.len() > 100
                    && std::str::from_utf8(&basename.as_bytes()[..100]).is_ok()
                    && name == &basename.as_bytes()[..100]
            };
            if prefix == dirname && valid_name {
                Ok(())
            } else {
                Err(AcquireError::Archive)
            }
        }
        _ => Err(AcquireError::Archive),
    }
}

fn validate_gnu_long_name_header(
    header: &[u8; BLOCK],
    long_name: &str,
) -> Result<(), AcquireError> {
    let bytes = long_name.as_bytes();
    if bytes.len() <= 100
        || std::str::from_utf8(&bytes[..100]).is_err()
        || header[345..500].iter().any(|byte| *byte != 0)
        || header[..100] != bytes[..100]
    {
        return Err(AcquireError::Archive);
    }
    Ok(())
}

#[derive(Clone, PartialEq, Eq)]
struct RegularMemberFact {
    mode: u32,
    size: u64,
    sha256: [u8; 32],
}

fn capture_limit(path: &str) -> Option<(&'static str, u64)> {
    let mut parts = path.split('/');
    let _root = parts.next()?;
    let name = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    match name {
        "package.json" => Some(("package.json", MAX_MANIFEST_BYTES)),
        "npm-shrinkwrap.json" => Some(("npm-shrinkwrap.json", MAX_SHRINKWRAP_BYTES)),
        _ => None,
    }
}

fn normalize_npm_path(path: &str) -> Result<(String, bool), AcquireError> {
    if safe_archive_path(path) {
        return Ok((path.to_owned(), false));
    }
    if path.is_empty()
        || path.len() > MAX_TAR_PATH_BYTES
        || path.starts_with('/')
        || path.contains('\\')
        || path.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(AcquireError::Archive);
    }
    let parts = path.split('/').collect::<Vec<_>>();
    let dots = parts
        .iter()
        .enumerate()
        .filter_map(|(index, part)| (*part == ".").then_some(index))
        .collect::<Vec<_>>();
    if dots.len() != 1
        || dots[0] == 0
        || dots[0] + 1 == parts.len()
        || parts.iter().any(|part| part.is_empty() || *part == "..")
    {
        return Err(AcquireError::Archive);
    }
    let canonical = parts
        .into_iter()
        .filter(|part| *part != ".")
        .collect::<Vec<_>>()
        .join("/");
    if !safe_archive_path(&canonical) {
        return Err(AcquireError::Archive);
    }
    Ok((canonical, true))
}

#[derive(Default)]
struct PaxHeader {
    path: Option<String>,
    size: Option<u64>,
}

fn parse_pax(bytes: &[u8], policy: ArchivePolicy, index: usize) -> Result<PaxHeader, AcquireError> {
    let mut offset = 0_usize;
    let mut values = BTreeMap::new();
    while offset < bytes.len() {
        if values.len() >= 256 {
            return Err(AcquireError::Archive);
        }
        let space = bytes[offset..]
            .iter()
            .position(|byte| *byte == b' ')
            .ok_or(AcquireError::Archive)?
            + offset;
        let length_text =
            std::str::from_utf8(&bytes[offset..space]).map_err(|_| AcquireError::Archive)?;
        let length = length_text
            .parse::<usize>()
            .map_err(|_| AcquireError::Archive)?;
        if length_text != length.to_string() || length == 0 || offset + length > bytes.len() {
            return Err(AcquireError::Archive);
        }
        let record = &bytes[space + 1..offset + length];
        if record.last() != Some(&b'\n') {
            return Err(AcquireError::Archive);
        }
        let text =
            std::str::from_utf8(&record[..record.len() - 1]).map_err(|_| AcquireError::Archive)?;
        let (key, value) = text.split_once('=').ok_or(AcquireError::Archive)?;
        if key.is_empty()
            || key.len() > 256
            || value.len() > 64 * 1024
            || values.insert(key.to_owned(), value.to_owned()).is_some()
        {
            return Err(AcquireError::Archive);
        }
        offset += length;
    }
    match policy {
        ArchivePolicy::LegacyNodeTarNpm => validate_legacy_nodetar_pax(&values, index),
        ArchivePolicy::CanonicalPaxNpm => validate_canonical_pax(&values, index),
        _ => Err(AcquireError::Archive),
    }
}

fn validate_canonical_pax(
    values: &BTreeMap<String, String>,
    index: usize,
) -> Result<PaxHeader, AcquireError> {
    const RECORDS: [(&str, u64); 3] = [
        (
            "package/esm/models/operations/getchatcompletionfieldoptionscountsv1observabilitychatcompletionfieldsfieldnameoptionscountspost.d.ts.map",
            758,
        ),
        (
            "package/esm/models/operations/getchatcompletionfieldoptionscountsv1observabilitychatcompletionfieldsfieldnameoptionscountspost.js.map",
            875,
        ),
        (
            "package/esm/models/operations/getchatcompletionfieldoptionscountsv1observabilitychatcompletionfieldsfieldnameoptionscountspost.d.ts",
            1_432,
        ),
    ];
    let (path, size) = RECORDS.get(index).ok_or(AcquireError::Archive)?;
    if values.len() != 3
        || values.get("path").map(String::as_str) != Some(*path)
        || values.get("mtime").map(String::as_str) != Some("499162500")
        || values
            .get("size")
            .and_then(|value| value.parse::<u64>().ok())
            != Some(*size)
    {
        return Err(AcquireError::Archive);
    }
    Ok(PaxHeader {
        path: Some((*path).to_owned()),
        size: Some(*size),
    })
}

fn validate_legacy_nodetar_pax(
    values: &BTreeMap<String, String>,
    index: usize,
) -> Result<PaxHeader, AcquireError> {
    const RECORDS: [(&str, u64, &str); 7] = [
        ("package/package.json", 484, "37102453"),
        ("package/.npmignore", 26, "37102454"),
        ("package/README.md", 1_101, "37102455"),
        ("package/index.js", 1_045, "37102456"),
        ("package/test.js", 1_013, "37102457"),
        ("package/.travis.yml", 45, "37102458"),
        ("package/LICENSE.txt", 1_518, "37102459"),
    ];
    let (path, size, inode) = RECORDS.get(index).ok_or(AcquireError::Archive)?;
    if values.len() != 28
        || values.get("path").map(String::as_str) != Some(*path)
        || values
            .get("size")
            .and_then(|value| value.parse::<u64>().ok())
            != Some(*size)
        || values.get("SCHILY.ino").map(String::as_str) != Some(*inode)
    {
        return Err(AcquireError::Archive);
    }
    for (key, value) in values {
        if matches!(key.as_str(), "path" | "size" | "SCHILY.ino") {
            continue;
        }
        if legacy_nodetar_static_value(key).is_none_or(|expected| value != expected) {
            return Err(AcquireError::Archive);
        }
    }
    Ok(PaxHeader {
        path: Some((*path).to_owned()),
        size: Some(*size),
    })
}

fn legacy_nodetar_static_value(key: &str) -> Option<&'static str> {
    Some(match key {
        "NODETAR.blksize" => "4096",
        "NODETAR.blocks" => "8",
        "NODETAR.depth" => "1",
        "NODETAR.follow" => "false",
        "NODETAR.ignoreFiles.0" => ".npmignore",
        "NODETAR.ignoreFiles.1" => ".gitignore",
        "NODETAR.ignoreFiles.2" => "package.json",
        "NODETAR.package.author" => "GoInstant Inc., a salesforce.com company",
        "NODETAR.package.description" => "Constant-time comparison of Buffers",
        "NODETAR.package.devDependencies.mocha" => "~1.15.1",
        "NODETAR.package.keywords.0" => "buffer",
        "NODETAR.package.keywords.1" => "equal",
        "NODETAR.package.keywords.2" => "constant-time",
        "NODETAR.package.keywords.3" => "crypto",
        "NODETAR.package.license" => "BSD-3-Clause",
        "NODETAR.package.main" => "index.js",
        "NODETAR.package.name" => "buffer-equal-constant-time",
        "NODETAR.package.repository" => "git@github.com:goinstant/buffer-equal-constant-time.git",
        "NODETAR.package.scripts.test" => "mocha test.js",
        "NODETAR.package.version" => "1.0.1",
        "NODETAR.type" => "File",
        "SCHILY.dev" => "234881029",
        "SCHILY.nlink" => "1",
        "uid" => "718322462",
        "gid" => "454177323",
        _ => return None,
    })
}

fn read_member_bytes(
    reader: &mut impl Read,
    size: u64,
    maximum: u64,
) -> Result<Vec<u8>, AcquireError> {
    if size > maximum || size > usize::MAX as u64 {
        return Err(AcquireError::Archive);
    }
    let mut bytes = vec![0_u8; size as usize];
    reader
        .read_exact(&mut bytes)
        .map_err(|_| AcquireError::Archive)?;
    read_padding(reader, size)?;
    Ok(bytes)
}

type CapturedMember = Option<(&'static str, Vec<u8>)>;

fn read_regular_member(
    reader: &mut impl Read,
    size: u64,
    mode: u32,
    capture: Option<(&'static str, u64)>,
) -> Result<(RegularMemberFact, CapturedMember), AcquireError> {
    if capture.is_some_and(|(_, maximum)| size == 0 || size > maximum) {
        return Err(AcquireError::Archive);
    }
    let mut hasher = Sha256::new();
    let mut remaining = size;
    let mut buffer = [0_u8; 64 * 1024];
    let mut captured = capture.map(|(role, _)| (role, Vec::with_capacity(size as usize)));
    while remaining != 0 {
        let wanted = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| AcquireError::Archive)?;
        reader
            .read_exact(&mut buffer[..wanted])
            .map_err(|_| AcquireError::Archive)?;
        hasher.update(&buffer[..wanted]);
        if let Some((_, bytes)) = &mut captured {
            bytes.extend_from_slice(&buffer[..wanted]);
        }
        remaining -= wanted as u64;
    }
    read_padding(reader, size)?;
    Ok((
        RegularMemberFact {
            mode,
            size,
            sha256: hasher.finalize().into(),
        },
        captured,
    ))
}

fn read_padding(reader: &mut impl Read, size: u64) -> Result<(), AcquireError> {
    let padding = (BLOCK as u64 - size % BLOCK as u64) % BLOCK as u64;
    let mut bytes = [0_u8; BLOCK];
    reader
        .read_exact(&mut bytes[..padding as usize])
        .map_err(|_| AcquireError::Archive)
}

fn tar_path(header: &[u8; BLOCK]) -> Result<String, AcquireError> {
    let name = tar_string(&header[..100])?;
    let prefix = tar_string(&header[345..500])?;
    if name.is_empty() {
        return Err(AcquireError::Archive);
    }
    Ok(if prefix.is_empty() {
        name
    } else {
        format!("{prefix}/{name}")
    })
}

fn tar_path_legacy_star(header: &[u8; BLOCK]) -> Result<String, AcquireError> {
    let name = tar_string(&header[..100])?;
    if name.is_empty() {
        return Err(AcquireError::Archive);
    }
    Ok(name)
}

fn validate_legacy_star_header(header: &[u8; BLOCK]) -> Result<usize, AcquireError> {
    const COMMON: &[u8; 12] = b"15200453521\0";
    const ALTERNATE: &[u8; 12] = b"15200453534\0";
    if header[345..476].iter().any(|byte| *byte != 0) || &header[488..500] != COMMON {
        return Err(AcquireError::Archive);
    }
    match &header[476..488] {
        value if value == COMMON => Ok(0),
        value if value == ALTERNATE => Ok(1),
        _ => Err(AcquireError::Archive),
    }
}

fn tar_string(bytes: &[u8]) -> Result<String, AcquireError> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    if bytes[end..].iter().any(|byte| *byte != 0) {
        return Err(AcquireError::Archive);
    }
    std::str::from_utf8(&bytes[..end])
        .map(str::to_owned)
        .map_err(|_| AcquireError::Archive)
}

fn validate_numeric_header(
    header: &[u8; BLOCK],
    policy: ArchivePolicy,
) -> Result<(), AcquireError> {
    for field in [
        &header[100..108],
        &header[136..148],
        &header[329..337],
        &header[337..345],
    ] {
        parse_tar_number(field)?;
    }
    for field in [&header[108..116], &header[116..124]] {
        if policy == ArchivePolicy::LegacyNodeTarNpm {
            if field.first().is_none_or(|byte| byte & 0x80 == 0) {
                return Err(AcquireError::Archive);
            }
        } else {
            parse_tar_number(field)?;
        }
    }
    Ok(())
}

fn parse_tar_number(bytes: &[u8]) -> Result<u64, AcquireError> {
    if bytes.first().is_some_and(|byte| byte & 0x80 != 0) {
        return Err(AcquireError::Archive);
    }
    let text = bytes
        .iter()
        .copied()
        .take_while(|byte| *byte != 0 && *byte != b' ')
        .collect::<Vec<_>>();
    if text.is_empty() {
        return Ok(0);
    }
    let text = std::str::from_utf8(&text).map_err(|_| AcquireError::Archive)?;
    if !text.bytes().all(|byte| matches!(byte, b'0'..=b'7')) {
        return Err(AcquireError::Archive);
    }
    u64::from_str_radix(text, 8).map_err(|_| AcquireError::Archive)
}

fn valid_tar_checksum(header: &[u8; BLOCK]) -> bool {
    let Ok(expected) = parse_tar_number(&header[148..156]) else {
        return false;
    };
    let actual: u64 = header[..148]
        .iter()
        .chain([b' '; 8].iter())
        .chain(header[156..].iter())
        .map(|byte| u64::from(*byte))
        .sum();
    expected == actual
}

fn safe_archive_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_TAR_PATH_BYTES
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.bytes().any(|byte| byte.is_ascii_control())
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn resolve_link(path: &str, target: &str) -> Result<String, AcquireError> {
    let mut parts = path.split('/').collect::<Vec<_>>();
    parts.pop();
    for part in target.split('/') {
        match part {
            "" | "." => return Err(AcquireError::Archive),
            ".." => {
                parts.pop().ok_or(AcquireError::Archive)?;
            }
            value if value.bytes().any(|byte| byte.is_ascii_control()) => {
                return Err(AcquireError::Archive);
            }
            value => parts.push(value),
        }
    }
    Ok(parts.join("/"))
}

fn safe_https_url(value: &str) -> bool {
    value.len() <= 2048
        && value.starts_with("https://")
        && !value.contains(['\\', '#', '?'])
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_sri(value: &str) -> bool {
    value.len() == 95
        && value.starts_with("sha512-")
        && base64::engine::general_purpose::STANDARD
            .decode(&value[7..])
            .is_ok_and(|bytes| bytes.len() == 64)
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn current_euid() -> u32 {
    // SAFETY: geteuid has no preconditions and no side effects.
    unsafe { libc::geteuid() }
}
