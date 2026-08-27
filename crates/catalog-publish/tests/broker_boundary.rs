#![cfg(unix)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};

#[allow(dead_code)]
#[path = "../src/broker.rs"]
mod broker;

use broker::{
    BrokerAssetUploadStatusV1, BrokerPublicationStatusV1, BrokerRequestV1, BrokerResponseV1,
    BrokerTagObjectTypeV1, BrokerTestCheckpoints, PublisherBrokerConfigV1,
};

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const TAG: &str = "catalog-v1-sequence-1";
const REPOSITORY: &str = "owner/name";
const CONFIG_CANARY: &str = "synthetic-owner-private-config-token-canary";
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);
static COMPILED_FAKE: OnceLock<PathBuf> = OnceLock::new();

struct TempTree(PathBuf);

impl TempTree {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "catalog-broker-{label}-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = make_tree_writable(&self.0);
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn make_tree_writable(path: &Path) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    fs::set_permissions(
        path,
        fs::Permissions::from_mode(if metadata.is_dir() { 0o700 } else { 0o600 }),
    )?;
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            make_tree_writable(&entry?.path())?;
        }
    }
    Ok(())
}

const FAKE_C: &str = r#"
#define _GNU_SOURCE
#include <asm/prctl.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/sched.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

static void sleep_ms(long milliseconds) {
    struct timespec value = { milliseconds / 1000, (milliseconds % 1000) * 1000000L };
    while (nanosleep(&value, &value) != 0 && errno == EINTR) {}
}

static void config_path(char *output, size_t capacity, const char *name) {
    const char *root = getenv("GH_CONFIG_DIR");
    if (root == NULL || snprintf(output, capacity, "%s/%s", root, name) >= (int)capacity) _exit(90);
}

static size_t read_file(const char *path, unsigned char *buffer, size_t capacity) {
    FILE *file = fopen(path, "rb");
    if (file == NULL) _exit(91);
    size_t total = fread(buffer, 1, capacity, file);
    if (ferror(file)) _exit(92);
    fclose(file);
    return total;
}

static void copy_file_to(const char *path, FILE *output) {
    FILE *input = fopen(path, "rb");
    if (input == NULL) _exit(93);
    unsigned char buffer[4096];
    for (;;) {
        size_t count = fread(buffer, 1, sizeof(buffer), input);
        if (count != 0 && fwrite(buffer, 1, count, output) != count) _exit(94);
        if (count < sizeof(buffer)) {
            if (ferror(input)) _exit(95);
            break;
        }
    }
    fclose(input);
}

static void flood(FILE *stream, size_t count) {
    unsigned char buffer[4096];
    memset(buffer, 'F', sizeof(buffer));
    while (count != 0) {
        size_t amount = count < sizeof(buffer) ? count : sizeof(buffer);
        if (fwrite(buffer, 1, amount, stream) != amount) break;
        fflush(stream);
        count -= amount;
    }
}

static int syscall_errno(long result) {
    return result == -1 ? errno : 0;
}

static volatile int thread_clone_ran;
static unsigned char thread_stack[64 * 1024];
static unsigned char probe_thread_stacks[32][64 * 1024];

static int thread_clone_main(void *unused) {
    (void)unused;
    thread_clone_ran = 1;
    return 0;
}

static int raw_clone_errno(unsigned long flags) {
    errno = 0;
    return syscall_errno(syscall(SYS_clone, flags, NULL, NULL, NULL, 0));
}

static int controlled_thread_clone_errno(unsigned long flags, size_t stack_index, void *tls) {
    int parent_tid = 0;
    volatile int child_tid = 1;
    thread_clone_ran = 0;
    errno = 0;
    int result = clone(
        thread_clone_main,
        probe_thread_stacks[stack_index] + sizeof(probe_thread_stacks[stack_index]),
        (int)flags,
        NULL,
        &parent_tid,
        tls,
        &child_tid
    );
    int result_errno = syscall_errno(result);
    for (int attempt = 0; result >= 0 && !thread_clone_ran && attempt < 1000; attempt++) sleep_ms(1);
    for (int attempt = 0;
         result >= 0 && (flags & CLONE_CHILD_CLEARTID) != 0 && child_tid != 0 && attempt < 1000;
         attempt++) sleep_ms(1);
    if (result >= 0 && (flags & CLONE_CHILD_CLEARTID) == 0) sleep_ms(2);
    return result_errno;
}

static void append_containment_probe(void) {
    char path[PATH_MAX];
    unsigned char path_bytes[PATH_MAX];
    config_path(path, sizeof(path), "snapshot_path");
    size_t path_size = read_file(path, path_bytes, sizeof(path_bytes) - 1);
    while (path_size != 0 && (path_bytes[path_size - 1] == '\n' || path_bytes[path_size - 1] == '\r')) path_size--;
    path_bytes[path_size] = 0;
    FILE *snapshot = fopen((char *)path_bytes, "ab");
    if (snapshot == NULL) _exit(80);

    errno = 0; int setsid_errno = syscall_errno(syscall(SYS_setsid));
    errno = 0; int setpgid_errno = syscall_errno(syscall(SYS_setpgid, 0, 0));
    errno = 0; long fork_result = syscall(SYS_fork); int fork_errno = syscall_errno(fork_result);
    if (fork_result == 0) _exit(81);
    errno = 0; long vfork_result = syscall(SYS_vfork); int vfork_errno = syscall_errno(vfork_result);
    if (vfork_result == 0) _exit(82);
    errno = 0; long clone_result = syscall(SYS_clone, SIGCHLD, 0, 0, 0, 0); int clone_errno = syscall_errno(clone_result);
    if (clone_result == 0) _exit(83);
    errno = 0; int clone3_errno = syscall_errno(syscall(SYS_clone3, NULL, 0));
    errno = 0; int unshare_errno = syscall_errno(syscall(SYS_unshare, 0));
    errno = 0; int setns_errno = syscall_errno(syscall(SYS_setns, -1, 0));
    errno = 0; int mount_errno = syscall_errno(syscall(SYS_mount, NULL, NULL, NULL, 0, NULL));

    const unsigned long thread_flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
        CLONE_SYSVSEM | CLONE_THREAD;
    void *current_tls = NULL;
    if (syscall(SYS_arch_prctl, ARCH_GET_FS, &current_tls) != 0) _exit(86);
    int settls_errno = controlled_thread_clone_errno(thread_flags | CLONE_SETTLS, 0, current_tls);
    int tid_parent_errno = controlled_thread_clone_errno(
        thread_flags | CLONE_PARENT_SETTID, 1, NULL
    );
    int tid_child_errno = controlled_thread_clone_errno(
        thread_flags | CLONE_PARENT_SETTID | CLONE_CHILD_SETTID, 2, NULL
    );
    int tid_clear_errno = controlled_thread_clone_errno(
        thread_flags | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID, 3, NULL
    );
    int tid_all_errno = controlled_thread_clone_errno(
        thread_flags | CLONE_PARENT_SETTID | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID, 4, NULL
    );

    int missing_vm_errno = controlled_thread_clone_errno(
        (thread_flags & ~CLONE_VM) | CLONE_PARENT_SETTID, 5, NULL
    );
    int missing_fs_errno = controlled_thread_clone_errno(
        (thread_flags & ~CLONE_FS) | CLONE_PARENT_SETTID, 6, NULL
    );
    int missing_files_errno = controlled_thread_clone_errno(
        (thread_flags & ~CLONE_FILES) | CLONE_PARENT_SETTID, 7, NULL
    );
    int missing_sighand_errno = controlled_thread_clone_errno(
        (thread_flags & ~CLONE_SIGHAND) | CLONE_PARENT_SETTID, 8, NULL
    );
    int missing_sysvsem_errno = controlled_thread_clone_errno(
        (thread_flags & ~CLONE_SYSVSEM) | CLONE_PARENT_SETTID, 9, NULL
    );
    int missing_thread_errno = controlled_thread_clone_errno(
        (thread_flags & ~CLONE_THREAD) | CLONE_PARENT_SETTID, 10, NULL
    );

    int extra_signal_errno = controlled_thread_clone_errno(
        thread_flags | CLONE_PARENT_SETTID | SIGCHLD, 11, NULL
    );
    int extra_parent_errno = controlled_thread_clone_errno(
        thread_flags | CLONE_PARENT_SETTID | CLONE_PARENT, 12, NULL
    );
    int extra_vfork_errno = controlled_thread_clone_errno(
        thread_flags | CLONE_PARENT_SETTID | CLONE_VFORK, 13, NULL
    );
    int extra_ptrace_errno = controlled_thread_clone_errno(
        thread_flags | CLONE_PARENT_SETTID | CLONE_PTRACE, 14, NULL
    );
    int extra_untraced_errno = controlled_thread_clone_errno(
        thread_flags | CLONE_PARENT_SETTID | CLONE_UNTRACED, 15, NULL
    );
    int extra_newns_errno = controlled_thread_clone_errno(
        thread_flags | CLONE_PARENT_SETTID | CLONE_NEWNS, 16, NULL
    );
    int extra_newuser_errno = controlled_thread_clone_errno(
        thread_flags | CLONE_PARENT_SETTID | CLONE_NEWUSER, 17, NULL
    );
    int extra_newpid_errno = controlled_thread_clone_errno(
        thread_flags | CLONE_PARENT_SETTID | CLONE_NEWPID, 18, NULL
    );
    int extra_newnet_errno = controlled_thread_clone_errno(
        thread_flags | CLONE_PARENT_SETTID | CLONE_NEWNET, 19, NULL
    );
    int high_word_errno = raw_clone_errno(thread_flags | (1UL << 32));

    errno = 0;
    int thread_result = clone(thread_clone_main, thread_stack + sizeof(thread_stack), thread_flags, NULL);
    int thread_errno = syscall_errno(thread_result);
    for (int attempt = 0; thread_result >= 0 && !thread_clone_ran && attempt < 1000; attempt++) sleep_ms(1);

    fputs("PROBE_BEGIN\n", snapshot);
    fprintf(snapshot,
        "setsid=%d\nsetpgid=%d\nfork=%d\nvfork=%d\nprocess_clone=%d\nclone3=%d\nunshare=%d\nsetns=%d\nmount=%d\nthread_clone=%d\nthread_ran=%d\n",
        setsid_errno, setpgid_errno, fork_errno, vfork_errno, clone_errno, clone3_errno,
        unshare_errno, setns_errno, mount_errno, thread_errno, thread_clone_ran);
    fprintf(snapshot,
        "settls_clone=%d\ntid_parent=%d\ntid_child=%d\ntid_clear=%d\ntid_all=%d\n",
        settls_errno, tid_parent_errno, tid_child_errno, tid_clear_errno, tid_all_errno);
    fprintf(snapshot,
        "missing_vm=%d\nmissing_fs=%d\nmissing_files=%d\nmissing_sighand=%d\nmissing_sysvsem=%d\nmissing_thread=%d\n",
        missing_vm_errno, missing_fs_errno, missing_files_errno, missing_sighand_errno,
        missing_sysvsem_errno, missing_thread_errno);
    fprintf(snapshot,
        "extra_signal=%d\nextra_parent=%d\nextra_vfork=%d\nextra_ptrace=%d\nextra_untraced=%d\nextra_newns=%d\nextra_newuser=%d\nextra_newpid=%d\nextra_newnet=%d\nhigh_word=%d\n",
        extra_signal_errno, extra_parent_errno, extra_vfork_errno, extra_ptrace_errno,
        extra_untraced_errno, extra_newns_errno, extra_newuser_errno, extra_newpid_errno,
        extra_newnet_errno, high_word_errno);
    fputs("PROBE_END\n", snapshot);
    fclose(snapshot);
}

static void attempt_config_retention(void) {
    pid_t child = fork();
    if (child < 0 && errno == EPERM) return;
    if (child < 0) _exit(84);
    if (child == 0) {
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        sleep_ms(750);
        char config[PATH_MAX], marker_config[PATH_MAX];
        unsigned char marker_path[PATH_MAX], canary[256];
        config_path(config, sizeof(config), "canary");
        config_path(marker_config, sizeof(marker_config), "escape_marker_path");
        size_t marker_size = read_file(marker_config, marker_path, sizeof(marker_path) - 1);
        marker_path[marker_size] = 0;
        size_t canary_size = read_file(config, canary, sizeof(canary));
        int marker = open((char *)marker_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (marker >= 0) {
            (void)write(marker, canary, canary_size);
            close(marker);
        }
        _exit(0);
    }
}

static void capture_snapshot(int argc, char **argv, const char *behavior) {
    char path[PATH_MAX];
    unsigned char path_bytes[PATH_MAX];
    config_path(path, sizeof(path), "snapshot_path");
    size_t path_size = read_file(path, path_bytes, sizeof(path_bytes) - 1);
    while (path_size != 0 && (path_bytes[path_size - 1] == '\n' || path_bytes[path_size - 1] == '\r')) path_size--;
    path_bytes[path_size] = 0;
    FILE *snapshot = fopen((char *)path_bytes, "wb");
    if (snapshot == NULL) _exit(96);

    fputs("ARGS_BEGIN\n", snapshot);
    for (int index = 1; index < argc; index++) fprintf(snapshot, "%s\n", argv[index]);
    fputs("ARGS_END\nENV_BEGIN\n", snapshot);
    for (char **entry = environ; *entry != NULL; entry++) fprintf(snapshot, "%s\n", *entry);
    fputs("ENV_END\nCONFIG_BEGIN\n", snapshot);
    config_path(path, sizeof(path), "canary");
    copy_file_to(path, snapshot);
    fputs("\nCONFIG_END\nBODY_BEGIN\n", snapshot);
    if (strcmp(behavior, "never_read_stdin") != 0) {
        if (strcmp(behavior, "delayed_stdin") == 0) sleep_ms(300);
        unsigned char buffer[4096];
        for (;;) {
            size_t count = fread(buffer, 1, sizeof(buffer), stdin);
            if (count != 0) fwrite(buffer, 1, count, snapshot);
            if (count < sizeof(buffer)) break;
        }
    }
    fputs("\nBODY_END\nINPUT_BEGIN\n", snapshot);
    if (argc == 7 && strcmp(argv[1], "release") == 0 && strcmp(argv[2], "upload") == 0) {
        copy_file_to(argv[4], snapshot);
    }
    fputs("\nINPUT_END\nINPUT_MODE_BEGIN\n", snapshot);
    if (argc == 7 && strcmp(argv[1], "release") == 0 && strcmp(argv[2], "upload") == 0) {
        struct stat metadata;
        if (stat(argv[4], &metadata) == 0) fprintf(snapshot, "%03o", metadata.st_mode & 0777);
    }
    fputs("\nINPUT_MODE_END\nFDS_BEGIN\n", snapshot);
    DIR *directory = opendir("/proc/self/fd");
    if (directory != NULL) {
        struct dirent *entry;
        while ((entry = readdir(directory)) != NULL) {
            if (entry->d_name[0] == '.') continue;
            char link_path[PATH_MAX], target[PATH_MAX];
            snprintf(link_path, sizeof(link_path), "/proc/self/fd/%s", entry->d_name);
            ssize_t size = readlink(link_path, target, sizeof(target) - 1);
            if (size >= 0) { target[size] = 0; fprintf(snapshot, "%s=%s\n", entry->d_name, target); }
        }
        closedir(directory);
    }
    fputs("FDS_END\n", snapshot);
    fclose(snapshot);
}

int main(int argc, char **argv) {
    char path[PATH_MAX];
    if (argc == 2 && strcmp(argv[1], "--post-exec-containment-probe") == 0) {
        append_containment_probe();
        config_path(path, sizeof(path), "response");
        copy_file_to(path, stdout);
        fflush(stdout);
        return 0;
    }
    unsigned char behavior_bytes[128];
    config_path(path, sizeof(path), "behavior");
    size_t behavior_size = read_file(path, behavior_bytes, sizeof(behavior_bytes) - 1);
    while (behavior_size != 0 && (behavior_bytes[behavior_size - 1] == '\n' || behavior_bytes[behavior_size - 1] == '\r')) behavior_size--;
    behavior_bytes[behavior_size] = 0;
    const char *behavior = (char *)behavior_bytes;
    capture_snapshot(argc, argv, behavior);

    config_path(path, sizeof(path), "response");
    if (strcmp(behavior, "failure") == 0) {
        copy_file_to(path, stdout);
        fputs("duplicate-token-path-request-canary", stderr);
        return 7;
    }
    if (strcmp(behavior, "flood_stdout") == 0) { flood(stdout, 131073); sleep_ms(10000); return 0; }
    if (strcmp(behavior, "flood_stderr") == 0) { flood(stderr, 65537); sleep_ms(10000); return 0; }
    if (strcmp(behavior, "deadlock") == 0) { flood(stderr, 131072); flood(stdout, 262144); sleep_ms(10000); return 0; }
    if (strcmp(behavior, "timeout") == 0 || strcmp(behavior, "never_read_stdin") == 0) { sleep_ms(10000); return 0; }
    if (strcmp(behavior, "signal") == 0) { raise(SIGTERM); return 0; }
    if (strcmp(behavior, "invalid_utf8") == 0) { fputc(0xff, stdout); fputc(0xfe, stdout); return 0; }
    if (strcmp(behavior, "download_overflow") == 0) { flood(stdout, 65537); return 0; }
    if (strcmp(behavior, "containment_probe") == 0) append_containment_probe();
    if (strcmp(behavior, "exec_persistence") == 0) {
        char *const arguments[] = {argv[0], "--post-exec-containment-probe", NULL};
        execve("/proc/self/exe", arguments, environ);
        return 85;
    }
    if (strcmp(behavior, "config_retention") == 0) attempt_config_retention();
    if (strcmp(behavior, "stubborn") == 0) {
        signal(SIGTERM, SIG_IGN);
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        for (;;) pause();
    }
    if (strcmp(behavior, "leader_hold") == 0 || strcmp(behavior, "download_hold") == 0) {
        pid_t child = fork();
        if (child == 0) { close(0); close(1); close(2); sleep_ms(10000); _exit(0); }
        if (child < 0 && errno != EPERM) return 88;
        copy_file_to(path, stdout);
        fflush(stdout);
        return 0;
    }
    if (strcmp(behavior, "descendant_flood") == 0) {
        pid_t child = fork();
        if (child == 0) { flood(stdout, 262144); flood(stderr, 131072); sleep_ms(10000); _exit(0); }
        if (child < 0 && errno != EPERM) return 87;
        copy_file_to(path, stdout);
        fflush(stdout);
        return 0;
    }
    copy_file_to(path, stdout);
    fflush(stdout);
    return 0;
}
"#;

fn compiled_fake() -> &'static Path {
    COMPILED_FAKE
        .get_or_init(|| {
            let root = std::env::temp_dir().join(format!(
                "catalog-broker-compiled-fake-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&root);
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            let source = root.join("fake-gh.c");
            let executable = root.join("fake-gh");
            fs::write(&source, FAKE_C).unwrap();
            let output = Command::new("cc")
                .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
                .arg(&source)
                .arg("-o")
                .arg(&executable)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "fake ELF compile failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o500)).unwrap();
            executable
        })
        .as_path()
}

#[derive(Clone, Copy)]
enum FakeBehavior {
    Success,
    Failure,
    FloodStdout,
    FloodStderr,
    Deadlock,
    Timeout,
    NeverReadStdin,
    DelayedStdin,
    Signal,
    InvalidUtf8,
    LeaderHold,
    DescendantFlood,
    DownloadOverflow,
    DownloadHold,
    ContainmentProbe,
    ExecPersistence,
    ConfigRetention,
    Stubborn,
}

impl FakeBehavior {
    const fn name(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::FloodStdout => "flood_stdout",
            Self::FloodStderr => "flood_stderr",
            Self::Deadlock => "deadlock",
            Self::Timeout => "timeout",
            Self::NeverReadStdin => "never_read_stdin",
            Self::DelayedStdin => "delayed_stdin",
            Self::Signal => "signal",
            Self::InvalidUtf8 => "invalid_utf8",
            Self::LeaderHold => "leader_hold",
            Self::DescendantFlood => "descendant_flood",
            Self::DownloadOverflow => "download_overflow",
            Self::DownloadHold => "download_hold",
            Self::ContainmentProbe => "containment_probe",
            Self::ExecPersistence => "exec_persistence",
            Self::ConfigRetention => "config_retention",
            Self::Stubborn => "stubborn",
        }
    }
}

struct Fixture {
    root: TempTree,
    executable: PathBuf,
    config_dir: PathBuf,
    config: PathBuf,
    snapshot: PathBuf,
}

impl Fixture {
    fn new(label: &str, behavior: FakeBehavior, response: &[u8]) -> Self {
        let root = TempTree::new(label);
        let config_dir = root.path("github-config");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&config_dir)
            .unwrap();
        let snapshot = root.path("snapshot");
        let escape_marker = root.path("escaped-config-marker");
        for (name, bytes) in [
            ("canary", CONFIG_CANARY.as_bytes()),
            ("behavior", behavior.name().as_bytes()),
            ("response", response),
            ("snapshot_path", snapshot.as_os_str().as_encoded_bytes()),
            (
                "escape_marker_path",
                escape_marker.as_os_str().as_encoded_bytes(),
            ),
        ] {
            fs::write(config_dir.join(name), bytes).unwrap();
            fs::set_permissions(config_dir.join(name), fs::Permissions::from_mode(0o600)).unwrap();
        }
        let executable = root.path("fake-gh");
        fs::copy(compiled_fake(), &executable).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o500)).unwrap();
        let config = root.path("broker-config.json");
        write_config(
            &config,
            &PublisherBrokerConfigV1 {
                schema_version: 1,
                gh_path: executable.to_str().unwrap().to_owned(),
                gh_sha256: sha256(&fs::read(&executable).unwrap()),
                github_config_dir: config_dir.to_str().unwrap().to_owned(),
            },
        );
        Self {
            root,
            executable,
            config_dir,
            config,
            snapshot,
        }
    }

    fn snapshot_section(&self, start: &str, end: &str) -> String {
        let value = fs::read_to_string(&self.snapshot).unwrap();
        value
            .split_once(start)
            .unwrap()
            .1
            .split_once(end)
            .unwrap()
            .0
            .trim_matches('\n')
            .to_owned()
    }

    fn arguments(&self) -> Vec<String> {
        self.snapshot_section("ARGS_BEGIN\n", "\nARGS_END")
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

fn write_config(path: &Path, value: &PublisherBrokerConfigV1) {
    fs::write(path, serde_jcs::to_vec(value).unwrap()).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn tag_json() -> Vec<u8> {
    format!("{{\"object\":{{\"secret\":\"child-token-canary\",\"sha\":\"{COMMIT}\",\"type\":\"commit\"}},\"ref\":\"refs/tags/{TAG}\",\"unexpected\":\"child-path-canary\"}}").into_bytes()
}

fn draft_json() -> Vec<u8> {
    format!("{{\"assets\":[{{\"id\":8,\"name\":\"existing.bin\",\"secret\":\"child-token-canary\",\"size\":3}}],\"body\":\"Reviewed release notes\",\"draft\":true,\"id\":7,\"name\":\"Runtime catalog sequence 1\",\"prerelease\":false,\"tag_name\":\"{TAG}\",\"target_commitish\":\"{COMMIT}\",\"unexpected\":\"child-path-canary\"}}").into_bytes()
}

fn draft_list_json() -> Vec<u8> {
    let draft = String::from_utf8(draft_json()).unwrap();
    format!("[{draft}]").into_bytes()
}

fn read_tag_request() -> BrokerRequestV1 {
    BrokerRequestV1::ReadTag {
        schema_version: 1,
        repository: REPOSITORY.to_owned(),
        tag: TAG.to_owned(),
    }
}

fn execute(
    fixture: &Fixture,
    request: &BrokerRequestV1,
) -> Result<BrokerResponseV1, broker::BrokerError> {
    struct Noop;
    impl BrokerTestCheckpoints for Noop {}
    broker::execute_with_test_checkpoints(&fixture.config, request, &mut Noop)
}

#[test]
fn broker_requests_are_a_closed_command_family_and_protocol_is_strict() {
    assert_eq!(
        BrokerRequestV1::all_kinds(),
        &[
            "create_tag",
            "read_tag",
            "create_draft",
            "read_draft",
            "upload_asset",
            "download_asset",
            "publish_draft"
        ]
    );
    let canonical = read_tag_request().to_canonical_bytes().unwrap();
    assert_eq!(
        BrokerRequestV1::from_canonical_bytes(&canonical).unwrap(),
        read_tag_request()
    );

    let upload = BrokerRequestV1::UploadAsset {
        schema_version: 1,
        repository: REPOSITORY.to_owned(),
        tag: TAG.to_owned(),
        name: "support.bin".to_owned(),
        input_path: "/private/input".to_owned(),
    };
    let encoded = String::from_utf8(upload.to_canonical_bytes().unwrap()).unwrap();
    assert!(encoded.contains(&format!("\"tag\":\"{TAG}\"")));
    assert!(!encoded.contains("release_id"));

    for bytes in [
        br#"{"kind":"auth","repository":"owner/name","schema_version":1}"#.as_slice(),
        br#"{"kind":"read_tag","repository":"owner/name","schema_version":1,"tag":"catalog-v1-sequence-1","token":"denied"}"#,
        br#"{"kind":"read_tag","repository":"owner/name","schema_version":1,"schema_version":1,"tag":"catalog-v1-sequence-1"}"#,
        br#"{"kind":"read_tag","repository":"owner/name","schema_version":1,"tag":"catalog-v1-sequence-1"} "#,
        br#"{"kind":"read_tag","repository":"owner/name","schema_version":1,"tag":"refs/tags/main"}"#,
        br#"{"kind":"read_tag","repository":"owner//name","schema_version":1,"tag":"catalog-v1-sequence-1"}"#,
        br#"{"input_path":"/private/input","kind":"upload_asset","name":"support.bin","release_id":"7","repository":"owner/name","schema_version":1,"tag":"catalog-v1-sequence-1"}"#,
    ] {
        assert!(BrokerRequestV1::from_canonical_bytes(bytes).is_err());
    }
    assert!(
        BrokerResponseV1::from_canonical_bytes(
            br#"{"kind":"asset_uploaded","name":"support.bin","release_id":"7","schema_version":1,"sha256":"0000000000000000000000000000000000000000000000000000000000000000","size":1,"status":"asset_uploaded"}"#
        )
        .is_err()
    );
}

#[test]
fn read_draft_list_distinguishes_exact_missing_duplicate_and_truncated_state() {
    let request = BrokerRequestV1::ReadDraft {
        schema_version: 1,
        repository: REPOSITORY.to_owned(),
        tag: TAG.to_owned(),
    };
    let missing = Fixture::new("draft-missing", FakeBehavior::Success, b"[]");
    assert_eq!(
        execute(&missing, &request).unwrap(),
        BrokerResponseV1::DraftMissing {
            schema_version: 1,
            tag: TAG.to_owned()
        }
    );

    let draft = String::from_utf8(draft_json()).unwrap();
    let duplicate = draft.replace("\"id\":7", "\"id\":9");
    let ambiguous = Fixture::new(
        "draft-duplicate",
        FakeBehavior::Success,
        format!("[{draft},{duplicate}]").as_bytes(),
    );
    assert!(execute(&ambiguous, &request).is_err());

    let full_page = serde_json::to_vec(
        &(1..=100)
            .map(|sequence| serde_json::json!({"tag_name": format!("catalog-v1-sequence-{sequence}")}))
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let truncated = Fixture::new("draft-full-page", FakeBehavior::Success, &full_page);
    assert!(execute(&truncated, &request).is_err());

    let exact = Fixture::new(
        "draft-exact-list",
        FakeBehavior::Success,
        format!("[{draft}]").as_bytes(),
    );
    assert!(matches!(
        execute(&exact, &request).unwrap(),
        BrokerResponseV1::Draft { title, notes, .. }
            if title == "Runtime catalog sequence 1" && notes == "Reviewed release notes"
    ));
}

#[test]
fn exact_seven_command_families_have_fixed_argv_body_environment_and_projection() {
    let cases = vec![
        (
            BrokerRequestV1::CreateTag {
                schema_version: 1,
                repository: REPOSITORY.to_owned(),
                tag: TAG.to_owned(),
                commit_sha: COMMIT.to_owned(),
            },
            tag_json(),
            vec![
                "api",
                "--method",
                "POST",
                "/repos/owner/name/git/refs",
                "--header",
                "Accept: application/vnd.github+json",
                "--header",
                "X-GitHub-Api-Version: 2022-11-28",
                "--input",
                "-",
            ],
            format!("{{\"ref\":\"refs/tags/{TAG}\",\"sha\":\"{COMMIT}\"}}"),
        ),
        (
            read_tag_request(),
            tag_json(),
            vec![
                "api",
                "--method",
                "GET",
                "/repos/owner/name/git/ref/tags/catalog-v1-sequence-1",
                "--header",
                "Accept: application/vnd.github+json",
                "--header",
                "X-GitHub-Api-Version: 2022-11-28",
            ],
            String::new(),
        ),
        (
            BrokerRequestV1::CreateDraft {
                schema_version: 1,
                repository: REPOSITORY.to_owned(),
                tag: TAG.to_owned(),
                target_commitish: COMMIT.to_owned(),
                title: "Runtime catalog sequence 1".to_owned(),
                notes: "Reviewed release notes".to_owned(),
                prerelease: false,
            },
            draft_json(),
            vec![
                "api",
                "--method",
                "POST",
                "/repos/owner/name/releases",
                "--header",
                "Accept: application/vnd.github+json",
                "--header",
                "X-GitHub-Api-Version: 2022-11-28",
                "--input",
                "-",
            ],
            format!(
                "{{\"body\":\"Reviewed release notes\",\"draft\":true,\"name\":\"Runtime catalog sequence 1\",\"prerelease\":false,\"tag_name\":\"{TAG}\",\"target_commitish\":\"{COMMIT}\"}}"
            ),
        ),
        (
            BrokerRequestV1::ReadDraft {
                schema_version: 1,
                repository: REPOSITORY.to_owned(),
                tag: TAG.to_owned(),
            },
            draft_list_json(),
            vec![
                "api",
                "--method",
                "GET",
                "/repos/owner/name/releases?per_page=100",
                "--header",
                "Accept: application/vnd.github+json",
                "--header",
                "X-GitHub-Api-Version: 2022-11-28",
            ],
            String::new(),
        ),
        (
            BrokerRequestV1::PublishDraft {
                schema_version: 1,
                repository: REPOSITORY.to_owned(),
                release_id: "7".to_owned(),
            },
            br#"{"draft":false,"id":7,"secret":"child-token-canary"}"#.to_vec(),
            vec![
                "api",
                "--method",
                "PATCH",
                "/repos/owner/name/releases/7",
                "--header",
                "Accept: application/vnd.github+json",
                "--header",
                "X-GitHub-Api-Version: 2022-11-28",
                "--input",
                "-",
            ],
            "{\"draft\":false}".to_owned(),
        ),
    ];

    for (index, (request, response, expected_args, expected_body)) in cases.into_iter().enumerate()
    {
        let fixture = Fixture::new(&format!("matrix-{index}"), FakeBehavior::Success, &response);
        let projected = execute(&fixture, &request).unwrap();
        let safe = String::from_utf8(projected.to_canonical_bytes().unwrap()).unwrap();
        assert!(!safe.contains("child-token-canary"));
        assert!(!safe.contains("child-path-canary"));
        assert_eq!(fixture.arguments(), expected_args);
        assert_eq!(
            fixture.snapshot_section("BODY_BEGIN\n", "\nBODY_END"),
            expected_body
        );
        assert_eq!(
            fixture.snapshot_section("CONFIG_BEGIN\n", "\nCONFIG_END"),
            CONFIG_CANARY
        );
        assert_exact_environment(&fixture);
    }

    let upload_fixture = Fixture::new(
        "matrix-upload",
        FakeBehavior::Success,
        b"ignored-child-token-canary",
    );
    let input = upload_fixture.root.path("host-object");
    fs::write(&input, b"asset-canary").unwrap();
    fs::set_permissions(&input, fs::Permissions::from_mode(0o400)).unwrap();
    let upload = BrokerRequestV1::UploadAsset {
        schema_version: 1,
        repository: REPOSITORY.to_owned(),
        tag: TAG.to_owned(),
        name: "support.bin".to_owned(),
        input_path: input.to_str().unwrap().to_owned(),
    };
    assert!(matches!(
        execute(&upload_fixture, &upload).unwrap(),
        BrokerResponseV1::AssetUploaded {
            status: BrokerAssetUploadStatusV1::AssetUploaded,
            ..
        }
    ));
    let upload_args = upload_fixture.arguments();
    assert_eq!(
        &upload_args[..4],
        ["release", "upload", TAG, upload_args[3].as_str()]
    );
    assert_eq!(&upload_args[4..], ["--repo", REPOSITORY]);
    assert_eq!(
        Path::new(&upload_args[3]).file_name().unwrap(),
        "support.bin"
    );
    assert!(upload_args[3].starts_with("/tmp/catalog-gh-broker-upload-"));
    assert!(!upload_args.iter().any(|argument| argument == "--clobber"));
    assert_exact_environment(&upload_fixture);
    assert!(
        !upload_fixture
            .snapshot_section("FDS_BEGIN\n", "\nFDS_END")
            .contains(input.to_str().unwrap())
    );

    let download_fixture = Fixture::new(
        "matrix-download",
        FakeBehavior::Success,
        b"downloaded-asset",
    );
    let output = download_fixture.root.path("downloaded.bin");
    let download = BrokerRequestV1::DownloadAsset {
        schema_version: 1,
        repository: REPOSITORY.to_owned(),
        asset_id: "9".to_owned(),
        name: "downloaded.bin".to_owned(),
        output_path: output.to_str().unwrap().to_owned(),
    };
    execute(&download_fixture, &download).unwrap();
    assert_eq!(
        download_fixture.arguments(),
        [
            "api",
            "--method",
            "GET",
            "/repos/owner/name/releases/assets/9",
            "--header",
            "Accept: application/octet-stream",
            "--header",
            "X-GitHub-Api-Version: 2022-11-28"
        ]
    );
    assert_exact_environment(&download_fixture);
    assert!(
        !download_fixture
            .snapshot_section("FDS_BEGIN\n", "\nFDS_END")
            .contains(output.to_str().unwrap())
    );
}

fn assert_exact_environment(fixture: &Fixture) {
    let environment = fixture.snapshot_section("ENV_BEGIN\n", "\nENV_END");
    let environment = environment
        .lines()
        .map(|line| line.split_once('=').unwrap())
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        environment.keys().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from(["GH_CONFIG_DIR", "HOME", "LANG", "LC_ALL", "TZ"])
    );
    assert_eq!(environment["LANG"], "C");
    assert_eq!(environment["LC_ALL"], "C");
    assert_eq!(environment["TZ"], "UTC");
    assert!(environment["GH_CONFIG_DIR"].starts_with("/proc/self/fd/"));
    assert!(environment["HOME"].starts_with("/tmp/catalog-gh-broker-home-"));
    assert!(!Path::new(environment["HOME"]).exists());
    let descriptors = fixture.snapshot_section("FDS_BEGIN\n", "\nFDS_END");
    assert!(descriptors.contains(fixture.config_dir.to_str().unwrap()));
    assert!(descriptors.contains(fixture.executable.to_str().unwrap()));
    assert!(!descriptors.contains(fixture.config.to_str().unwrap()));
    assert!(!descriptors.contains("/.ssh/"));
    assert!(!descriptors.contains("/.config/gh"));
}

#[test]
fn release_upload_materializes_private_exact_file_and_returns_no_fabricated_id() {
    let fixture = Fixture::new(
        "upload-private",
        FakeBehavior::Success,
        b"child-token-path-canary",
    );
    let input = fixture.root.path("host-input-object");
    fs::write(&input, b"exact-upload-bytes").unwrap();
    fs::set_permissions(&input, fs::Permissions::from_mode(0o400)).unwrap();
    let request = BrokerRequestV1::UploadAsset {
        schema_version: 1,
        repository: REPOSITORY.to_owned(),
        tag: TAG.to_owned(),
        name: "support.bin".to_owned(),
        input_path: input.to_str().unwrap().to_owned(),
    };
    let response = execute(&fixture, &request).unwrap();
    assert_eq!(
        response,
        BrokerResponseV1::AssetUploaded {
            schema_version: 1,
            status: BrokerAssetUploadStatusV1::AssetUploaded,
            name: "support.bin".to_owned(),
            size: 18,
            sha256: sha256(b"exact-upload-bytes")
        }
    );
    let canonical = String::from_utf8(response.to_canonical_bytes().unwrap()).unwrap();
    assert!(!canonical.contains("asset_id"));
    assert!(!canonical.contains("release_id"));
    assert!(!canonical.contains("child-token-path-canary"));
    assert_eq!(
        fixture.snapshot_section("INPUT_BEGIN\n", "\nINPUT_END"),
        "exact-upload-bytes"
    );
    assert_eq!(
        fixture.snapshot_section("INPUT_MODE_BEGIN\n", "\nINPUT_MODE_END"),
        "400"
    );
    let arguments = fixture.arguments();
    assert_eq!(arguments[0..3], ["release", "upload", TAG]);
    assert_eq!(arguments[4..], ["--repo", REPOSITORY]);
    assert_ne!(Path::new(&arguments[3]), input);
    assert_eq!(Path::new(&arguments[3]).file_name().unwrap(), "support.bin");
    assert!(
        !Path::new(&arguments[3]).exists(),
        "private upload file is removed after the request"
    );
    assert_eq!(fs::read(&input).unwrap(), b"exact-upload-bytes");

    let duplicate = Fixture::new(
        "upload-duplicate",
        FakeBehavior::Failure,
        b"duplicate-secret-canary",
    );
    let duplicate_input = duplicate.root.path("host-object");
    fs::write(&duplicate_input, b"same-bytes").unwrap();
    fs::set_permissions(&duplicate_input, fs::Permissions::from_mode(0o400)).unwrap();
    let duplicate_request = BrokerRequestV1::UploadAsset {
        schema_version: 1,
        repository: REPOSITORY.to_owned(),
        tag: TAG.to_owned(),
        name: "support.bin".to_owned(),
        input_path: duplicate_input.to_str().unwrap().to_owned(),
    };
    let error = execute(&duplicate, &duplicate_request).unwrap_err();
    assert_eq!(error.to_string(), "github broker failed");
    assert_eq!(fs::read(&duplicate_input).unwrap(), b"same-bytes");
    let private_path = duplicate.arguments()[3].clone();
    assert!(!Path::new(&private_path).exists());
    let binary_failure = run_binary(
        &duplicate.config,
        &duplicate_request.to_canonical_bytes().unwrap(),
    );
    assert!(!binary_failure.status.success());
    assert!(binary_failure.stdout.is_empty());
    assert_eq!(binary_failure.stderr, b"github broker failed\n");
    assert!(!String::from_utf8_lossy(&binary_failure.stderr).contains("duplicate-secret-canary"));
}

#[test]
fn one_nonblocking_deadline_supervises_stdin_and_has_no_blocking_post_deadline_wait() {
    let large_notes = "n".repeat(16 * 1024);
    let delayed = Fixture::new("delayed-stdin", FakeBehavior::DelayedStdin, &draft_json());
    let delayed_request = BrokerRequestV1::CreateDraft {
        schema_version: 1,
        repository: REPOSITORY.to_owned(),
        tag: TAG.to_owned(),
        target_commitish: COMMIT.to_owned(),
        title: "title".to_owned(),
        notes: large_notes.clone(),
        prerelease: false,
    };
    assert!(execute(&delayed, &delayed_request).is_ok());

    let never = Fixture::new(
        "non-reading-stdin",
        FakeBehavior::NeverReadStdin,
        &draft_json(),
    );
    let request = BrokerRequestV1::CreateDraft {
        schema_version: 1,
        repository: REPOSITORY.to_owned(),
        tag: TAG.to_owned(),
        target_commitish: COMMIT.to_owned(),
        title: "title".to_owned(),
        notes: large_notes,
        prerelease: false,
    };
    assert_bounded_failure(&never, &request);

    for (label, behavior) in [
        ("stdout-one-byte-overflow", FakeBehavior::FloodStdout),
        ("stderr-one-byte-overflow", FakeBehavior::FloodStderr),
        ("simultaneous-deadlock-flood", FakeBehavior::Deadlock),
        ("timeout", FakeBehavior::Timeout),
        ("stubborn-closed-stdio", FakeBehavior::Stubborn),
        ("signal", FakeBehavior::Signal),
        ("invalid-utf8", FakeBehavior::InvalidUtf8),
    ] {
        let fixture = Fixture::new(label, behavior, &tag_json());
        assert_bounded_failure(&fixture, &read_tag_request());
    }
}

#[test]
fn seccomp_denies_process_and_session_escape_but_allows_runtime_thread_clone() {
    let probe = Fixture::new(
        "containment-syscall-probe",
        FakeBehavior::ContainmentProbe,
        &tag_json(),
    );
    assert!(execute(&probe, &read_tag_request()).is_ok());
    let outcomes = probe.snapshot_section("PROBE_BEGIN\n", "\nPROBE_END");
    for syscall in [
        "setsid",
        "setpgid",
        "fork",
        "vfork",
        "process_clone",
        "clone3",
        "unshare",
        "setns",
        "mount",
    ] {
        assert!(
            outcomes.lines().any(|line| line == format!("{syscall}=1")),
            "missing EPERM containment outcome for {syscall}: {outcomes}"
        );
    }
    assert!(outcomes.lines().any(|line| line == "thread_clone=0"));
    assert!(outcomes.lines().any(|line| line == "thread_ran=1"));
    let errno = |name: &str| {
        outcomes
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}=")))
            .and_then(|value| value.parse::<i32>().ok())
            .unwrap_or_else(|| panic!("missing clone outcome for {name}: {outcomes}"))
    };
    assert_ne!(errno("settls_clone"), libc::EPERM);
    for metadata_probe in ["tid_parent", "tid_child", "tid_clear", "tid_all"] {
        assert_ne!(
            errno(metadata_probe),
            libc::EPERM,
            "safe TID metadata was rejected: {metadata_probe}"
        );
    }
    for missing_required in [
        "missing_vm",
        "missing_fs",
        "missing_files",
        "missing_sighand",
        "missing_sysvsem",
        "missing_thread",
    ] {
        assert_eq!(
            errno(missing_required),
            libc::EPERM,
            "clone missing a required thread-sharing flag was admitted: {missing_required}"
        );
    }
    for forbidden_extra in [
        "extra_signal",
        "extra_parent",
        "extra_vfork",
        "extra_ptrace",
        "extra_untraced",
        "extra_newns",
        "extra_newuser",
        "extra_newpid",
        "extra_newnet",
        "high_word",
    ] {
        assert_eq!(
            errno(forbidden_extra),
            libc::EPERM,
            "clone with a forbidden process flag was admitted: {forbidden_extra}"
        );
    }

    let post_exec = Fixture::new(
        "containment-persists-across-later-exec",
        FakeBehavior::ExecPersistence,
        &tag_json(),
    );
    assert!(execute(&post_exec, &read_tag_request()).is_ok());
    let post_exec_outcomes = post_exec.snapshot_section("PROBE_BEGIN\n", "\nPROBE_END");
    assert!(post_exec_outcomes.lines().any(|line| line == "fork=1"));
    assert!(
        post_exec_outcomes
            .lines()
            .any(|line| line == "thread_clone=0")
    );

    for (label, behavior) in [
        (
            "leader-exits-after-denied-closed-stdio-fork",
            FakeBehavior::LeaderHold,
        ),
        (
            "denied-descendant-cannot-flood-retained-pipes",
            FakeBehavior::DescendantFlood,
        ),
        (
            "denied-descendant-cannot-retain-config",
            FakeBehavior::ConfigRetention,
        ),
    ] {
        let fixture = Fixture::new(label, behavior, &tag_json());
        let started = Instant::now();
        assert!(execute(&fixture, &read_tag_request()).is_ok());
        assert!(started.elapsed() < Duration::from_secs(2));
        thread::sleep(Duration::from_millis(900));
        assert!(
            !fixture.root.path("escaped-config-marker").exists(),
            "descendant retained config after successful return: {label}"
        );
    }
}

fn assert_bounded_failure(fixture: &Fixture, request: &BrokerRequestV1) {
    let start = Instant::now();
    let error = execute(fixture, request).unwrap_err();
    assert_eq!(error.to_string(), "github broker failed");
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "unbounded broker failure: {:?}",
        start.elapsed()
    );
}

#[test]
fn download_is_broker_streamed_bounded_and_removes_partial_or_descendant_output() {
    let success = Fixture::new(
        "download-stream",
        FakeBehavior::Success,
        b"downloaded-asset",
    );
    let output = success.root.path("downloaded.bin");
    let request = BrokerRequestV1::DownloadAsset {
        schema_version: 1,
        repository: REPOSITORY.to_owned(),
        asset_id: "9".to_owned(),
        name: "downloaded.bin".to_owned(),
        output_path: output.to_str().unwrap().to_owned(),
    };
    let response = execute(&success, &request).unwrap();
    assert_eq!(fs::read(&output).unwrap(), b"downloaded-asset");
    assert_eq!(
        fs::metadata(&output).unwrap().permissions().mode() & 0o7777,
        0o400
    );
    assert!(matches!(response, BrokerResponseV1::Asset { .. }));

    let contained = Fixture::new(
        "download-descendant-denied-before-final-settlement",
        FakeBehavior::DownloadHold,
        b"contained-download",
    );
    let contained_output = contained.root.path("contained.bin");
    let contained_request = BrokerRequestV1::DownloadAsset {
        schema_version: 1,
        repository: REPOSITORY.to_owned(),
        asset_id: "9".to_owned(),
        name: "contained.bin".to_owned(),
        output_path: contained_output.to_str().unwrap().to_owned(),
    };
    assert!(execute(&contained, &contained_request).is_ok());
    assert_eq!(fs::read(contained_output).unwrap(), b"contained-download");

    let no_clobber = Fixture::new("download-no-clobber", FakeBehavior::Success, b"new");
    let existing = no_clobber.root.path("downloaded.bin");
    fs::write(&existing, b"prior").unwrap();
    let request = BrokerRequestV1::DownloadAsset {
        schema_version: 1,
        repository: REPOSITORY.to_owned(),
        asset_id: "9".to_owned(),
        name: "downloaded.bin".to_owned(),
        output_path: existing.to_str().unwrap().to_owned(),
    };
    assert!(execute(&no_clobber, &request).is_err());
    assert_eq!(fs::read(existing).unwrap(), b"prior");

    let overflow = Fixture::new(
        "download-overflow",
        FakeBehavior::DownloadOverflow,
        b"partial-download-canary",
    );
    let overflow_output = overflow.root.path("failed.bin");
    let overflow_request = BrokerRequestV1::DownloadAsset {
        schema_version: 1,
        repository: REPOSITORY.to_owned(),
        asset_id: "9".to_owned(),
        name: "failed.bin".to_owned(),
        output_path: overflow_output.to_str().unwrap().to_owned(),
    };
    assert_bounded_failure(&overflow, &overflow_request);
    assert!(
        !overflow_output.exists(),
        "failed streamed output survived: download-overflow"
    );

    struct BlockSettlement;
    impl BrokerTestCheckpoints for BlockSettlement {
        fn block_download_settlement_after_first_write(&mut self) -> bool {
            true
        }
    }
    let blocked = Fixture::new(
        "download-blocked-settlement-writer",
        FakeBehavior::Success,
        b"partial-download-canary",
    );
    let output = blocked.root.path("blocked.bin");
    let request = BrokerRequestV1::DownloadAsset {
        schema_version: 1,
        repository: REPOSITORY.to_owned(),
        asset_id: "9".to_owned(),
        name: "blocked.bin".to_owned(),
        output_path: output.to_str().unwrap().to_owned(),
    };
    let started = Instant::now();
    assert!(
        broker::execute_with_test_checkpoints(&blocked.config, &request, &mut BlockSettlement)
            .is_err()
    );
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "settlement exceeded its separate hard deadline: {:?}",
        started.elapsed()
    );
    assert!(!output.exists(), "exact partial settlement inode survived");
}

#[test]
fn download_rebinds_the_canonical_parent_and_leaf_after_settlement() {
    struct SwapParentAfterSettlementHelper {
        requested_parent: PathBuf,
        retained_parent: PathBuf,
        replacement_parent: PathBuf,
    }
    impl BrokerTestCheckpoints for SwapParentAfterSettlementHelper {
        fn after_download_settlement_helper(&mut self) {
            fs::rename(&self.requested_parent, &self.retained_parent).unwrap();
            fs::rename(&self.replacement_parent, &self.requested_parent).unwrap();
        }
    }

    let fixture = Fixture::new(
        "download-post-settlement-parent-swap",
        FakeBehavior::Success,
        b"settled-download-canary",
    );
    let replacement = TempTree::new("download-canonical-parent-replacement");
    let replacement_output = replacement.path("swapped.bin");
    fs::write(&replacement_output, b"canonical-replacement-canary").unwrap();
    fs::set_permissions(&replacement_output, fs::Permissions::from_mode(0o600)).unwrap();
    let replacement_identity = fs::metadata(&replacement_output).unwrap();
    let requested_parent = fixture.root.0.clone();
    let retained_parent = requested_parent.with_extension("retained-parent");
    let request = BrokerRequestV1::DownloadAsset {
        schema_version: 1,
        repository: REPOSITORY.to_owned(),
        asset_id: "9".to_owned(),
        name: "swapped.bin".to_owned(),
        output_path: requested_parent
            .join("swapped.bin")
            .to_str()
            .unwrap()
            .to_owned(),
    };
    let mut checkpoint = SwapParentAfterSettlementHelper {
        requested_parent: requested_parent.clone(),
        retained_parent: retained_parent.clone(),
        replacement_parent: replacement.0.clone(),
    };

    assert!(
        broker::execute_with_test_checkpoints(&fixture.config, &request, &mut checkpoint).is_err(),
        "download succeeded after its requested canonical parent was replaced"
    );
    let canonical_replacement = requested_parent.join("swapped.bin");
    assert_eq!(
        fs::read(&canonical_replacement).unwrap(),
        b"canonical-replacement-canary"
    );
    let after_identity = fs::metadata(&canonical_replacement).unwrap();
    assert_eq!(after_identity.dev(), replacement_identity.dev());
    assert_eq!(after_identity.ino(), replacement_identity.ino());
    assert_eq!(after_identity.permissions().mode() & 0o7777, 0o600);
    assert!(
        !retained_parent.join("swapped.bin").exists(),
        "cleanup did not remove the exact settled inode from the retained old parent"
    );

    fs::rename(&requested_parent, &replacement.0).unwrap();
    fs::rename(&retained_parent, &requested_parent).unwrap();
}

#[test]
fn executable_is_supported_elf_only_and_retained_after_final_rebind() {
    let script = Fixture::new("script-rejected", FakeBehavior::Success, &tag_json());
    fs::set_permissions(&script.executable, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&script.executable, b"#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&script.executable, fs::Permissions::from_mode(0o500)).unwrap();
    let mut config: PublisherBrokerConfigV1 =
        serde_json::from_slice(&fs::read(&script.config).unwrap()).unwrap();
    config.gh_sha256 = sha256(&fs::read(&script.executable).unwrap());
    write_config(&script.config, &config);
    assert!(execute(&script, &read_tag_request()).is_err());
    assert!(!script.snapshot.exists());

    struct ReplaceAfterFinalRebind {
        path: PathBuf,
        replacement: PathBuf,
    }
    impl BrokerTestCheckpoints for ReplaceAfterFinalRebind {
        fn after_final_rebind(&mut self) {
            fs::rename(&self.path, self.path.with_extension("retained")).unwrap();
            fs::rename(&self.replacement, &self.path).unwrap();
        }
    }
    let retained = Fixture::new("after-final-rebind", FakeBehavior::Success, &tag_json());
    let replacement = retained.root.path("named-replacement");
    fs::write(&replacement, b"#!/bin/sh\necho replacement-canary\n").unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o500)).unwrap();
    let mut checkpoint = ReplaceAfterFinalRebind {
        path: retained.executable.clone(),
        replacement,
    };
    let response = broker::execute_with_test_checkpoints(
        &retained.config,
        &read_tag_request(),
        &mut checkpoint,
    )
    .unwrap();
    assert!(matches!(response, BrokerResponseV1::Tag { .. }));
    assert!(
        retained.snapshot.exists(),
        "retained ELF bytes, not named replacement, executed"
    );

    struct ReplaceBeforeSpawn {
        path: PathBuf,
        replacement: PathBuf,
    }
    impl BrokerTestCheckpoints for ReplaceBeforeSpawn {
        fn before_spawn(&mut self) {
            fs::rename(&self.path, self.path.with_extension("retained")).unwrap();
            fs::rename(&self.replacement, &self.path).unwrap();
        }
    }
    let rejected = Fixture::new("replace-before-spawn", FakeBehavior::Success, &tag_json());
    let replacement = rejected.root.path("replacement-elf");
    fs::copy(compiled_fake(), &replacement).unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o500)).unwrap();
    let mut checkpoint = ReplaceBeforeSpawn {
        path: rejected.executable.clone(),
        replacement,
    };
    assert!(
        broker::execute_with_test_checkpoints(
            &rejected.config,
            &read_tag_request(),
            &mut checkpoint
        )
        .is_err()
    );
    assert!(!rejected.snapshot.exists());
}

#[test]
fn config_executable_and_directory_identity_hash_mode_and_links_fail_closed() {
    let wrong_hash = Fixture::new("wrong-hash", FakeBehavior::Success, &tag_json());
    let mut config: PublisherBrokerConfigV1 =
        serde_json::from_slice(&fs::read(&wrong_hash.config).unwrap()).unwrap();
    config.gh_sha256 = "00".repeat(32);
    write_config(&wrong_hash.config, &config);
    assert!(execute(&wrong_hash, &read_tag_request()).is_err());

    let config_mode = Fixture::new("config-mode", FakeBehavior::Success, &tag_json());
    fs::set_permissions(&config_mode.config, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(execute(&config_mode, &read_tag_request()).is_err());

    let exec_mode = Fixture::new("exec-mode", FakeBehavior::Success, &tag_json());
    fs::set_permissions(&exec_mode.executable, fs::Permissions::from_mode(0o520)).unwrap();
    assert!(execute(&exec_mode, &read_tag_request()).is_err());

    let dir_mode = Fixture::new("dir-mode", FakeBehavior::Success, &tag_json());
    fs::set_permissions(&dir_mode.config_dir, fs::Permissions::from_mode(0o750)).unwrap();
    assert!(execute(&dir_mode, &read_tag_request()).is_err());

    let linked_exec = Fixture::new("exec-hardlink", FakeBehavior::Success, &tag_json());
    fs::hard_link(&linked_exec.executable, linked_exec.root.path("other-link")).unwrap();
    assert!(execute(&linked_exec, &read_tag_request()).is_err());

    let linked_config = Fixture::new("config-symlink", FakeBehavior::Success, &tag_json());
    let link = linked_config.root.path("config-link");
    symlink(&linked_config.config, &link).unwrap();
    struct Noop;
    impl BrokerTestCheckpoints for Noop {}
    assert!(broker::execute_with_test_checkpoints(&link, &read_tag_request(), &mut Noop).is_err());
}

#[test]
fn invalid_requests_are_rejected_before_config_or_process_authority() {
    let fixture = Fixture::new("invalid-before-config", FakeBehavior::Success, &tag_json());
    fs::remove_file(&fixture.config).unwrap();
    let invalid = BrokerRequestV1::ReadTag {
        schema_version: 1,
        repository: "owner/name;--hostname=evil".to_owned(),
        tag: TAG.to_owned(),
    };
    assert!(execute(&fixture, &invalid).is_err());
    assert!(!fixture.snapshot.exists());
    for denied in [
        "auth",
        "graphql",
        "--jq",
        "--template",
        "--hostname",
        "http://evil",
        "Authorization: token",
    ] {
        let bytes =
            format!("{{\"kind\":\"{denied}\",\"repository\":\"owner/name\",\"schema_version\":1}}");
        assert!(BrokerRequestV1::from_canonical_bytes(bytes.as_bytes()).is_err());
    }
}

#[test]
fn repeated_and_concurrent_requests_receive_distinct_fresh_homes() {
    let workers = (0..4)
        .map(|index| {
            thread::spawn(move || {
                let fixture = Fixture::new(
                    &format!("concurrent-{index}"),
                    FakeBehavior::Success,
                    &tag_json(),
                );
                execute(&fixture, &read_tag_request()).unwrap();
                fixture
                    .snapshot_section("ENV_BEGIN\n", "\nENV_END")
                    .lines()
                    .find_map(|line| line.strip_prefix("HOME="))
                    .unwrap()
                    .to_owned()
            })
        })
        .collect::<Vec<_>>();
    let homes = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(homes.len(), 4);
    assert!(homes.iter().all(|home| !Path::new(home).exists()));
}

fn run_binary(config: &Path, request: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_catalog-gh-broker"))
        .args(["--config", config.to_str().unwrap()])
        .env("GH_TOKEN", "ambient-gh-token-canary")
        .env("GITHUB_TOKEN", "ambient-github-token-canary")
        .env("HTTPS_PROXY", "ambient-proxy-canary")
        .env("SSH_AUTH_SOCK", "ambient-agent-canary")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(request).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn binary_uses_fake_elf_only_exact_cli_environment_and_fixed_redaction() {
    let fixture = Fixture::new("binary", FakeBehavior::Success, &tag_json());
    let request = read_tag_request().to_canonical_bytes().unwrap();
    let output = run_binary(&fixture.config, &request);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(
        BrokerResponseV1::from_canonical_bytes(&output.stdout).unwrap(),
        BrokerResponseV1::Tag {
            schema_version: 1,
            tag: TAG.to_owned(),
            commit_sha: COMMIT.to_owned(),
            object_type: BrokerTagObjectTypeV1::Commit
        }
    );
    let environment = fixture.snapshot_section("ENV_BEGIN\n", "\nENV_END");
    for denied in [
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "HTTPS_PROXY",
        "SSH_AUTH_SOCK",
        "ambient-gh-token-canary",
        "ambient-github-token-canary",
        "ambient-proxy-canary",
        "ambient-agent-canary",
    ] {
        assert!(!environment.contains(denied));
    }

    let failed = Fixture::new("binary-failure", FakeBehavior::Failure, b"raw-token-canary");
    let output = run_binary(&failed.config, &request);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"github broker failed\n");
    assert!(!String::from_utf8_lossy(&output.stderr).contains("raw-token-canary"));

    let output = Command::new(env!("CARGO_BIN_EXE_catalog-gh-broker"))
        .args(["--config", fixture.config.to_str().unwrap(), "extra"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"github broker failed\n");
    assert_eq!(
        BrokerPublicationStatusV1::Published,
        BrokerPublicationStatusV1::Published
    );
}
