//! kekkai (結界): sandbox child processes on Linux.
//!
//! kekkai applies a filesystem allowlist (Landlock), a syscall and network
//! gate (seccomp) and resource limits to a [`std::process::Command`] before it
//! spawns. [`Backend::Userspace`] (cargo feature `guest`) launches a helper
//! that owns spawn instead.
//!
//! Public enums and [`Settings`] are `#[non_exhaustive]`. Construct settings
//! with [`Settings::builder`] so adding a field later is not a breaking change.
//! A change to what the sandbox allows or denies is a versioned change, never
//! a patch-level surprise.
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use std::process::Command;
//! use kekkai::{Backend, Sandbox, Settings};
//!
//! let settings = Settings::builder()
//!     .backend(Backend::LinuxNative)
//!     .build();
//! let sandbox = Sandbox::prepare(&settings, "/path/to/workspace")?;
//! let mut cmd = Command::new("python3");
//! sandbox.apply(&mut cmd)?;
//! let _status = cmd.status()?;
//! # Ok(())
//! # }
//! ```
#![deny(missing_docs)]

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

#[cfg(target_os = "linux")]
use std::sync::{Arc, Mutex};

mod capture;
#[cfg(target_os = "linux")]
mod cgroup;
mod guest;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod notif;
#[cfg(target_os = "linux")]
mod ns;
#[cfg(target_os = "linux")]
mod proxy;
mod report;
#[cfg(target_os = "linux")]
mod syscalls;
#[cfg(target_os = "linux")]
mod view;

pub use capture::StreamCapture;
pub use report::{RunReport, RunTiming, SCHEMA_VERSION, SettingsSummary};

/// Isolation backend for spawned child processes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Backend {
    /// No isolation (development only).
    #[default]
    None,
    /// Unix resource limits and a process group, no filesystem or network rules.
    Rlimit,
    /// Landlock filesystem rules plus a seccomp socket gate, applied in `pre_exec`.
    LinuxNative,
    /// Userspace helper owns spawn. No guest kernel image. Requires the
    /// `guest` cargo feature and a helper (`Settings::guest_helper`,
    /// `KEKKAI_GUEST_HELPER`, or `kekkai-guest` on `PATH`).
    Userspace,
}

impl fmt::Display for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Backend::None => "none",
            Backend::Rlimit => "rlimit",
            Backend::LinuxNative => "linux_native",
            Backend::Userspace => "userspace",
        })
    }
}

/// Whether the child may create network sockets.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Network {
    /// `socket()` fails with `EPERM`. This is the default.
    #[default]
    Deny,
    /// Socket creation is left to the host. Filesystem rules still apply.
    Allow,
    /// Only `AF_UNIX` sockets. The parent runs a CONNECT proxy on a unix
    /// socket in scratch and injects `*_PROXY` environment variables.
    /// Direct IP sockets fail. Requires Landlock ABI 6.
    Allowlist(Vec<AllowHost>),
    /// Private network namespace with only loopback up. Requires
    /// [`Namespaces::Isolate`]. Host routes and host abstract unix sockets
    /// are gone. Loopback works. Missing netns support is [`Error::Unavailable`].
    Loopback,
}

/// One host (and optional port) permitted through [`Network::Allowlist`].
///
/// Matching is by the CONNECT target string, not by DNS. A raw IP does not
/// match a hostname entry.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AllowHost {
    /// Hostname or literal address as it appears in CONNECT.
    pub host: String,
    /// When set, only this port matches.
    pub port: Option<u16>,
}

/// Kind of recorded sandbox denial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ViolationKind {
    /// The egress proxy refused a CONNECT target.
    Network,
    /// A Landlock filesystem denial (path in `detail`). Recorded only when
    /// the host can observe those events.
    Filesystem,
    /// A seccomp-denied syscall (name in `detail`).
    Syscall,
}

/// One denial class observed for a child.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct SandboxViolation {
    /// Class of denial.
    pub kind: ViolationKind,
    /// Host:port for network denials, path for filesystem, syscall name otherwise.
    pub detail: String,
    /// Times this denial was observed.
    pub count: u64,
}

/// Opt-in cgroup v2 limits. Empty means do not use a cgroup.
///
/// Requesting any field without a delegated cgroup v2 subtree is an error;
/// kekkai never falls back to `RLIMIT_AS`. A missing controller (`io`,
/// `cpu`, `memory`, `pids`) is [`Error::Unavailable`].
///
/// This struct is exhaustive: adding a field is a 0.x minor change for
/// struct literals. Fill unknowns with `..CgroupLimits::default()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CgroupLimits {
    /// Hard memory cap in bytes (`memory.max`).
    pub memory_max: Option<u64>,
    /// Optional throttle threshold in bytes (`memory.high`).
    pub memory_high: Option<u64>,
    /// Maximum number of pids (`pids.max`).
    pub pids_max: Option<u64>,
    /// CPU quota in microseconds per period (`cpu.max`).
    pub cpu_quota_us: Option<u64>,
    /// Period for `cpu.max` in microseconds. Defaults to 100000 when quota is set.
    pub cpu_period_us: Option<u64>,
    /// Relative CPU weight (`cpu.weight`). Range 1..=10000.
    pub cpu_weight: Option<u64>,
    /// Per-device IO cap (`io.max`).
    pub io_max: Option<IoMax>,
}

/// Per-device cgroup v2 `io.max` cap (`major:minor rbps= wbps= riops= wiops=`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IoMax {
    /// Block device major number.
    pub major: u32,
    /// Block device minor number.
    pub minor: u32,
    /// Read bytes per second. `None` leaves that dimension uncapped.
    pub rbps: Option<u64>,
    /// Write bytes per second.
    pub wbps: Option<u64>,
    /// Read IOPS.
    pub riops: Option<u64>,
    /// Write IOPS.
    pub wiops: Option<u64>,
}

impl IoMax {
    /// True when no byte or IOPS cap is set.
    pub fn is_empty(&self) -> bool {
        self.rbps.is_none() && self.wbps.is_none() && self.riops.is_none() && self.wiops.is_none()
    }
}

impl CgroupLimits {
    /// True when no cgroup controllers are requested.
    pub fn is_empty(&self) -> bool {
        self.memory_max.is_none()
            && self.memory_high.is_none()
            && self.pids_max.is_none()
            && self.cpu_quota_us.is_none()
            && self.cpu_period_us.is_none()
            && self.cpu_weight.is_none()
            && self.io_max.is_none()
    }
}

/// Usage collected from a child's cgroup.
///
/// [`Sandbox::usage`] may be called while the child is still running.
/// [`Sandbox::finish`] is the post-exit report and includes violations.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
#[serde(default)]
pub struct ChildUsage {
    /// `memory.events` `oom_kill` was non-zero.
    pub oom_killed: bool,
    /// Peak memory in bytes (`memory.peak`), if the controller reported it.
    pub memory_peak_bytes: Option<u64>,
    /// Current memory in bytes (`memory.current`).
    pub memory_current_bytes: Option<u64>,
    /// CPU time in microseconds (`cpu.stat` `usage_usec`).
    pub cpu_usec: Option<u64>,
    /// Current pids (`pids.current`).
    pub pids_current: Option<u64>,
    /// Bytes read (`io.stat` `rbytes` summed across devices).
    pub io_rbytes: Option<u64>,
    /// Bytes written (`io.stat` `wbytes` summed across devices).
    pub io_wbytes: Option<u64>,
    /// True when [`Sandbox::spawn_with_deadline`] expired the wall-clock limit.
    pub timed_out: bool,
    /// Denials recorded for this child (seccomp user notification and proxy).
    pub violations: Vec<SandboxViolation>,
    /// True when kernel syscall denials could be observed. When false, an
    /// empty `violations` list is not a clean kernel run; parent-side proxy
    /// denials may still appear. Filesystem denials are unavailable without
    /// a privileged audit stream (`health` reports `fs_violations=unavailable`).
    pub violations_observed: bool,
}

/// Which end of a captured stream to keep when it exceeds the cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum CaptureKeep {
    /// First `max` bytes.
    #[default]
    Head,
    /// Last `max` bytes.
    Tail,
    /// First and last halves of `max` bytes; the middle is dropped.
    HeadAndTail,
}

/// Per-stream byte caps for [`Sandbox::spawn_with_deadline_captured`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CaptureLimits {
    /// Maximum kept stdout bytes. `None` leaves stdout to the caller.
    pub stdout_max: Option<usize>,
    /// Maximum kept stderr bytes. `None` leaves stderr to the caller.
    pub stderr_max: Option<usize>,
    /// Head, tail, or both when a stream exceeds its cap.
    pub keep: CaptureKeep,
}

/// Process namespace mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Namespaces {
    /// Share the host namespaces. This is the default.
    #[default]
    Off,
    /// Fresh user, mount, PID, IPC, and UTS namespaces with a private `/proc`.
    ///
    /// Requires unprivileged user namespaces. Selection is an error when the
    /// host cannot create them; there is no silent fallback.
    Isolate,
}

/// Mount-namespace filesystem view. Requires [`Namespaces::Isolate`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum FilesystemView {
    /// Host tree, filtered by Landlock only. This is the default.
    #[default]
    Host,
    /// Read-only binds for inputs, tmpfs scratch, overlay on the output
    /// tree, then a new root so paths outside the view are gone.
    Isolate {
        /// Whether overlay writes persist on the host.
        overlay: OverlayPersist,
    },
}

/// Where overlay upperdir lives for [`FilesystemView::Isolate`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum OverlayPersist {
    /// Upperdir is tmpfs. Writes vanish with the mount namespace.
    #[default]
    Discard,
    /// Upperdir is this host directory (`upper/` and `work/` are created).
    /// Writes survive the child.
    Keep(PathBuf),
}

/// Unix resource limits applied in the child before exec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Limits {
    /// CPU seconds (`RLIMIT_CPU`).
    pub cpu_time_secs: Option<u64>,
    /// Address-space limit in MiB (`RLIMIT_AS`).
    pub memory_mb: Option<u64>,
    /// Per-real-user process ceiling (`RLIMIT_NPROC`).
    pub user_processes: Option<u64>,
    /// Maximum file size in MiB (`RLIMIT_FSIZE`).
    pub file_size_mb: Option<u64>,
    /// Maximum number of open file descriptors (`RLIMIT_NOFILE`).
    pub open_files: Option<u64>,
}

/// Settings for [`Sandbox::prepare`].
///
/// Construct with [`Settings::builder`]. Adding a field is not a breaking
/// change for that path.
///
/// ```
/// use kekkai::{Backend, Settings};
/// let settings = Settings::builder().backend(Backend::None).build();
/// assert_eq!(settings.backend, Backend::None);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Settings {
    /// Isolation backend. Selecting one the host cannot provide is an error.
    pub backend: Backend,
    /// Resource limits applied by `rlimit` and `linux_native`.
    pub limits: Limits,
    /// Read-only input paths under `linux_native`. Writes are denied.
    ///
    /// An input that is the same as, or lives under, a writable role (output,
    /// the workspace when it is the output, extra [`Self::writable_roots`],
    /// or scratch) is [`Error::Invalid`].
    pub inputs: Vec<PathBuf>,
    /// Writable output directory under `linux_native`. `None` uses the
    /// workspace root passed to [`Sandbox::prepare`].
    pub output: Option<PathBuf>,
    /// Extra absolute paths granted read and execute under `linux_native`.
    pub readable_roots: Vec<PathBuf>,
    /// Extra absolute paths granted read and write under `linux_native`.
    /// Scratch is always writable. The workspace root is writable when
    /// [`Self::output`] is `None` or names that same path.
    pub writable_roots: Vec<PathBuf>,
    /// Extra character or block devices granted under `linux_native`.
    /// Empty (the default) grants only the built-in nodes (`/dev/null`,
    /// `/dev/zero`, `/dev/urandom`, `/dev/random`). Paths must exist and
    /// be device nodes at prepare. Landlock mediates open and, on ABI 5+,
    /// device ioctl.
    pub devices: Vec<PathBuf>,
    /// Socket and network-namespace policy. `Deny`, `Allow`, and `Allowlist`
    /// apply under `linux_native`. `Loopback` also requires isolate namespaces
    /// on `rlimit` or `linux_native`.
    pub network: Network,
    /// Opt-in cgroup v2 limits. Requires `rlimit` or `linux_native`.
    pub cgroup: CgroupLimits,
    /// Delegated cgroup v2 directory. `None` probes the current cgroup.
    pub cgroup_root: Option<PathBuf>,
    /// Opt-in process namespaces. Requires `rlimit` or `linux_native`.
    pub namespaces: Namespaces,
    /// Isolated filesystem view. Requires [`Namespaces::Isolate`].
    pub filesystem_view: FilesystemView,
    /// Seccomp syscall profile under `linux_native`.
    ///
    /// [`SyscallProfile::Default`] is the historical denylist. `Strict` and
    /// `Python` are per-architecture allowlists and require
    /// [`Backend::LinuxNative`].
    pub syscall_profile: SyscallProfile,
    /// Helper binary for [`Backend::Userspace`]. `None` uses
    /// `KEKKAI_GUEST_HELPER` or `kekkai-guest` on `PATH`.
    pub guest_helper: Option<PathBuf>,
}

impl Settings {
    /// Start a builder. Adding a field to [`Settings`] does not break this.
    pub fn builder() -> SettingsBuilder {
        SettingsBuilder::default()
    }
}

/// Builder for [`Settings`].
#[derive(Debug, Clone, Default)]
pub struct SettingsBuilder {
    inner: Settings,
}

impl SettingsBuilder {
    /// Isolation backend.
    pub fn backend(mut self, backend: Backend) -> Self {
        self.inner.backend = backend;
        self
    }

    /// Resource limits.
    pub fn limits(mut self, limits: Limits) -> Self {
        self.inner.limits = limits;
        self
    }

    /// Read-only input paths.
    pub fn inputs(mut self, inputs: Vec<PathBuf>) -> Self {
        self.inner.inputs = inputs;
        self
    }

    /// Writable output directory.
    pub fn output(mut self, output: Option<PathBuf>) -> Self {
        self.inner.output = output;
        self
    }

    /// Extra read-and-execute paths.
    pub fn readable_roots(mut self, readable_roots: Vec<PathBuf>) -> Self {
        self.inner.readable_roots = readable_roots;
        self
    }

    /// Extra read-and-write paths.
    pub fn writable_roots(mut self, writable_roots: Vec<PathBuf>) -> Self {
        self.inner.writable_roots = writable_roots;
        self
    }

    /// Extra character or block devices.
    pub fn devices(mut self, devices: Vec<PathBuf>) -> Self {
        self.inner.devices = devices;
        self
    }

    /// Socket creation policy.
    pub fn network(mut self, network: Network) -> Self {
        self.inner.network = network;
        self
    }

    /// Opt-in cgroup v2 limits.
    pub fn cgroup(mut self, cgroup: CgroupLimits) -> Self {
        self.inner.cgroup = cgroup;
        self
    }

    /// Delegated cgroup v2 directory.
    pub fn cgroup_root(mut self, cgroup_root: Option<PathBuf>) -> Self {
        self.inner.cgroup_root = cgroup_root;
        self
    }

    /// Opt-in process namespaces.
    pub fn namespaces(mut self, namespaces: Namespaces) -> Self {
        self.inner.namespaces = namespaces;
        self
    }

    /// Isolated filesystem view.
    pub fn filesystem_view(mut self, filesystem_view: FilesystemView) -> Self {
        self.inner.filesystem_view = filesystem_view;
        self
    }

    /// Seccomp syscall profile.
    pub fn syscall_profile(mut self, syscall_profile: SyscallProfile) -> Self {
        self.inner.syscall_profile = syscall_profile;
        self
    }

    /// Helper binary for [`Backend::Userspace`].
    pub fn guest_helper(mut self, guest_helper: Option<PathBuf>) -> Self {
        self.inner.guest_helper = guest_helper;
        self
    }

    /// Finish the builder.
    pub fn build(self) -> Settings {
        self.inner
    }
}

/// Health of a configured backend on the current host.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Health {
    /// Prepare can proceed.
    Ok(String),
    /// Prepare can proceed with a warning (`none` always warns).
    Warning(String),
    /// Prepare will fail with [`Error::Unsupported`] or [`Error::Unavailable`].
    Error(String),
}

/// Host kernel capabilities that affect backend selection.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Capabilities {
    /// Unix resource limits can be applied in `pre_exec`.
    pub rlimit: bool,
    /// Landlock ABI if the kernel probe succeeded.
    pub landlock_abi: Option<u32>,
    /// The host is Linux, where seccomp-BPF can be installed in `pre_exec`.
    pub seccomp: bool,
    /// A writable cgroup v2 subtree is available for per-child limits.
    pub cgroup: bool,
    /// Seccomp user notification can record denied syscalls in the parent.
    pub seccomp_user_notif: bool,
    /// Unprivileged user namespaces can be created for isolate mode.
    pub user_namespaces: bool,
    /// Overlayfs, tmpfs, and pivot_root work inside isolate namespaces.
    pub filesystem_view: bool,
    /// A private network namespace with loopback can be created.
    pub network_namespace: bool,
}

/// Seccomp syscall profile under `linux_native`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum SyscallProfile {
    /// Historical denylist: `ptrace`, `io_uring`, identity-change, and
    /// namespace-escape syscalls fail; everything else is allowed. This is
    /// the default.
    #[default]
    Default,
    /// Small allowlist for a simple child (`true`, file copy).
    Strict,
    /// Allowlist sized for CPython and in-process analytics.
    Python,
}

/// Failure to prepare or apply a sandbox.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The backend is not implemented on this operating system.
    Unsupported {
        /// Backend that is not implemented here.
        backend: Backend,
        /// Human-readable reason.
        message: String,
    },
    /// The backend is implemented but the host cannot enforce it.
    Unavailable {
        /// Backend the host cannot enforce.
        backend: Backend,
        /// Human-readable reason.
        message: String,
    },
    /// Settings or paths cannot be used.
    Invalid {
        /// Human-readable reason.
        message: String,
    },
}

impl Error {
    pub(crate) fn unsupported(backend: Backend, message: impl Into<String>) -> Self {
        Self::Unsupported {
            backend,
            message: message.into(),
        }
    }

    pub(crate) fn unavailable(backend: Backend, message: impl Into<String>) -> Self {
        Self::Unavailable {
            backend,
            message: message.into(),
        }
    }

    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid {
            message: message.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported { backend, message } => {
                write!(f, "sandbox backend `{backend}` is unsupported: {message}")
            }
            Self::Unavailable { backend, message } => {
                write!(f, "sandbox backend `{backend}` is unavailable: {message}")
            }
            Self::Invalid { message } => {
                write!(f, "sandbox configuration: {message}")
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<Error> for io::Error {
    fn from(error: Error) -> Self {
        io::Error::other(error)
    }
}

/// Probe which backends this process can enforce.
pub fn capabilities() -> Capabilities {
    #[cfg(unix)]
    let rlimit = true;
    #[cfg(not(unix))]
    let rlimit = false;

    #[cfg(target_os = "linux")]
    let landlock_abi = linux::probe_abi().ok();
    #[cfg(not(target_os = "linux"))]
    let landlock_abi = None;

    #[cfg(target_os = "linux")]
    let cgroup = cgroup::probe(None).is_ok();
    #[cfg(not(target_os = "linux"))]
    let cgroup = false;

    #[cfg(target_os = "linux")]
    let seccomp_user_notif = notif::probe_user_notif();
    #[cfg(not(target_os = "linux"))]
    let seccomp_user_notif = false;

    #[cfg(target_os = "linux")]
    let user_namespaces = ns::probe().is_ok();
    #[cfg(not(target_os = "linux"))]
    let user_namespaces = false;

    #[cfg(target_os = "linux")]
    let filesystem_view = view::probe().is_ok();
    #[cfg(not(target_os = "linux"))]
    let filesystem_view = false;

    #[cfg(target_os = "linux")]
    let network_namespace = ns::probe_loopback().is_ok();
    #[cfg(not(target_os = "linux"))]
    let network_namespace = false;

    Capabilities {
        rlimit,
        landlock_abi,
        seccomp: cfg!(target_os = "linux"),
        cgroup,
        seccomp_user_notif,
        user_namespaces,
        filesystem_view,
        network_namespace,
    }
}

/// Probe the configured backend without constructing a run-scoped ruleset.
pub fn health(settings: &Settings) -> Health {
    let backend = match settings.backend {
        Backend::None => {
            Health::Warning("sandbox:   backend=none — no OS isolation for child processes".into())
        }
        Backend::Rlimit => {
            if cfg!(unix) {
                Health::Ok(format!(
                    "sandbox:   backend=rlimit cpu={:?} memory_mb={:?} user_processes={:?} (no filesystem or network rules)",
                    settings.limits.cpu_time_secs,
                    settings.limits.memory_mb,
                    settings.limits.user_processes
                ))
            } else {
                Health::Error("sandbox backend rlimit is supported only on Unix".into())
            }
        }
        Backend::LinuxNative => linux_native_health(settings),
        Backend::Userspace => userspace_health(settings),
    };
    let with_cgroup = match (&backend, cgroup_health(settings)) {
        (_, Some(Health::Error(message))) => Health::Error(message),
        (Health::Error(_), _) => backend,
        (Health::Ok(base), Some(Health::Ok(extra))) => Health::Ok(format!("{base}; {extra}")),
        (Health::Warning(base), Some(Health::Ok(extra))) => {
            Health::Warning(format!("{base}; {extra}"))
        }
        _ => backend,
    };
    let with_ns = match (&with_cgroup, namespace_health(settings)) {
        (_, Some(Health::Error(message))) => Health::Error(message),
        (Health::Error(_), _) => with_cgroup,
        (Health::Ok(base), Some(Health::Ok(extra))) => Health::Ok(format!("{base}; {extra}")),
        (Health::Warning(base), Some(Health::Ok(extra))) => {
            Health::Warning(format!("{base}; {extra}"))
        }
        _ => with_cgroup,
    };
    let with_view = match (&with_ns, view_health(settings)) {
        (_, Some(Health::Error(message))) => Health::Error(message),
        (Health::Error(_), _) => with_ns,
        (Health::Ok(base), Some(Health::Ok(extra))) => Health::Ok(format!("{base}; {extra}")),
        (Health::Warning(base), Some(Health::Ok(extra))) => {
            Health::Warning(format!("{base}; {extra}"))
        }
        _ => with_ns,
    };
    match (&with_view, loopback_health(settings)) {
        (_, Some(Health::Error(message))) => Health::Error(message),
        (Health::Error(_), _) => with_view,
        (Health::Ok(base), Some(Health::Ok(extra))) => Health::Ok(format!("{base}; {extra}")),
        (Health::Warning(base), Some(Health::Ok(extra))) => {
            Health::Warning(format!("{base}; {extra}"))
        }
        _ => with_view,
    }
}

fn namespace_health(settings: &Settings) -> Option<Health> {
    if matches!(settings.namespaces, Namespaces::Off) {
        return None;
    }
    if matches!(settings.backend, Backend::None) {
        return Some(Health::Error(
            "namespace isolate requires backend rlimit or linux_native".into(),
        ));
    }
    #[cfg(target_os = "linux")]
    {
        Some(match ns::probe() {
            Ok(()) => Health::Ok("namespaces=isolate pid+mount+ipc+uts".into()),
            Err(error) => Health::Error(error.to_string()),
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        Some(Health::Error(
            "namespace isolate is supported only on Linux".into(),
        ))
    }
}

fn view_health(settings: &Settings) -> Option<Health> {
    if matches!(settings.filesystem_view, FilesystemView::Host) {
        return None;
    }
    if matches!(settings.namespaces, Namespaces::Off) {
        return Some(Health::Error(
            "filesystem view requires namespace isolate".into(),
        ));
    }
    if matches!(settings.backend, Backend::None) {
        return Some(Health::Error(
            "filesystem view requires backend rlimit or linux_native".into(),
        ));
    }
    #[cfg(target_os = "linux")]
    {
        Some(match view::probe() {
            Ok(()) => {
                let overlay = match &settings.filesystem_view {
                    FilesystemView::Isolate { overlay } => match overlay {
                        OverlayPersist::Discard => "discard",
                        OverlayPersist::Keep(_) => "keep",
                    },
                    FilesystemView::Host => "host",
                };
                Health::Ok(format!("view=isolate overlay={overlay} ro-bind tmpfs"))
            }
            Err(error) => Health::Error(error.to_string()),
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        Some(Health::Error(
            "filesystem view is supported only on Linux".into(),
        ))
    }
}

fn loopback_health(settings: &Settings) -> Option<Health> {
    if !matches!(settings.network, Network::Loopback) {
        return None;
    }
    if matches!(settings.namespaces, Namespaces::Off) {
        return Some(Health::Error(
            "Network::Loopback requires namespace isolate".into(),
        ));
    }
    if matches!(settings.backend, Backend::None) {
        return Some(Health::Error(
            "Network::Loopback requires backend rlimit or linux_native".into(),
        ));
    }
    #[cfg(target_os = "linux")]
    {
        Some(match ns::probe_loopback() {
            Ok(()) => Health::Ok("netns=loopback".into()),
            Err(error) => Health::Error(error.to_string()),
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        Some(Health::Error(
            "Network::Loopback is supported only on Linux".into(),
        ))
    }
}

fn cgroup_health(settings: &Settings) -> Option<Health> {
    if settings.cgroup.is_empty() {
        return None;
    }
    if matches!(settings.backend, Backend::None) {
        return Some(Health::Error(
            "cgroup limits require backend rlimit or linux_native".into(),
        ));
    }
    #[cfg(target_os = "linux")]
    {
        Some(
            match cgroup::probe_with(
                settings.backend,
                settings.cgroup_root.as_deref(),
                &settings.cgroup,
            ) {
                Ok(path) => Health::Ok(format!(
                    "cgroup=v2 root={} memory_max={:?} pids_max={:?} cpu_quota_us={:?} cpu_weight={:?} io_max={}",
                    path.display(),
                    settings.cgroup.memory_max,
                    settings.cgroup.pids_max,
                    settings.cgroup.cpu_quota_us,
                    settings.cgroup.cpu_weight,
                    match settings.cgroup.io_max {
                        Some(_) => "set",
                        None => "none",
                    }
                )),
                Err(error) => Health::Error(error.to_string()),
            },
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        Some(Health::Error(
            "cgroup v2 limits are supported only on Linux".into(),
        ))
    }
}

#[cfg(target_os = "linux")]
fn syscall_profile_label(profile: SyscallProfile) -> &'static str {
    match profile {
        SyscallProfile::Default => "default",
        SyscallProfile::Strict => "strict",
        SyscallProfile::Python => "python",
    }
}

#[cfg(target_os = "linux")]
fn linux_native_health(settings: &Settings) -> Health {
    match linux::probe_enforcement() {
        Ok(abi) => {
            let signal = if abi >= 6 { "landlock" } else { "none" };
            if matches!(settings.network, Network::Allowlist(_)) && abi < 6 {
                return Health::Error(
                    "Network::Allowlist requires Landlock ABI 6 (abstract unix socket scoping)"
                        .into(),
                );
            }
            let network = match &settings.network {
                Network::Deny => "deny".to_string(),
                Network::Allow => "allow".to_string(),
                Network::Allowlist(hosts) => {
                    format!("allowlist={hosts_len}", hosts_len = hosts.len())
                }
                Network::Loopback => "loopback".to_string(),
            };
            let violations = if notif::probe_user_notif() {
                "user_notif"
            } else {
                "unavailable"
            };
            Health::Ok(format!(
                "sandbox:   backend=linux_native abi={abi} network={network} syscalls={} signal_scoping={signal} writable=output+scratch+{} inputs={} readable={} devices={} cpu={:?} memory_mb={:?} user_processes={:?} violations={violations} fs_violations=unavailable",
                syscall_profile_label(settings.syscall_profile),
                settings.writable_roots.len(),
                settings.inputs.len(),
                settings.readable_roots.len(),
                settings.devices.len(),
                settings.limits.cpu_time_secs,
                settings.limits.memory_mb,
                settings.limits.user_processes
            ))
        }
        Err(error) => Health::Error(error.to_string()),
    }
}

#[cfg(not(target_os = "linux"))]
fn linux_native_health(_settings: &Settings) -> Health {
    Health::Error("sandbox backend linux_native is supported only on Linux".into())
}

fn userspace_health(settings: &Settings) -> Health {
    #[cfg(not(feature = "guest"))]
    {
        let _ = settings;
        Health::Error("sandbox backend userspace requires cargo feature guest".into())
    }
    #[cfg(feature = "guest")]
    {
        if !cfg!(target_os = "linux") {
            return Health::Error("sandbox backend userspace is supported only on Linux".into());
        }
        match guest::resolve_helper(settings) {
            Err(message) => Health::Error(message),
            Ok(path) => match linux_native_health(settings) {
                Health::Error(message) => Health::Error(message),
                Health::Ok(_) | Health::Warning(_) => Health::Ok(format!(
                    "sandbox:   backend=userspace helper={}",
                    path.display()
                )),
            },
        }
    }
}

/// Prepared sandbox, applied to a [`Command`] before spawn.
#[derive(Debug)]
pub struct Sandbox {
    settings: Settings,
    root: PathBuf,
    guest_helper: Option<PathBuf>,
    prepared_at: Instant,
    prepare_ms: u64,
    apply_ms: AtomicU64,
    #[cfg(target_os = "linux")]
    linux: Option<Arc<linux::LinuxPrepared>>,
    #[cfg(target_os = "linux")]
    cgroup: Option<Arc<cgroup::CgroupPrepared>>,
    #[cfg(target_os = "linux")]
    proxy: Option<Arc<proxy::EgressProxy>>,
    #[cfg(target_os = "linux")]
    notif: Mutex<Vec<Arc<notif::ViolationCollector>>>,
    #[cfg(target_os = "linux")]
    view: Option<Arc<view::ViewPlan>>,
}

impl Sandbox {
    /// Validate settings, probe the host, and build any kernel ruleset.
    ///
    /// `root` is the workspace directory. Under `linux_native` it is the
    /// writable output when [`Settings::output`] is `None`. Path roles come
    /// from [`Settings`].
    pub fn prepare(settings: &Settings, root: impl AsRef<Path>) -> Result<Self, Error> {
        #[cfg(feature = "tracing")]
        {
            tracing::info_span!("kekkai.prepare", backend = %settings.backend)
                .in_scope(|| Self::prepare_inner(settings, root))
        }
        #[cfg(not(feature = "tracing"))]
        Self::prepare_inner(settings, root)
    }

    fn prepare_inner(settings: &Settings, root: impl AsRef<Path>) -> Result<Self, Error> {
        let started = Instant::now();
        let root = root.as_ref();
        validate(settings)?;
        check_path_roles(settings, root)?;
        match health(settings) {
            Health::Error(message) => return Err(error_from_health(settings.backend, message)),
            Health::Ok(_) | Health::Warning(_) => {}
        }
        #[cfg(target_os = "linux")]
        let linux = if matches!(settings.backend, Backend::LinuxNative) {
            Some(linux::prepare(
                root,
                &settings.inputs,
                settings.output.as_deref(),
                &settings.readable_roots,
                &settings.writable_roots,
                &settings.devices,
            )?)
        } else {
            None
        };
        #[cfg(target_os = "linux")]
        let cgroup = if settings.cgroup.is_empty() {
            None
        } else {
            Some(Arc::new(cgroup::prepare(
                settings.backend,
                &settings.cgroup,
                settings.cgroup_root.as_deref(),
            )?))
        };
        #[cfg(target_os = "linux")]
        let proxy = match (&settings.network, &linux) {
            (Network::Allowlist(hosts), Some(prepared)) => {
                let path = prepared.scratch.join("proxy.sock");
                Some(
                    proxy::EgressProxy::start(path, hosts.clone())
                        .map_err(|error| Error::invalid(format!("egress proxy: {error}")))?,
                )
            }
            _ => None,
        };
        #[cfg(target_os = "linux")]
        let view = match &settings.filesystem_view {
            FilesystemView::Host => None,
            FilesystemView::Isolate { overlay } => {
                let overlay_target = match &settings.output {
                    Some(path) => path.clone(),
                    None => root.to_path_buf(),
                };
                let (scratch, owned_scratch) = match &linux {
                    Some(prepared) => (prepared.scratch.clone(), None),
                    None => {
                        let nanos = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_nanos())
                            .unwrap_or(0);
                        let path = std::env::temp_dir()
                            .join(format!("kekkai-view-{}-{nanos}", std::process::id()));
                        fs::create_dir_all(&path).map_err(|error| {
                            Error::invalid(format!("filesystem view scratch: {error}"))
                        })?;
                        let path = fs::canonicalize(&path).map_err(|error| {
                            Error::invalid(format!("filesystem view scratch: {error}"))
                        })?;
                        (path.clone(), Some(path))
                    }
                };
                Some(Arc::new(view::prepare(
                    &overlay_target,
                    overlay,
                    &scratch,
                    &settings.inputs,
                    &settings.readable_roots,
                    &settings.writable_roots,
                    &settings.devices,
                    owned_scratch,
                )?))
            }
        };
        let guest_helper = if matches!(settings.backend, Backend::Userspace) {
            Some(guest::resolve_helper(settings).map_err(guest::missing_helper_error)?)
        } else {
            None
        };
        let root = if matches!(settings.backend, Backend::Userspace) {
            fs::canonicalize(root).map_err(|error| {
                Error::invalid(format!("workspace `{}`: {error}", root.display()))
            })?
        } else {
            root.to_path_buf()
        };
        Ok(Self {
            settings: settings.clone(),
            root,
            guest_helper,
            prepared_at: started,
            prepare_ms: millis_since(started),
            apply_ms: AtomicU64::new(0),
            #[cfg(target_os = "linux")]
            linux,
            #[cfg(target_os = "linux")]
            cgroup,
            #[cfg(target_os = "linux")]
            proxy,
            #[cfg(target_os = "linux")]
            notif: Mutex::new(Vec::new()),
            #[cfg(target_os = "linux")]
            view,
        })
    }

    /// Install `pre_exec` hooks on a standard library command.
    pub fn apply(&self, command: &mut Command) -> Result<(), Error> {
        #[cfg(feature = "tracing")]
        {
            tracing::info_span!("kekkai.apply", backend = %self.settings.backend)
                .in_scope(|| self.apply_inner(command))
        }
        #[cfg(not(feature = "tracing"))]
        self.apply_inner(command)
    }

    fn apply_inner(&self, command: &mut Command) -> Result<(), Error> {
        let started = Instant::now();
        let result = match self.settings.backend {
            Backend::None => Ok(()),
            Backend::Rlimit => self.apply_rlimit(command),
            Backend::LinuxNative => self.apply_linux_native(command),
            Backend::Userspace => Err(Error::invalid("guest backend owns spawn; apply is invalid")),
        };
        self.apply_ms
            .fetch_add(millis_since(started), Ordering::Relaxed);
        result
    }

    /// Install the same hooks on a `tokio::process::Command`.
    #[cfg(feature = "tokio")]
    pub fn apply_tokio(&self, command: &mut tokio::process::Command) -> Result<(), Error> {
        self.apply(command.as_std_mut())
    }

    /// Host command that starts the child.
    ///
    /// [`Backend::Userspace`] returns the helper invocation; [`Self::apply`]
    /// stays [`Error::Invalid`]. In-process backends return `Command::new(program)`
    /// with [`Self::apply`] already installed.
    pub fn command(&self, program: impl AsRef<std::ffi::OsStr>) -> Result<Command, Error> {
        match self.settings.backend {
            Backend::Userspace => {
                Ok(self.wrap_guest(program, std::iter::empty::<&std::ffi::OsStr>())?)
            }
            Backend::None | Backend::Rlimit | Backend::LinuxNative => {
                let mut command = Command::new(program);
                self.apply(&mut command)?;
                Ok(command)
            }
        }
    }

    /// Spawn `program` with `args`. Guest backends launch the helper.
    pub fn spawn(
        &self,
        program: impl AsRef<std::ffi::OsStr>,
        args: impl IntoIterator<Item = impl AsRef<std::ffi::OsStr>>,
    ) -> Result<std::process::Child, Error> {
        let mut command = self.command(program)?;
        command.args(args);
        command.spawn().map_err(|error| self.spawn_error(error))
    }

    fn wrap_guest(
        &self,
        program: impl AsRef<std::ffi::OsStr>,
        args: impl IntoIterator<Item = impl AsRef<std::ffi::OsStr>>,
    ) -> Result<Command, Error> {
        let helper = self.guest_helper.as_ref().ok_or_else(|| {
            Error::unavailable(Backend::Userspace, "guest helper was not prepared")
        })?;
        Ok(guest::wrap_command(
            helper,
            &self.root,
            &self.settings,
            program,
            args,
        ))
    }

    fn wrap_guest_command(&self, command: &mut Command) -> Result<(), Error> {
        let helper = self.guest_helper.as_ref().ok_or_else(|| {
            Error::unavailable(Backend::Userspace, "guest helper was not prepared")
        })?;
        guest::wrap_into_command(helper, &self.root, &self.settings, command)
    }

    fn prepare_spawn_command(&self, command: &mut Command) -> Result<(), Error> {
        if matches!(self.settings.backend, Backend::Userspace) {
            self.wrap_guest_command(command)
        } else {
            self.apply(command)
        }
    }

    fn spawn_error(&self, error: io::Error) -> Error {
        if matches!(self.settings.backend, Backend::Userspace) {
            Error::unavailable(Backend::Userspace, format!("spawn guest helper: {error}"))
        } else {
            Error::invalid(format!("spawn sandboxed command: {error}"))
        }
    }

    #[cfg(unix)]
    fn apply_rlimit(&self, command: &mut Command) -> Result<(), Error> {
        use std::os::unix::process::CommandExt;

        let limits = rlimit_values(&self.settings);
        let cgroup_fd = self.cgroup_procs_fd();
        let isolate = matches!(self.settings.namespaces, Namespaces::Isolate);
        let loopback = matches!(self.settings.network, Network::Loopback);
        #[cfg(target_os = "linux")]
        let view = self.view.clone();
        // SAFETY: `pre_exec` runs between fork and exec. The closure only
        // performs async-signal-safe libc calls and does not allocate.
        unsafe {
            command.pre_exec(move || {
                if libc::setpgid(0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                join_cgroup(cgroup_fd)?;
                #[cfg(target_os = "linux")]
                if isolate {
                    ns::enter_with_view(view.as_deref(), loopback)?;
                }
                #[cfg(not(target_os = "linux"))]
                let _ = (isolate, loopback);
                apply_rlimit_values(limits)
            });
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn apply_rlimit(&self, _command: &mut Command) -> Result<(), Error> {
        Err(Error::unsupported(
            Backend::Rlimit,
            "rlimit is supported only on Unix",
        ))
    }

    #[cfg(target_os = "linux")]
    fn apply_linux_native(&self, command: &mut Command) -> Result<(), Error> {
        self.apply_linux_native_with(command, true, false)
    }

    #[cfg(target_os = "linux")]
    fn apply_linux_native_with(
        &self,
        command: &mut Command,
        create_process_group: bool,
        pdeathsig: bool,
    ) -> Result<(), Error> {
        let prepared = self
            .linux
            .clone()
            .ok_or_else(|| Error::invalid("linux_native ruleset was not prepared"))?;
        if let Some(proxy) = &self.proxy {
            let path = proxy.path.display().to_string();
            let url = format!("unix://{path}");
            command.env("KEKKAI_PROXY", &path);
            command.env("ALL_PROXY", &url);
            command.env("all_proxy", &url);
            command.env("HTTP_PROXY", &url);
            command.env("HTTPS_PROXY", &url);
            command.env("http_proxy", &url);
            command.env("https_proxy", &url);
            command.env_remove("NO_PROXY");
            command.env_remove("no_proxy");
        }
        let sockets = match &self.settings.network {
            Network::Allow | Network::Loopback => linux::SocketPolicy::Allow,
            Network::Allowlist(_) => linux::SocketPolicy::UnixOnly,
            Network::Deny => linux::SocketPolicy::Deny,
        };
        let mut notif_sock = None;
        if notif::probe_user_notif()
            && let Ok((collector, child_fd)) = notif::ViolationCollector::listen()
        {
            if let Ok(mut list) = self.notif.lock() {
                list.push(collector);
            }
            notif_sock = Some(child_fd);
        }
        linux::apply(
            command,
            rlimit_values(&self.settings),
            sockets,
            self.cgroup_procs_fd(),
            prepared,
            notif_sock,
            matches!(self.settings.namespaces, Namespaces::Isolate),
            self.view.clone(),
            matches!(self.settings.network, Network::Loopback),
            self.settings.syscall_profile,
            create_process_group,
            pdeathsig,
        )
    }

    /// Install linux_native hooks in the helper. The payload stays in the
    /// helper process group so library `kill(-helper)` reaches descendants,
    /// and dies if the helper exits (`PR_SET_PDEATHSIG`).
    #[cfg(feature = "guest")]
    pub(crate) fn apply_helper_payload(&self, command: &mut Command) -> Result<(), Error> {
        #[cfg(target_os = "linux")]
        {
            self.apply_linux_native_with(command, false, true)
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.apply_linux_native(command)
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn apply_linux_native(&self, _command: &mut Command) -> Result<(), Error> {
        Err(Error::unsupported(
            Backend::LinuxNative,
            "linux_native is supported only on Linux",
        ))
    }

    /// Kill the process group created by the sandbox backend.
    ///
    /// Best-effort cleanup for timeout and shutdown. Ignores `ESRCH`.
    pub fn kill_process_group(&self, pid: Option<u32>) {
        self.signal_spawned(pid, sigkill());
    }

    /// Apply hooks, spawn, and enforce a wall-clock deadline.
    ///
    /// At `deadline` the process group receives `SIGTERM`. After `term_grace`
    /// a still-running group is `SIGKILL`ed and the cgroup is killed. The
    /// returned usage has `timed_out` set only when the deadline expired.
    pub fn spawn_with_deadline(
        &self,
        command: &mut Command,
        deadline: std::time::Duration,
        term_grace: std::time::Duration,
    ) -> Result<(std::process::ExitStatus, ChildUsage), Error> {
        self.prepare_spawn_command(command)?;
        let mut child = command.spawn().map_err(|error| self.spawn_error(error))?;
        self.wait_child_deadline(&mut child, deadline, term_grace)
    }

    /// Like [`Self::spawn_with_deadline`], capturing stdout and stderr under byte caps.
    ///
    /// Bytes past the cap are drained so the child does not block on a full pipe.
    /// Kept memory is bounded by the cap (plus a small read buffer).
    pub fn spawn_with_deadline_captured(
        &self,
        command: &mut Command,
        deadline: std::time::Duration,
        term_grace: std::time::Duration,
        capture: CaptureLimits,
    ) -> Result<
        (
            std::process::ExitStatus,
            ChildUsage,
            StreamCapture,
            StreamCapture,
        ),
        Error,
    > {
        self.prepare_spawn_command(command)?;
        self.spawn_captured_applied(command, deadline, term_grace, capture)
    }

    fn spawn_captured_applied(
        &self,
        command: &mut Command,
        deadline: std::time::Duration,
        term_grace: std::time::Duration,
        capture: CaptureLimits,
    ) -> Result<
        (
            std::process::ExitStatus,
            ChildUsage,
            StreamCapture,
            StreamCapture,
        ),
        Error,
    > {
        if capture.stdout_max.is_some() {
            command.stdout(Stdio::piped());
        }
        if capture.stderr_max.is_some() {
            command.stderr(Stdio::piped());
        }
        let mut child = command.spawn().map_err(|error| self.spawn_error(error))?;
        let stdout = capture::spawn_drain(child.stdout.take(), capture.stdout_max, capture.keep);
        let stderr = capture::spawn_drain(child.stderr.take(), capture.stderr_max, capture.keep);
        let (status, usage) = self.wait_child_deadline(&mut child, deadline, term_grace)?;
        Ok((
            status,
            usage,
            capture::join_drain(stdout),
            capture::join_drain(stderr),
        ))
    }

    fn wait_child_deadline(
        &self,
        child: &mut std::process::Child,
        deadline: std::time::Duration,
        term_grace: std::time::Duration,
    ) -> Result<(std::process::ExitStatus, ChildUsage), Error> {
        let pid = child.id();
        let mut guard = DeadlineGuard {
            sandbox: self,
            pid: Some(pid),
            disarm: false,
        };
        let started = std::time::Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    self.reap_userspace_group(Some(pid));
                    guard.disarm = true;
                    return Ok((status, self.usage_after(false)));
                }
                Ok(None) if started.elapsed() >= deadline => {
                    self.signal_spawned(Some(pid), sigterm());
                    let grace_end = std::time::Instant::now() + term_grace;
                    while std::time::Instant::now() < grace_end {
                        if let Ok(Some(_)) = child.try_wait() {
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    self.kill_process_group(Some(pid));
                    self.kill_cgroup();
                    let status = match child.try_wait() {
                        Ok(Some(status)) => status,
                        _ => child.wait().map_err(|error| {
                            Error::invalid(format!("wait sandboxed command: {error}"))
                        })?,
                    };
                    guard.disarm = true;
                    return Ok((status, self.usage_after(true)));
                }
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(10)),
                Err(error) => {
                    return Err(Error::invalid(format!("wait sandboxed command: {error}")));
                }
            }
        }
    }

    /// Same as [`Self::spawn_with_deadline`] for `tokio::process::Command`.
    #[cfg(feature = "tokio")]
    pub async fn spawn_with_deadline_tokio(
        &self,
        command: &mut tokio::process::Command,
        deadline: std::time::Duration,
        term_grace: std::time::Duration,
    ) -> Result<(std::process::ExitStatus, ChildUsage), Error> {
        if matches!(self.settings.backend, Backend::Userspace) {
            self.wrap_guest_command(command.as_std_mut())?;
        } else {
            self.apply_tokio(command)?;
        }
        let mut child = command.spawn().map_err(|error| self.spawn_error(error))?;
        let pid = child.id();
        let mut guard = DeadlineGuard {
            sandbox: self,
            pid,
            disarm: false,
        };
        let started = std::time::Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    self.reap_userspace_group(pid);
                    guard.disarm = true;
                    return Ok((status, self.usage_after(false)));
                }
                Ok(None) if started.elapsed() >= deadline => {
                    self.signal_spawned(pid, sigterm());
                    let grace_end = std::time::Instant::now() + term_grace;
                    while std::time::Instant::now() < grace_end {
                        if let Ok(Some(_)) = child.try_wait() {
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                    self.kill_process_group(pid);
                    self.kill_cgroup();
                    let status = match child.try_wait() {
                        Ok(Some(status)) => status,
                        _ => child.wait().await.map_err(|error| {
                            Error::invalid(format!("wait sandboxed command: {error}"))
                        })?,
                    };
                    guard.disarm = true;
                    return Ok((status, self.usage_after(true)));
                }
                Ok(None) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
                Err(error) => {
                    return Err(Error::invalid(format!("wait sandboxed command: {error}")));
                }
            }
        }
    }

    /// Tokio entry that captures through the std helper after `apply_tokio`.
    ///
    /// Drains and waits on the calling thread (std pipes plus drain threads).
    #[cfg(feature = "tokio")]
    #[allow(clippy::unused_async)]
    pub async fn spawn_with_deadline_captured_tokio(
        &self,
        command: &mut tokio::process::Command,
        deadline: std::time::Duration,
        term_grace: std::time::Duration,
        capture: CaptureLimits,
    ) -> Result<
        (
            std::process::ExitStatus,
            ChildUsage,
            StreamCapture,
            StreamCapture,
        ),
        Error,
    > {
        if matches!(self.settings.backend, Backend::Userspace) {
            self.wrap_guest_command(command.as_std_mut())?;
        } else {
            self.apply_tokio(command)?;
        }
        self.spawn_captured_applied(command.as_std_mut(), deadline, term_grace, capture)
    }

    fn usage_after(&self, timed_out: bool) -> ChildUsage {
        let mut usage = self.finish();
        usage.timed_out = timed_out;
        usage
    }

    fn kill_cgroup(&self) {
        #[cfg(target_os = "linux")]
        if let Some(prepared) = &self.cgroup {
            prepared.kill();
        }
    }

    fn reap_userspace_group(&self, pid: Option<u32>) {
        if matches!(self.settings.backend, Backend::Userspace) {
            self.kill_process_group(pid);
        }
    }

    fn signal_spawned(&self, pid: Option<u32>, sig: i32) {
        #[cfg(unix)]
        if let Some(pid) = pid
            && pid > 1
        {
            let target = if matches!(
                self.settings.backend,
                Backend::Rlimit | Backend::LinuxNative | Backend::Userspace
            ) {
                -(pid as libc::pid_t)
            } else {
                pid as libc::pid_t
            };
            // SAFETY: `pid` came from a child of this process. Negative
            // targets the process group created in `pre_exec`.
            unsafe {
                let _ = libc::kill(target, sig);
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (pid, sig);
        }
    }

    /// Live cgroup snapshot while a child may still be running.
    ///
    /// Empty when no cgroup was prepared. Values come from `memory.current`,
    /// `cpu.stat`, `io.stat`, and `pids.current`.
    pub fn usage(&self) -> ChildUsage {
        #[cfg(target_os = "linux")]
        {
            self.cgroup
                .as_ref()
                .map(|prepared| prepared.usage())
                .unwrap_or_default()
        }
        #[cfg(not(target_os = "linux"))]
        ChildUsage::default()
    }

    /// Build a JSON-serializable run report (settings summary, usage, timing).
    pub fn report(&self) -> RunReport {
        RunReport {
            schema_version: SCHEMA_VERSION,
            settings: SettingsSummary::from_settings(&self.settings),
            usage: self.finish(),
            timing: RunTiming {
                prepare_ms: self.prepare_ms,
                apply_ms: self.apply_ms.load(Ordering::Relaxed),
                since_prepare_ms: millis_since(self.prepared_at),
            },
        }
    }

    /// Read cgroup events after the child exits. Empty when no cgroup was used.
    pub fn finish(&self) -> ChildUsage {
        #[cfg(feature = "tracing")]
        {
            tracing::info_span!("kekkai.finish").in_scope(|| self.finish_inner())
        }
        #[cfg(not(feature = "tracing"))]
        self.finish_inner()
    }

    fn finish_inner(&self) -> ChildUsage {
        #[cfg(target_os = "linux")]
        {
            let mut usage = self
                .cgroup
                .as_ref()
                .map(|prepared| prepared.usage())
                .unwrap_or_default();
            if let Ok(collectors) = self.notif.lock() {
                for collector in collectors.iter() {
                    if collector.observed() {
                        usage.violations_observed = true;
                    }
                    merge_violations(&mut usage.violations, collector.violations());
                }
            }
            if let Some(proxy) = &self.proxy {
                merge_violations(&mut usage.violations, proxy.violations());
            }
            usage
        }
        #[cfg(not(target_os = "linux"))]
        ChildUsage::default()
    }

    #[cfg(target_os = "linux")]
    fn cgroup_procs_fd(&self) -> Option<i32> {
        self.cgroup.as_ref().map(|prepared| prepared.procs_fd())
    }

    #[cfg(not(target_os = "linux"))]
    fn cgroup_procs_fd(&self) -> Option<i32> {
        None
    }

    /// Scratch directory used as `TMPDIR` under `linux_native`.
    pub fn scratch_dir(&self) -> Option<&Path> {
        #[cfg(target_os = "linux")]
        {
            self.linux
                .as_ref()
                .map(|prepared| prepared.scratch.as_path())
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }
}

/// CLI entry for the `kekkai-guest` helper.
///
/// Parses the helper protocol, prepares [`Backend::LinuxNative`], spawns the
/// payload without a nested process group, waits, and drops the sandbox so
/// scratch is removed. The helper is the process-group leader.
#[cfg(feature = "guest")]
pub fn run_guest_helper() -> std::process::ExitCode {
    guest::run()
}

struct DeadlineGuard<'a> {
    sandbox: &'a Sandbox,
    pid: Option<u32>,
    disarm: bool,
}

impl Drop for DeadlineGuard<'_> {
    fn drop(&mut self) {
        if !self.disarm {
            self.sandbox.kill_process_group(self.pid);
            self.sandbox.kill_cgroup();
        }
    }
}

fn sigterm() -> i32 {
    #[cfg(unix)]
    {
        libc::SIGTERM
    }
    #[cfg(not(unix))]
    {
        0
    }
}

fn sigkill() -> i32 {
    #[cfg(unix)]
    {
        libc::SIGKILL
    }
    #[cfg(not(unix))]
    {
        0
    }
}

#[cfg(target_os = "linux")]
fn merge_violations(into: &mut Vec<SandboxViolation>, extra: Vec<SandboxViolation>) {
    for item in extra {
        if let Some(existing) = into
            .iter_mut()
            .find(|v| v.kind == item.kind && v.detail == item.detail)
        {
            existing.count = existing.count.saturating_add(item.count);
        } else {
            into.push(item);
        }
    }
}

fn millis_since(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn validate(settings: &Settings) -> Result<(), Error> {
    for (name, value) in [
        ("cpu_time_secs", settings.limits.cpu_time_secs),
        ("memory_mb", settings.limits.memory_mb),
        ("user_processes", settings.limits.user_processes),
        ("file_size_mb", settings.limits.file_size_mb),
        ("open_files", settings.limits.open_files),
    ] {
        if value == Some(0) {
            return Err(Error::invalid(format!("{name} must be greater than zero")));
        }
    }
    let named_paths = !settings.inputs.is_empty() || settings.output.is_some();
    if (named_paths
        || !settings.readable_roots.is_empty()
        || !settings.writable_roots.is_empty()
        || !settings.devices.is_empty())
        && !matches!(settings.backend, Backend::LinuxNative | Backend::Userspace)
    {
        return Err(Error::invalid(
            "path roles, readable_roots, writable_roots, and devices are only applied by backend linux_native or userspace",
        ));
    }
    if let Some(path) = &settings.guest_helper {
        if !matches!(settings.backend, Backend::Userspace) {
            return Err(Error::invalid("guest_helper requires backend userspace"));
        }
        if !path.is_absolute() {
            return Err(Error::invalid(format!(
                "guest helper `{}` must be an absolute path",
                path.display()
            )));
        }
    }
    for path in settings
        .inputs
        .iter()
        .chain(settings.output.iter())
        .chain(settings.readable_roots.iter())
        .chain(settings.writable_roots.iter())
        .chain(settings.devices.iter())
    {
        if !path.is_absolute() {
            return Err(Error::invalid(format!(
                "root `{}` must be an absolute path",
                path.display()
            )));
        }
    }
    let inputs: Vec<PathBuf> = settings.inputs.iter().map(|p| normalize_path(p)).collect();
    let writable_roots: Vec<PathBuf> = settings
        .writable_roots
        .iter()
        .map(|p| normalize_path(p))
        .collect();
    let output_buf;
    let named: Vec<(&str, &Path)> = if let Some(path) = &settings.output {
        output_buf = normalize_path(path);
        vec![("output", output_buf.as_path())]
    } else {
        Vec::new()
    };
    reject_inputs_under_writables(&inputs, &named, &writable_roots)?;
    if !settings.cgroup.is_empty() && matches!(settings.backend, Backend::None) {
        return Err(Error::invalid(
            "cgroup limits require backend rlimit or linux_native",
        ));
    }
    if matches!(settings.namespaces, Namespaces::Isolate)
        && matches!(settings.backend, Backend::None)
    {
        return Err(Error::invalid(
            "namespace isolate requires backend rlimit or linux_native",
        ));
    }
    if !matches!(settings.filesystem_view, FilesystemView::Host) {
        if matches!(settings.namespaces, Namespaces::Off) {
            return Err(Error::invalid("filesystem view requires namespace isolate"));
        }
        if matches!(settings.backend, Backend::None) {
            return Err(Error::invalid(
                "filesystem view requires backend rlimit or linux_native",
            ));
        }
    }
    if let FilesystemView::Isolate {
        overlay: OverlayPersist::Keep(path),
    } = &settings.filesystem_view
        && !path.is_absolute()
    {
        return Err(Error::invalid(format!(
            "overlay keep `{}` must be an absolute path",
            path.display()
        )));
    }
    match &settings.network {
        Network::Allowlist(hosts) => {
            if !matches!(settings.backend, Backend::LinuxNative) {
                return Err(Error::invalid(
                    "Network::Allowlist requires backend linux_native",
                ));
            }
            if hosts.is_empty() {
                return Err(Error::invalid(
                    "Network::Allowlist must name at least one host",
                ));
            }
            for host in hosts {
                if host.host.is_empty() {
                    return Err(Error::invalid("AllowHost.host must not be empty"));
                }
                if host.port == Some(0) {
                    return Err(Error::invalid("AllowHost.port must be greater than zero"));
                }
            }
        }
        Network::Loopback => {
            if matches!(settings.namespaces, Namespaces::Off) {
                return Err(Error::invalid(
                    "Network::Loopback requires namespace isolate",
                ));
            }
            if matches!(settings.backend, Backend::None) {
                return Err(Error::invalid(
                    "Network::Loopback requires backend rlimit or linux_native",
                ));
            }
        }
        Network::Deny | Network::Allow => {}
    }
    if !matches!(settings.syscall_profile, SyscallProfile::Default)
        && !matches!(settings.backend, Backend::LinuxNative)
    {
        return Err(Error::invalid(
            "syscall profile strict and python require backend linux_native",
        ));
    }
    if matches!(settings.backend, Backend::Userspace) {
        if !settings.cgroup.is_empty() {
            return Err(Error::invalid(
                "cgroup limits are not applied by backend userspace",
            ));
        }
        if matches!(settings.namespaces, Namespaces::Isolate) {
            return Err(Error::invalid(
                "namespace isolate is not applied by backend userspace",
            ));
        }
    }
    for (name, value) in [
        ("cgroup.memory_max", settings.cgroup.memory_max),
        ("cgroup.memory_high", settings.cgroup.memory_high),
        ("cgroup.pids_max", settings.cgroup.pids_max),
        ("cgroup.cpu_quota_us", settings.cgroup.cpu_quota_us),
        ("cgroup.cpu_period_us", settings.cgroup.cpu_period_us),
        ("cgroup.cpu_weight", settings.cgroup.cpu_weight),
    ] {
        if value == Some(0) {
            return Err(Error::invalid(format!("{name} must be greater than zero")));
        }
    }
    if let Some(weight) = settings.cgroup.cpu_weight
        && weight > 10_000
    {
        return Err(Error::invalid(
            "cgroup.cpu_weight must be between 1 and 10000",
        ));
    }
    if let Some(io) = settings.cgroup.io_max {
        if io.is_empty() {
            return Err(Error::invalid(
                "cgroup.io_max must set rbps, wbps, riops, or wiops",
            ));
        }
        for (name, value) in [
            ("cgroup.io_max.rbps", io.rbps),
            ("cgroup.io_max.wbps", io.wbps),
            ("cgroup.io_max.riops", io.riops),
            ("cgroup.io_max.wiops", io.wiops),
        ] {
            if value == Some(0) {
                return Err(Error::invalid(format!("{name} must be greater than zero")));
            }
        }
    }
    if settings.cgroup.cpu_period_us.is_some() && settings.cgroup.cpu_quota_us.is_none() {
        return Err(Error::invalid(
            "cgroup.cpu_period_us requires cgroup.cpu_quota_us",
        ));
    }
    if let Some(root) = &settings.cgroup_root
        && !root.is_absolute()
    {
        return Err(Error::invalid(format!(
            "cgroup_root `{}` must be an absolute path",
            root.display()
        )));
    }
    Ok(())
}

fn check_path_roles(settings: &Settings, workspace: &Path) -> Result<(), Error> {
    let inputs: Vec<PathBuf> = settings.inputs.iter().map(|p| normalize_path(p)).collect();
    let writable_roots: Vec<PathBuf> = settings
        .writable_roots
        .iter()
        .map(|p| normalize_path(p))
        .collect();
    let output = match &settings.output {
        Some(path) => normalize_path(path),
        None => normalize_path(workspace),
    };
    reject_inputs_under_writables(&inputs, &[("output", output.as_path())], &writable_roots)
}

fn normalize_path(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|cwd| cwd.join(path))
                .unwrap_or_else(|_| path.to_path_buf())
        }
    })
}

fn path_is_same_or_under(path: &Path, ancestor: &Path) -> bool {
    path == ancestor || path.starts_with(ancestor)
}

pub(crate) fn reject_inputs_under_writables(
    inputs: &[PathBuf],
    named: &[(&str, &Path)],
    writable_roots: &[PathBuf],
) -> Result<(), Error> {
    for input in inputs {
        for (label, writable) in named {
            if path_is_same_or_under(input, writable) {
                return Err(Error::invalid(format!(
                    "input `{}` overlaps writable {label} `{}`",
                    input.display(),
                    writable.display()
                )));
            }
        }
        for writable in writable_roots {
            if path_is_same_or_under(input, writable) {
                return Err(Error::invalid(format!(
                    "input `{}` overlaps writable writable_roots `{}`",
                    input.display(),
                    writable.display()
                )));
            }
        }
    }
    Ok(())
}

fn rlimit_values(settings: &Settings) -> Limits {
    let mut limits = settings.limits;
    if settings.cgroup.memory_max.is_some() {
        limits.memory_mb = None;
    }
    if settings.cgroup.pids_max.is_some() {
        limits.user_processes = None;
    }
    limits
}

pub(crate) fn join_cgroup(fd: Option<i32>) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    if let Some(fd) = fd {
        return cgroup::join(fd);
    }
    let _ = fd;
    Ok(())
}

fn error_from_health(backend: Backend, message: String) -> Error {
    let unsupported = match backend {
        Backend::LinuxNative | Backend::Userspace => !cfg!(target_os = "linux"),
        Backend::Rlimit => !cfg!(unix),
        Backend::None => false,
    };
    if unsupported {
        Error::unsupported(backend, message)
    } else {
        Error::unavailable(backend, message)
    }
}

#[cfg(unix)]
pub(crate) fn apply_rlimit_values(limits: Limits) -> io::Result<()> {
    set_limit(libc::RLIMIT_CPU, limits.cpu_time_secs)?;
    set_limit(
        libc::RLIMIT_AS,
        limits
            .memory_mb
            .map(|value| value.saturating_mul(1024 * 1024)),
    )?;
    set_limit(libc::RLIMIT_NPROC, limits.user_processes)?;
    set_limit(
        libc::RLIMIT_FSIZE,
        limits
            .file_size_mb
            .map(|value| value.saturating_mul(1024 * 1024)),
    )?;
    set_limit(libc::RLIMIT_NOFILE, limits.open_files)?;
    Ok(())
}

#[cfg(unix)]
fn set_limit(resource: RlimitResource, limit: Option<u64>) -> io::Result<()> {
    let Some(limit) = limit else {
        return Ok(());
    };
    let value = libc::rlimit {
        rlim_cur: limit as libc::rlim_t,
        rlim_max: limit as libc::rlim_t,
    };
    // SAFETY: `value` is initialized and the resource constants are supplied
    // by libc for this target.
    if unsafe { libc::setrlimit(resource as _, &value) } != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
type RlimitResource = libc::c_uint;

#[cfg(all(unix, not(target_os = "linux")))]
type RlimitResource = libc::c_int;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_names_are_stable() {
        assert_eq!(Backend::None.to_string(), "none");
        assert_eq!(Backend::Rlimit.to_string(), "rlimit");
        assert_eq!(Backend::LinuxNative.to_string(), "linux_native");
        assert_eq!(Backend::Userspace.to_string(), "userspace");
        assert_eq!(Backend::default(), Backend::None);
    }

    #[test]
    fn userspace_without_helper_does_not_downgrade() {
        let settings = Settings {
            backend: Backend::Userspace,
            guest_helper: Some(PathBuf::from("/no/such/kekkai-guest-helper")),
            ..Settings::default()
        };
        match health(&settings) {
            Health::Error(_) => {
                let error = Sandbox::prepare(&settings, ".").unwrap_err();
                assert!(
                    matches!(
                        error,
                        Error::Unsupported {
                            backend: Backend::Userspace,
                            ..
                        } | Error::Unavailable {
                            backend: Backend::Userspace,
                            ..
                        }
                    ),
                    "{error}"
                );
            }
            other => panic!("expected health error, got {other:?}"),
        }
    }

    #[test]
    fn default_sandbox_is_a_noop() {
        let sandbox = Sandbox::prepare(&Settings::default(), ".").unwrap();
        let mut command = Command::new("true");
        sandbox.apply(&mut command).unwrap();
        assert!(sandbox.scratch_dir().is_none());
    }

    #[test]
    fn none_backend_is_a_health_warning() {
        assert!(matches!(
            health(&Settings::default()),
            Health::Warning(message) if message.contains("backend=none")
        ));
    }

    #[test]
    fn zero_limits_are_invalid() {
        let mut settings = Settings::default();
        settings.limits.memory_mb = Some(0);
        let error = Sandbox::prepare(&settings, ".").unwrap_err();
        assert!(
            matches!(error, Error::Invalid { ref message } if message.contains("memory_mb")),
            "{error}"
        );
    }

    #[test]
    fn isolate_namespaces_without_a_real_backend_are_invalid() {
        let settings = Settings {
            namespaces: Namespaces::Isolate,
            ..Settings::default()
        };
        let error = Sandbox::prepare(&settings, ".").unwrap_err();
        assert!(error.to_string().contains("namespace"), "{error}");
    }

    #[test]
    fn extra_roots_require_linux_native() {
        let mut settings = Settings::default();
        settings.readable_roots.push("/usr".into());
        let error = Sandbox::prepare(&settings, ".").unwrap_err();
        assert!(error.to_string().contains("linux_native"), "{error}");
    }

    #[test]
    fn allowlist_requires_linux_native() {
        let settings = Settings {
            network: Network::Allowlist(vec![AllowHost {
                host: "example.com".into(),
                port: Some(443),
            }]),
            ..Settings::default()
        };
        let error = Sandbox::prepare(&settings, ".").unwrap_err();
        assert!(error.to_string().contains("linux_native"), "{error}");
    }

    #[test]
    fn empty_allowlist_is_invalid() {
        let settings = Settings {
            backend: Backend::LinuxNative,
            network: Network::Allowlist(Vec::new()),
            ..Settings::default()
        };
        let error = Sandbox::prepare(&settings, ".").unwrap_err();
        assert!(
            matches!(error, Error::Invalid { ref message } if message.contains("Allowlist")),
            "{error}"
        );
    }

    #[test]
    fn devices_require_linux_native() {
        let mut settings = Settings::default();
        settings.devices.push("/dev/full".into());
        let error = Sandbox::prepare(&settings, ".").unwrap_err();
        assert!(error.to_string().contains("linux_native"), "{error}");
    }

    #[test]
    fn devices_must_be_absolute() {
        let mut settings = Settings {
            backend: Backend::LinuxNative,
            ..Settings::default()
        };
        settings.devices.push("dev/full".into());
        let error = Sandbox::prepare(&settings, ".").unwrap_err();
        assert!(
            matches!(error, Error::Invalid { ref message } if message.contains("absolute")),
            "{error}"
        );
    }

    #[test]
    fn extra_roots_must_be_absolute() {
        let mut settings = Settings {
            backend: Backend::LinuxNative,
            ..Settings::default()
        };
        settings.readable_roots.push("relative/path".into());
        let error = Sandbox::prepare(&settings, ".").unwrap_err();
        assert!(
            matches!(error, Error::Invalid { ref message } if message.contains("absolute")),
            "{error}"
        );
    }

    #[test]
    fn inputs_require_linux_native() {
        let mut settings = Settings::default();
        settings.inputs.push("/tmp".into());
        let error = Sandbox::prepare(&settings, ".").unwrap_err();
        assert!(error.to_string().contains("linux_native"), "{error}");
    }

    #[test]
    fn input_overlapping_output_is_invalid() {
        let settings = Settings {
            backend: Backend::LinuxNative,
            inputs: vec!["/tmp".into()],
            output: Some("/tmp".into()),
            ..Settings::default()
        };
        let error = Sandbox::prepare(&settings, "/tmp").unwrap_err();
        assert!(
            matches!(error, Error::Invalid { ref message } if message.contains("overlap")),
            "{error}"
        );
    }

    #[test]
    fn input_inside_workspace_is_invalid() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = tmp.path().join("ws");
        let input = workspace.join("in");
        fs::create_dir_all(&input).unwrap();
        let settings = Settings {
            backend: Backend::LinuxNative,
            inputs: vec![input],
            ..Settings::default()
        };
        let error = Sandbox::prepare(&settings, &workspace).unwrap_err();
        assert!(
            matches!(error, Error::Invalid { ref message } if message.contains("overlap")),
            "{error}"
        );
    }

    #[test]
    fn input_inside_writable_root_is_invalid() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = tmp.path().join("ws");
        let writable = tmp.path().join("rw");
        let input = writable.join("in");
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(&input).unwrap();
        let settings = Settings {
            backend: Backend::LinuxNative,
            inputs: vec![input],
            writable_roots: vec![writable],
            ..Settings::default()
        };
        let error = Sandbox::prepare(&settings, &workspace).unwrap_err();
        assert!(
            matches!(error, Error::Invalid { ref message } if message.contains("overlap")),
            "{error}"
        );
    }

    #[test]
    fn linux_native_health_matches_the_host() {
        let settings = Settings {
            backend: Backend::LinuxNative,
            ..Settings::default()
        };
        let report = health(&settings);
        if cfg!(target_os = "linux") {
            assert!(
                matches!(
                    report,
                    Health::Ok(ref message) if message.contains("linux_native")
                ) || matches!(report, Health::Error(_)),
                "{report:?}"
            );
        } else {
            assert!(
                matches!(report, Health::Error(ref message) if message.contains("Linux")),
                "{report:?}"
            );
        }
    }

    #[test]
    fn linux_native_never_silently_downgrades() {
        let settings = Settings {
            backend: Backend::LinuxNative,
            ..Settings::default()
        };
        match health(&settings) {
            Health::Error(_) => {
                let error = Sandbox::prepare(&settings, ".").unwrap_err();
                assert!(
                    matches!(
                        error,
                        Error::Unsupported {
                            backend: Backend::LinuxNative,
                            ..
                        } | Error::Unavailable {
                            backend: Backend::LinuxNative,
                            ..
                        }
                    ),
                    "{error}"
                );
            }
            Health::Ok(_) => {
                let dir = std::env::temp_dir();
                Sandbox::prepare(&settings, &dir).unwrap();
            }
            Health::Warning(message) => {
                panic!("linux_native must not warn: {message}");
            }
        }
    }

    #[test]
    fn capabilities_report_this_host() {
        let caps = capabilities();
        assert_eq!(caps.rlimit, cfg!(unix));
        assert_eq!(caps.seccomp, cfg!(target_os = "linux"));
        if !cfg!(target_os = "linux") {
            assert_eq!(caps.landlock_abi, None);
            assert!(!caps.cgroup);
            assert!(!caps.seccomp_user_notif);
            assert!(!caps.user_namespaces);
            assert!(!caps.filesystem_view);
            assert!(!caps.network_namespace);
        }
    }

    #[test]
    fn syscall_profile_without_linux_native_is_invalid() {
        let settings = Settings {
            backend: Backend::Rlimit,
            syscall_profile: SyscallProfile::Python,
            ..Settings::default()
        };
        let error = Sandbox::prepare(&settings, ".").unwrap_err();
        assert!(error.to_string().contains("linux_native"), "{error}");
    }

    #[test]
    fn loopback_without_namespaces_is_invalid() {
        let settings = Settings {
            backend: Backend::Rlimit,
            network: Network::Loopback,
            ..Settings::default()
        };
        let error = Sandbox::prepare(&settings, ".").unwrap_err();
        assert!(error.to_string().contains("Loopback"), "{error}");
    }

    #[test]
    fn filesystem_view_without_namespaces_is_invalid() {
        let settings = Settings {
            backend: Backend::Rlimit,
            filesystem_view: FilesystemView::Isolate {
                overlay: OverlayPersist::Discard,
            },
            ..Settings::default()
        };
        let error = Sandbox::prepare(&settings, ".").unwrap_err();
        assert!(error.to_string().contains("filesystem view"), "{error}");
    }

    #[test]
    fn cpu_weight_out_of_range_is_invalid() {
        let settings = Settings {
            backend: Backend::Rlimit,
            cgroup: CgroupLimits {
                cpu_weight: Some(10_001),
                ..CgroupLimits::default()
            },
            ..Settings::default()
        };
        let error = Sandbox::prepare(&settings, ".").unwrap_err();
        assert!(error.to_string().contains("cpu_weight"), "{error}");
    }

    #[test]
    fn empty_io_max_is_invalid() {
        let settings = Settings {
            backend: Backend::Rlimit,
            cgroup: CgroupLimits {
                io_max: Some(IoMax {
                    major: 8,
                    minor: 0,
                    ..IoMax::default()
                }),
                ..CgroupLimits::default()
            },
            ..Settings::default()
        };
        let error = Sandbox::prepare(&settings, ".").unwrap_err();
        assert!(error.to_string().contains("io_max"), "{error}");
    }

    #[test]
    fn io_max_zero_dimension_is_invalid() {
        let settings = Settings {
            backend: Backend::Rlimit,
            cgroup: CgroupLimits {
                io_max: Some(IoMax {
                    major: 8,
                    minor: 0,
                    wbps: Some(0),
                    ..IoMax::default()
                }),
                ..CgroupLimits::default()
            },
            ..Settings::default()
        };
        let error = Sandbox::prepare(&settings, ".").unwrap_err();
        assert!(error.to_string().contains("io_max"), "{error}");
    }

    #[test]
    fn cgroup_limits_without_a_real_backend_are_invalid() {
        let mut settings = Settings::default();
        settings.cgroup.memory_max = Some(512 * 1024 * 1024);
        let error = Sandbox::prepare(&settings, ".").unwrap_err();
        assert!(error.to_string().contains("cgroup"), "{error}");
    }

    #[test]
    fn cgroup_limits_fail_closed_without_delegation() {
        let mut settings = Settings {
            backend: Backend::Rlimit,
            ..Settings::default()
        };
        settings.cgroup.memory_max = Some(32 * 1024 * 1024);
        match health(&settings) {
            Health::Error(message) => {
                assert!(
                    message.contains("cgroup") || message.contains("Linux"),
                    "{message}"
                );
                let error = Sandbox::prepare(&settings, ".").unwrap_err();
                assert!(
                    matches!(error, Error::Unsupported { .. } | Error::Unavailable { .. }),
                    "{error}"
                );
            }
            Health::Ok(_) => {
                let sandbox = Sandbox::prepare(&settings, ".").unwrap();
                assert!(!sandbox.finish().oom_killed);
            }
            Health::Warning(message) => panic!("cgroup request must not warn: {message}"),
        }
    }

    #[test]
    fn rlimit_health_matches_the_host() {
        let settings = Settings {
            backend: Backend::Rlimit,
            ..Settings::default()
        };
        let report = health(&settings);
        if cfg!(unix) {
            assert!(
                matches!(report, Health::Ok(ref message) if message.contains("rlimit")),
                "{report:?}"
            );
            Sandbox::prepare(&settings, ".").unwrap();
        } else {
            assert!(matches!(report, Health::Error(_)), "{report:?}");
        }
    }
}
