//! kekkai (結界): sandbox child processes on Linux.
//!
//! kekkai applies a filesystem allowlist (Landlock), a syscall and network
//! gate (seccomp) and resource limits to a [`std::process::Command`] before it
//! spawns.
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use std::process::Command;
//! use kekkai::{Backend, Sandbox, Settings};
//!
//! let mut settings = Settings::default();
//! settings.backend = Backend::LinuxNative;
//! let sandbox = Sandbox::prepare(&settings, "/path/to/workspace")?;
//! let mut cmd = Command::new("python3");
//! sandbox.apply(&mut cmd)?;
//! let _status = cmd.status()?;
//! # Ok(())
//! # }
//! ```

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(target_os = "linux")]
use std::sync::Arc;

#[cfg(target_os = "linux")]
mod cgroup;
#[cfg(target_os = "linux")]
mod linux;

/// Isolation backend for spawned child processes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Backend {
    /// No isolation (development only).
    #[default]
    None,
    /// Unix resource limits and a process group, no filesystem or network rules.
    Rlimit,
    /// Landlock filesystem rules plus a seccomp socket gate, applied in `pre_exec`.
    LinuxNative,
}

impl fmt::Display for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Backend::None => "none",
            Backend::Rlimit => "rlimit",
            Backend::LinuxNative => "linux_native",
        })
    }
}

/// Whether the child may create network sockets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Network {
    /// `socket()` fails with `EPERM`. This is the default.
    #[default]
    Deny,
    /// Socket creation is left to the host. Filesystem rules still apply.
    Allow,
}

/// Opt-in cgroup v2 limits. Empty means do not use a cgroup.
///
/// Requesting any field without a delegated cgroup v2 subtree is an error;
/// kekkai never falls back to `RLIMIT_AS`.
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
}

impl CgroupLimits {
    /// True when no cgroup controllers are requested.
    pub fn is_empty(&self) -> bool {
        self.memory_max.is_none()
            && self.memory_high.is_none()
            && self.pids_max.is_none()
            && self.cpu_quota_us.is_none()
            && self.cpu_period_us.is_none()
    }
}

/// Usage collected from a child's cgroup after it exits.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChildUsage {
    /// `memory.events` `oom_kill` was non-zero.
    pub oom_killed: bool,
    /// Peak memory in bytes (`memory.peak`), if the controller reported it.
    pub memory_peak_bytes: Option<u64>,
    /// CPU time in microseconds (`cpu.stat` `usage_usec`).
    pub cpu_usec: Option<u64>,
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
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Settings {
    /// Isolation backend. Selecting one the host cannot provide is an error.
    pub backend: Backend,
    /// Resource limits applied by `rlimit` and `linux_native`.
    pub limits: Limits,
    /// Extra absolute paths granted read and execute under `linux_native`.
    pub readable_roots: Vec<PathBuf>,
    /// Extra absolute paths granted read and write under `linux_native`.
    /// The workspace root passed to [`Sandbox::prepare`] is always writable.
    pub writable_roots: Vec<PathBuf>,
    /// Socket creation policy under `linux_native`. Ignored by other backends.
    pub network: Network,
    /// Opt-in cgroup v2 limits. Requires `rlimit` or `linux_native`.
    pub cgroup: CgroupLimits,
    /// Delegated cgroup v2 directory. `None` probes the current cgroup.
    pub cgroup_root: Option<PathBuf>,
}

/// Health of a configured backend on the current host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Health {
    Ok(String),
    Warning(String),
    Error(String),
}

/// Host kernel capabilities that affect backend selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    /// Unix resource limits can be applied in `pre_exec`.
    pub rlimit: bool,
    /// Landlock ABI if the kernel probe succeeded.
    pub landlock_abi: Option<u32>,
    /// The host is Linux, where seccomp-BPF can be installed in `pre_exec`.
    pub seccomp: bool,
    /// A writable cgroup v2 subtree is available for per-child limits.
    pub cgroup: bool,
}

/// Failure to prepare or apply a sandbox.
#[derive(Debug)]
pub enum Error {
    /// The backend is not implemented on this operating system.
    Unsupported { backend: Backend, message: String },
    /// The backend is implemented but the host cannot enforce it.
    Unavailable { backend: Backend, message: String },
    /// Settings or paths cannot be used.
    Invalid { message: String },
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

    Capabilities {
        rlimit,
        landlock_abi,
        seccomp: cfg!(target_os = "linux"),
        cgroup,
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
    };
    match (&backend, cgroup_health(settings)) {
        (_, Some(Health::Error(message))) => Health::Error(message),
        (Health::Error(_), _) => backend,
        (Health::Ok(base), Some(Health::Ok(extra))) => Health::Ok(format!("{base}; {extra}")),
        (Health::Warning(base), Some(Health::Ok(extra))) => {
            Health::Warning(format!("{base}; {extra}"))
        }
        _ => backend,
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
            match cgroup::probe_with(settings.backend, settings.cgroup_root.as_deref()) {
                Ok(path) => Health::Ok(format!(
                    "cgroup=v2 root={} memory_max={:?} pids_max={:?} cpu_quota_us={:?}",
                    path.display(),
                    settings.cgroup.memory_max,
                    settings.cgroup.pids_max,
                    settings.cgroup.cpu_quota_us
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
fn linux_native_health(settings: &Settings) -> Health {
    match linux::probe_enforcement() {
        Ok(abi) => {
            let signal = if abi >= 6 { "landlock" } else { "none" };
            let network = match settings.network {
                Network::Deny => "deny",
                Network::Allow => "allow",
            };
            Health::Ok(format!(
                "sandbox:   backend=linux_native abi={abi} network={network} signal_scoping={signal} writable=workspace+scratch+{} readable={} cpu={:?} memory_mb={:?} user_processes={:?}",
                settings.writable_roots.len(),
                settings.readable_roots.len(),
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

/// Prepared sandbox, applied to a [`Command`] before spawn.
#[derive(Debug)]
pub struct Sandbox {
    settings: Settings,
    #[cfg(target_os = "linux")]
    linux: Option<Arc<linux::LinuxPrepared>>,
    #[cfg(target_os = "linux")]
    cgroup: Option<Arc<cgroup::CgroupPrepared>>,
}

impl Sandbox {
    /// Validate settings, probe the host, and build any kernel ruleset.
    ///
    /// `root` is the workspace directory. Under `linux_native` it is granted
    /// read and write; extra roots come from [`Settings`].
    pub fn prepare(settings: &Settings, root: impl AsRef<Path>) -> Result<Self, Error> {
        validate(settings)?;
        match health(settings) {
            Health::Error(message) => return Err(error_from_health(settings.backend, message)),
            Health::Ok(_) | Health::Warning(_) => {}
        }
        #[cfg(target_os = "linux")]
        let linux = if matches!(settings.backend, Backend::LinuxNative) {
            Some(linux::prepare(
                root.as_ref(),
                &settings.readable_roots,
                &settings.writable_roots,
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
        #[cfg(not(target_os = "linux"))]
        let _ = root;
        Ok(Self {
            settings: settings.clone(),
            #[cfg(target_os = "linux")]
            linux,
            #[cfg(target_os = "linux")]
            cgroup,
        })
    }

    /// Install `pre_exec` hooks on a standard library command.
    pub fn apply(&self, command: &mut Command) -> Result<(), Error> {
        match self.settings.backend {
            Backend::None => Ok(()),
            Backend::Rlimit => self.apply_rlimit(command),
            Backend::LinuxNative => self.apply_linux_native(command),
        }
    }

    /// Install the same hooks on a `tokio::process::Command`.
    #[cfg(feature = "tokio")]
    pub fn apply_tokio(&self, command: &mut tokio::process::Command) -> Result<(), Error> {
        self.apply(command.as_std_mut())
    }

    #[cfg(unix)]
    fn apply_rlimit(&self, command: &mut Command) -> Result<(), Error> {
        use std::os::unix::process::CommandExt;

        let limits = rlimit_values(&self.settings);
        let cgroup_fd = self.cgroup_procs_fd();
        // SAFETY: `pre_exec` runs between fork and exec. The closure only
        // performs async-signal-safe libc calls and does not allocate.
        unsafe {
            command.pre_exec(move || {
                if libc::setpgid(0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                join_cgroup(cgroup_fd)?;
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
        let prepared = self
            .linux
            .clone()
            .ok_or_else(|| Error::invalid("linux_native ruleset was not prepared"))?;
        linux::apply(
            command,
            rlimit_values(&self.settings),
            matches!(self.settings.network, Network::Deny),
            self.cgroup_procs_fd(),
            prepared,
        )
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
        #[cfg(unix)]
        if matches!(
            self.settings.backend,
            Backend::Rlimit | Backend::LinuxNative
        ) && let Some(pid) = pid
            && pid > 1
        {
            // SAFETY: negative pid targets the process group. The pid came
            // from a spawned child of this process.
            unsafe {
                let _ = libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
            }
        }
    }

    /// Read cgroup events after the child exits. Empty when no cgroup was used.
    pub fn finish(&self) -> ChildUsage {
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
    if (!settings.readable_roots.is_empty() || !settings.writable_roots.is_empty())
        && !matches!(settings.backend, Backend::LinuxNative)
    {
        return Err(Error::invalid(
            "readable_roots and writable_roots are only applied by backend linux_native",
        ));
    }
    for path in settings
        .readable_roots
        .iter()
        .chain(settings.writable_roots.iter())
    {
        if !path.is_absolute() {
            return Err(Error::invalid(format!(
                "root `{}` must be an absolute path",
                path.display()
            )));
        }
    }
    if !settings.cgroup.is_empty() && matches!(settings.backend, Backend::None) {
        return Err(Error::invalid(
            "cgroup limits require backend rlimit or linux_native",
        ));
    }
    for (name, value) in [
        ("cgroup.memory_max", settings.cgroup.memory_max),
        ("cgroup.memory_high", settings.cgroup.memory_high),
        ("cgroup.pids_max", settings.cgroup.pids_max),
        ("cgroup.cpu_quota_us", settings.cgroup.cpu_quota_us),
        ("cgroup.cpu_period_us", settings.cgroup.cpu_period_us),
    ] {
        if value == Some(0) {
            return Err(Error::invalid(format!("{name} must be greater than zero")));
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
        Backend::LinuxNative => !cfg!(target_os = "linux"),
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
        assert_eq!(Backend::default(), Backend::None);
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
    fn extra_roots_require_linux_native() {
        let mut settings = Settings::default();
        settings.readable_roots.push("/usr".into());
        let error = Sandbox::prepare(&settings, ".").unwrap_err();
        assert!(error.to_string().contains("linux_native"), "{error}");
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
        }
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
