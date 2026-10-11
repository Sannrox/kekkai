//! `kekkai run`: spawn a command through the library sandbox and print a JSON report.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
#[cfg(unix)]
use std::sync::atomic::{AtomicI32, Ordering};

use kekkai::{
    AllowHost, Backend, CgroupLimits, FilesystemView, IoMax, Limits, Namespaces, Network,
    OverlayPersist, RunReport, Sandbox, Settings, SyscallProfile,
};
use serde::Deserialize;

fn main() -> ExitCode {
    let mut argv = env::args_os().skip(1).peekable();
    match argv.peek() {
        None => usage(),
        Some(arg) if arg == "-h" || arg == "--help" => help(),
        Some(arg) if arg == "--version" => {
            println!("kekkai {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some(arg) if arg == "run" => {
            argv.next();
            run(argv)
        }
        Some(_) => usage(),
    }
}

fn help() -> ExitCode {
    println!("{HELP}");
    ExitCode::SUCCESS
}

fn usage() -> ExitCode {
    eprintln!("{HELP}");
    ExitCode::from(2)
}

const HELP: &str = "\
kekkai run — spawn a command under the same sandbox as the library.

Usage:
  kekkai run [options] -- PROGRAM [ARGS...]
  kekkai --help
  kekkai --version

Options:
  --settings FILE       JSON settings file. Flags override FILE.
  --workspace DIR       Workspace root (default: current directory)
  --backend NAME        none | rlimit | linux_native | macos | userspace
                        Default: linux_native on Linux, macos on macOS,
                        rlimit elsewhere
  --network POLICY      deny | allow
  --input PATH          Read-only input (repeatable)
  --output DIR          Writable output directory
  --readable PATH       Extra read/exec root (repeatable)
  --writable PATH       Extra read/write root (repeatable)
  --device PATH         Extra device node (repeatable)
  --syscall-profile P   default | strict | python
  --namespaces MODE     off | isolate
  --cpu-time-secs N
  --memory-mb N
  --user-processes N
  --file-size-mb N
  --open-files N
  --report PATH         Write JSON run report to PATH (`-` = stdout).
                        Default: one JSON object on stderr after the child exits
  --json                Same as --report -
  -h, --help
  --version

The child inherits stdin, stdout, and stderr. The JSON report is
RunReport schema_version 1 (settings summary, usage, timing; no host paths).

Exit codes:
  0-255   child's exit code
  128+N   child terminated by signal N
  2       usage error, or prepare/apply/spawn/report failed
";

enum ReportDest {
    Stderr,
    Stdout,
    File(PathBuf),
}

struct Cli {
    settings_path: Option<PathBuf>,
    workspace: Option<PathBuf>,
    backend: Option<Backend>,
    network: Option<Network>,
    inputs: Vec<PathBuf>,
    output: Option<PathBuf>,
    readable: Vec<PathBuf>,
    writable: Vec<PathBuf>,
    devices: Vec<PathBuf>,
    syscall_profile: Option<SyscallProfile>,
    namespaces: Option<Namespaces>,
    limits: Limits,
    report: ReportDest,
    program: OsString,
    args: Vec<OsString>,
}

fn run(mut argv: impl Iterator<Item = OsString>) -> ExitCode {
    let mut settings_path = None;
    let mut workspace = None;
    let mut backend = None;
    let mut network = None;
    let mut inputs = Vec::new();
    let mut output = None;
    let mut readable = Vec::new();
    let mut writable = Vec::new();
    let mut devices = Vec::new();
    let mut syscall_profile = None;
    let mut namespaces = None;
    let mut limits = Limits::default();
    let mut report = ReportDest::Stderr;
    let mut program = None;
    let mut args = Vec::new();

    while let Some(arg) = argv.next() {
        if arg == "--" {
            program = argv.next();
            args = argv.collect();
            break;
        }
        let Some(flag) = arg.to_str() else {
            return usage();
        };
        match flag {
            "-h" | "--help" => return help(),
            "--json" => {
                report = ReportDest::Stdout;
                continue;
            }
            "--version" => {
                println!("kekkai {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            _ => {}
        }
        let Some(value) = argv.next() else {
            return usage();
        };
        match flag {
            "--settings" => settings_path = Some(PathBuf::from(value)),
            "--workspace" => workspace = Some(PathBuf::from(value)),
            "--backend" => {
                let Some(parsed) = parse_backend(&value) else {
                    return fail(
                        2,
                        "unknown --backend (none|rlimit|linux_native|macos|userspace)",
                    );
                };
                backend = Some(parsed);
            }
            "--network" => {
                network = match value.to_str() {
                    Some("allow") => Some(Network::Allow),
                    Some("deny") => Some(Network::Deny),
                    _ => {
                        return fail(2, "unknown --network (deny|allow)");
                    }
                };
            }
            "--input" => inputs.push(PathBuf::from(value)),
            "--output" => output = Some(PathBuf::from(value)),
            "--readable" => readable.push(PathBuf::from(value)),
            "--writable" => writable.push(PathBuf::from(value)),
            "--device" => devices.push(PathBuf::from(value)),
            "--syscall-profile" => {
                let Some(parsed) = parse_syscall_profile(&value) else {
                    return fail(2, "unknown --syscall-profile (default|strict|python)");
                };
                syscall_profile = Some(parsed);
            }
            "--namespaces" => {
                let Some(parsed) = parse_namespaces(&value) else {
                    return fail(2, "unknown --namespaces (off|isolate)");
                };
                namespaces = Some(parsed);
            }
            "--cpu-time-secs" => {
                let Some(parsed) = parse_u64(&value) else {
                    return usage();
                };
                limits.cpu_time_secs = Some(parsed);
            }
            "--memory-mb" => {
                let Some(parsed) = parse_u64(&value) else {
                    return usage();
                };
                limits.memory_mb = Some(parsed);
            }
            "--user-processes" => {
                let Some(parsed) = parse_u64(&value) else {
                    return usage();
                };
                limits.user_processes = Some(parsed);
            }
            "--file-size-mb" => {
                let Some(parsed) = parse_u64(&value) else {
                    return usage();
                };
                limits.file_size_mb = Some(parsed);
            }
            "--open-files" => {
                let Some(parsed) = parse_u64(&value) else {
                    return usage();
                };
                limits.open_files = Some(parsed);
            }
            "--report" => {
                report = if value == "-" {
                    ReportDest::Stdout
                } else {
                    ReportDest::File(PathBuf::from(value))
                };
            }
            _ => return usage(),
        }
    }

    let Some(program) = program else {
        return usage();
    };

    let cli = Cli {
        settings_path,
        workspace,
        backend,
        network,
        inputs,
        output,
        readable,
        writable,
        devices,
        syscall_profile,
        namespaces,
        limits,
        report,
        program,
        args,
    };
    match execute(cli) {
        Ok(code) => code,
        Err(message) => fail(2, &message),
    }
}

fn execute(cli: Cli) -> Result<ExitCode, String> {
    let (mut settings, file_set_backend) = match &cli.settings_path {
        Some(path) => load_settings(path)?,
        None => (
            Settings::builder().backend(default_backend()).build(),
            false,
        ),
    };
    if let Some(backend) = cli.backend {
        settings.backend = backend;
    } else if cli.settings_path.is_some() && !file_set_backend {
        settings.backend = default_backend();
    }
    if let Some(network) = cli.network {
        settings.network = network;
    }
    if let Some(profile) = cli.syscall_profile {
        settings.syscall_profile = profile;
    }
    if let Some(namespaces) = cli.namespaces {
        settings.namespaces = namespaces;
    }
    if let Some(output) = cli.output {
        settings.output = Some(output);
    }
    merge_limits(&mut settings.limits, cli.limits);
    settings.inputs.extend(cli.inputs);
    settings.readable_roots.extend(cli.readable);
    settings.writable_roots.extend(cli.writable);
    settings.devices.extend(cli.devices);

    let workspace = match cli.workspace {
        Some(path) => path,
        None => env::current_dir().map_err(|error| format!("current directory: {error}"))?,
    };

    let sandbox = Sandbox::prepare(&settings, &workspace).map_err(|error| error.to_string())?;
    let mut child = sandbox
        .spawn(&cli.program, &cli.args)
        .map_err(|error| error.to_string())?;
    let _forward = SignalForward::install(settings.backend, child.id());
    let status = wait_child(&mut child)?;
    let report = sandbox.report();
    write_report(&cli.report, &report)?;
    Ok(exit_from_status(status))
}

fn wait_child(child: &mut std::process::Child) -> Result<std::process::ExitStatus, String> {
    loop {
        match child.wait() {
            Ok(status) => return Ok(status),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("wait sandboxed child: {error}")),
        }
    }
}

/// Isolating backends put the child in a new process group, so a terminal
/// SIGINT/SIGTERM would otherwise kill only `kekkai` and leave the child.
struct SignalForward;

#[cfg(unix)]
static FORWARD_PGID: AtomicI32 = AtomicI32::new(0);

#[cfg(unix)]
extern "C" fn forward_signal(sig: i32) {
    let pgid = FORWARD_PGID.load(Ordering::Relaxed);
    if pgid > 0 {
        // SAFETY: `pgid` is the child process-group leader set after spawn.
        unsafe {
            libc::kill(-pgid, sig);
        }
    }
}

impl SignalForward {
    fn install(backend: Backend, pid: u32) -> Self {
        #[cfg(unix)]
        {
            if matches!(
                backend,
                Backend::Rlimit | Backend::LinuxNative | Backend::Macos | Backend::Userspace
            ) && pid > 1
            {
                FORWARD_PGID.store(pid as i32, Ordering::Relaxed);
                // SAFETY: handler only loads an atomic and calls kill(2).
                unsafe {
                    libc::signal(
                        libc::SIGINT,
                        forward_signal as *const () as libc::sighandler_t,
                    );
                    libc::signal(
                        libc::SIGTERM,
                        forward_signal as *const () as libc::sighandler_t,
                    );
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (backend, pid);
        }
        Self
    }
}

#[cfg(unix)]
impl Drop for SignalForward {
    fn drop(&mut self) {
        FORWARD_PGID.store(0, Ordering::Relaxed);
        // SAFETY: restore default disposition after wait.
        unsafe {
            libc::signal(libc::SIGINT, libc::SIG_DFL);
            libc::signal(libc::SIGTERM, libc::SIG_DFL);
        }
    }
}

fn load_settings(path: &Path) -> Result<(Settings, bool), String> {
    let text = fs::read_to_string(path)
        .map_err(|error| format!("settings `{}`: {error}", path.display()))?;
    let file: FileSettings = serde_json::from_str(&text)
        .map_err(|error| format!("settings `{}`: {error}", path.display()))?;
    let backend_set = file.backend.is_some();
    Ok((file.into_settings()?, backend_set))
}

fn default_backend() -> Backend {
    if cfg!(target_os = "linux") {
        Backend::LinuxNative
    } else if cfg!(target_os = "macos") {
        Backend::Macos
    } else {
        Backend::Rlimit
    }
}

fn merge_limits(into: &mut Limits, extra: Limits) {
    if extra.cpu_time_secs.is_some() {
        into.cpu_time_secs = extra.cpu_time_secs;
    }
    if extra.memory_mb.is_some() {
        into.memory_mb = extra.memory_mb;
    }
    if extra.user_processes.is_some() {
        into.user_processes = extra.user_processes;
    }
    if extra.file_size_mb.is_some() {
        into.file_size_mb = extra.file_size_mb;
    }
    if extra.open_files.is_some() {
        into.open_files = extra.open_files;
    }
}

fn write_report(dest: &ReportDest, report: &RunReport) -> Result<(), String> {
    let json = report.to_json().map_err(|error| error.to_string())?;
    match dest {
        ReportDest::Stderr => {
            let mut out = io::stderr();
            writeln!(out, "{json}").map_err(|error| format!("write report: {error}"))?;
        }
        ReportDest::Stdout => {
            println!("{json}");
        }
        ReportDest::File(path) => {
            fs::write(path, format!("{json}\n"))
                .map_err(|error| format!("write report `{}`: {error}", path.display()))?;
        }
    }
    Ok(())
}

fn exit_from_status(status: std::process::ExitStatus) -> ExitCode {
    if let Some(code) = status.code() {
        return ExitCode::from(code as u8);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return ExitCode::from(128u8.saturating_add(sig as u8));
        }
    }
    ExitCode::from(1)
}

fn fail(code: u8, message: &str) -> ExitCode {
    eprintln!("kekkai: {message}");
    ExitCode::from(code)
}

fn parse_u64(value: &OsString) -> Option<u64> {
    value.to_str()?.parse().ok()
}

fn parse_backend(value: &OsString) -> Option<Backend> {
    match value.to_str()? {
        "none" => Some(Backend::None),
        "rlimit" => Some(Backend::Rlimit),
        "linux_native" => Some(Backend::LinuxNative),
        "macos" => Some(Backend::Macos),
        "userspace" => Some(Backend::Userspace),
        _ => None,
    }
}

fn parse_syscall_profile(value: &OsString) -> Option<SyscallProfile> {
    match value.to_str()? {
        "default" => Some(SyscallProfile::Default),
        "strict" => Some(SyscallProfile::Strict),
        "python" => Some(SyscallProfile::Python),
        _ => None,
    }
}

fn parse_namespaces(value: &OsString) -> Option<Namespaces> {
    match value.to_str()? {
        "off" => Some(Namespaces::Off),
        "isolate" => Some(Namespaces::Isolate),
        _ => None,
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileSettings {
    backend: Option<String>,
    network: Option<NetworkSpec>,
    limits: Option<LimitsFile>,
    inputs: Option<Vec<PathBuf>>,
    output: Option<PathBuf>,
    readable_roots: Option<Vec<PathBuf>>,
    writable_roots: Option<Vec<PathBuf>>,
    devices: Option<Vec<PathBuf>>,
    cgroup: Option<CgroupFile>,
    cgroup_root: Option<PathBuf>,
    namespaces: Option<String>,
    filesystem_view: Option<ViewSpec>,
    syscall_profile: Option<String>,
    guest_helper: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum NetworkSpec {
    Name(String),
    Allowlist { allowlist: Vec<AllowHostFile> },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowHostFile {
    host: String,
    port: Option<u16>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitsFile {
    cpu_time_secs: Option<u64>,
    memory_mb: Option<u64>,
    user_processes: Option<u64>,
    file_size_mb: Option<u64>,
    open_files: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct CgroupFile {
    memory_max: Option<u64>,
    memory_high: Option<u64>,
    pids_max: Option<u64>,
    cpu_quota_us: Option<u64>,
    cpu_period_us: Option<u64>,
    cpu_weight: Option<u64>,
    io_max: Option<IoMaxFile>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct IoMaxFile {
    major: u32,
    minor: u32,
    rbps: Option<u64>,
    wbps: Option<u64>,
    riops: Option<u64>,
    wiops: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ViewSpec {
    Name(String),
    Isolate { isolate: OverlaySpec },
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum OverlaySpec {
    Discard(String),
    Keep { keep: PathBuf },
}

impl FileSettings {
    fn into_settings(self) -> Result<Settings, String> {
        let mut settings = Settings::builder()
            .backend(match self.backend.as_deref() {
                None => Backend::None,
                Some("none") => Backend::None,
                Some("rlimit") => Backend::Rlimit,
                Some("linux_native") => Backend::LinuxNative,
                Some("macos") => Backend::Macos,
                Some("userspace") => Backend::Userspace,
                Some(other) => {
                    return Err(format!(
                        "settings backend `{other}` (none|rlimit|linux_native|macos|userspace)"
                    ));
                }
            })
            .build();
        if let Some(spec) = self.network {
            settings.network = match spec {
                NetworkSpec::Name(name) => match name.as_str() {
                    "deny" => Network::Deny,
                    "allow" => Network::Allow,
                    "loopback" => Network::Loopback,
                    other => {
                        return Err(format!(
                            "settings network `{other}` (deny|allow|loopback|{{allowlist}})"
                        ));
                    }
                },
                NetworkSpec::Allowlist { allowlist } => Network::Allowlist(
                    allowlist
                        .into_iter()
                        .map(|item| AllowHost {
                            host: item.host,
                            port: item.port,
                        })
                        .collect(),
                ),
            };
        }
        if let Some(limits) = self.limits {
            settings.limits = Limits {
                cpu_time_secs: limits.cpu_time_secs,
                memory_mb: limits.memory_mb,
                user_processes: limits.user_processes,
                file_size_mb: limits.file_size_mb,
                open_files: limits.open_files,
            };
        }
        if let Some(inputs) = self.inputs {
            settings.inputs = inputs;
        }
        if self.output.is_some() {
            settings.output = self.output;
        }
        if let Some(paths) = self.readable_roots {
            settings.readable_roots = paths;
        }
        if let Some(paths) = self.writable_roots {
            settings.writable_roots = paths;
        }
        if let Some(paths) = self.devices {
            settings.devices = paths;
        }
        if let Some(cgroup) = self.cgroup {
            settings.cgroup = CgroupLimits {
                memory_max: cgroup.memory_max,
                memory_high: cgroup.memory_high,
                pids_max: cgroup.pids_max,
                cpu_quota_us: cgroup.cpu_quota_us,
                cpu_period_us: cgroup.cpu_period_us,
                cpu_weight: cgroup.cpu_weight,
                io_max: cgroup.io_max.map(|io| IoMax {
                    major: io.major,
                    minor: io.minor,
                    rbps: io.rbps,
                    wbps: io.wbps,
                    riops: io.riops,
                    wiops: io.wiops,
                }),
            };
        }
        if self.cgroup_root.is_some() {
            settings.cgroup_root = self.cgroup_root;
        }
        if let Some(name) = self.namespaces {
            settings.namespaces = match name.as_str() {
                "off" => Namespaces::Off,
                "isolate" => Namespaces::Isolate,
                other => return Err(format!("settings namespaces `{other}` (off|isolate)")),
            };
        }
        if let Some(view) = self.filesystem_view {
            settings.filesystem_view = match view {
                ViewSpec::Name(name) if name == "host" => FilesystemView::Host,
                ViewSpec::Name(other) => {
                    return Err(format!(
                        "settings filesystem_view `{other}` (host|{{isolate}})"
                    ));
                }
                ViewSpec::Isolate { isolate } => match isolate {
                    OverlaySpec::Discard(name) if name == "discard" => FilesystemView::Isolate {
                        overlay: OverlayPersist::Discard,
                    },
                    OverlaySpec::Discard(other) => {
                        return Err(format!(
                            "settings filesystem_view isolate `{other}` (discard|{{keep}})"
                        ));
                    }
                    OverlaySpec::Keep { keep } => FilesystemView::Isolate {
                        overlay: OverlayPersist::Keep(keep),
                    },
                },
            };
        }
        if let Some(name) = self.syscall_profile {
            settings.syscall_profile = match name.as_str() {
                "default" => SyscallProfile::Default,
                "strict" => SyscallProfile::Strict,
                "python" => SyscallProfile::Python,
                other => {
                    return Err(format!(
                        "settings syscall_profile `{other}` (default|strict|python)"
                    ));
                }
            };
        }
        if self.guest_helper.is_some() {
            settings.guest_helper = self.guest_helper;
        }
        Ok(settings)
    }
}
