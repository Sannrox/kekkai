//! Userspace guest adapter: a helper owns spawn (ADR 0003).

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(feature = "guest")]
use std::process::ExitCode;

#[cfg(feature = "guest")]
use crate::{Backend, Limits, Sandbox};
use crate::{Error, Network, Settings};

/// Default helper file name on `PATH` and `KEKKAI_GUEST_HELPER`.
pub(crate) const HELPER_NAME: &str = "kekkai-guest";

pub(crate) fn resolve_helper(settings: &Settings) -> Result<PathBuf, String> {
    if let Some(path) = &settings.guest_helper {
        return require_helper(path);
    }
    if let Some(path) = env::var_os("KEKKAI_GUEST_HELPER") {
        return require_helper(Path::new(&path));
    }
    find_on_path(HELPER_NAME).ok_or_else(|| {
        format!("guest helper `{HELPER_NAME}` not found on PATH or KEKKAI_GUEST_HELPER")
    })
}

fn require_helper(path: &Path) -> Result<PathBuf, String> {
    match fs::metadata(path) {
        Ok(meta) if meta.is_file() => fs::canonicalize(path)
            .map_err(|_| format!("guest helper `{}` is missing", path.display())),
        Ok(_) => Err(format!("guest helper `{}` is not a file", path.display())),
        Err(_) => Err(format!("guest helper `{}` is missing", path.display())),
    }
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path).find_map(|dir| require_helper(&dir.join(name)).ok())
}

fn absolute_workspace(workspace: &Path) -> PathBuf {
    fs::canonicalize(workspace).unwrap_or_else(|_| {
        if workspace.is_absolute() {
            workspace.to_path_buf()
        } else {
            env::current_dir()
                .map(|cwd| cwd.join(workspace))
                .unwrap_or_else(|_| workspace.to_path_buf())
        }
    })
}

fn helper_argv(
    helper: &Path,
    workspace: &Path,
    settings: &Settings,
    program: impl AsRef<OsStr>,
    args: impl IntoIterator<Item = impl AsRef<OsStr>>,
) -> Vec<OsString> {
    let workspace = absolute_workspace(workspace);
    let mut argv = vec![
        helper.as_os_str().to_os_string(),
        OsString::from("--workspace"),
        workspace.into_os_string(),
    ];
    if let Some(output) = &settings.output {
        argv.push(OsString::from("--output"));
        argv.push(output.as_os_str().to_os_string());
    }
    argv.push(OsString::from("--network"));
    argv.push(OsString::from(match settings.network {
        Network::Allow => "allow",
        Network::Deny | Network::Allowlist(_) | Network::Loopback => "deny",
    }));
    for path in &settings.inputs {
        argv.push(OsString::from("--input"));
        argv.push(path.as_os_str().to_os_string());
    }
    for path in &settings.readable_roots {
        argv.push(OsString::from("--readable"));
        argv.push(path.as_os_str().to_os_string());
    }
    for path in &settings.writable_roots {
        argv.push(OsString::from("--writable"));
        argv.push(path.as_os_str().to_os_string());
    }
    if let Some(value) = settings.limits.cpu_time_secs {
        argv.push(OsString::from("--cpu-time-secs"));
        argv.push(OsString::from(value.to_string()));
    }
    if let Some(value) = settings.limits.memory_mb {
        argv.push(OsString::from("--memory-mb"));
        argv.push(OsString::from(value.to_string()));
    }
    if let Some(value) = settings.limits.user_processes {
        argv.push(OsString::from("--user-processes"));
        argv.push(OsString::from(value.to_string()));
    }
    if let Some(value) = settings.limits.file_size_mb {
        argv.push(OsString::from("--file-size-mb"));
        argv.push(OsString::from(value.to_string()));
    }
    if let Some(value) = settings.limits.open_files {
        argv.push(OsString::from("--open-files"));
        argv.push(OsString::from(value.to_string()));
    }
    argv.push(OsString::from("--"));
    argv.push(program.as_ref().to_os_string());
    argv.extend(args.into_iter().map(|arg| arg.as_ref().to_os_string()));
    argv
}

pub(crate) fn wrap_command(
    helper: &Path,
    workspace: &Path,
    settings: &Settings,
    program: impl AsRef<OsStr>,
    args: impl IntoIterator<Item = impl AsRef<OsStr>>,
) -> Command {
    let argv = helper_argv(helper, workspace, settings, program, args);
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        cmd.process_group(0);
    }
    cmd
}

/// Exec the helper from `command`'s `pre_exec` so env, cwd, stdio, and uid stay.
pub(crate) fn wrap_into_command(
    helper: &Path,
    workspace: &Path,
    settings: &Settings,
    command: &mut Command,
) -> Result<(), Error> {
    let argv = helper_argv(
        helper,
        workspace,
        settings,
        command.get_program(),
        command.get_args(),
    );
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::process::CommandExt as _;

        let cstrings = argv
            .iter()
            .map(|arg| {
                CString::new(arg.as_bytes())
                    .map_err(|_| Error::invalid("guest helper argument contains an interior NUL"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut ptrs: Vec<usize> = cstrings.iter().map(|s| s.as_ptr() as usize).collect();
        ptrs.push(0);
        command.process_group(0);
        // SAFETY: `pre_exec` runs after fork. `execv` is async-signal-safe and
        // uses the environment the standard library already installed.
        // `ptrs` stores addresses of `cstrings`, which the closure owns.
        unsafe {
            command.pre_exec(move || {
                let _keep = &cstrings;
                libc::execv(
                    ptrs[0] as *const libc::c_char,
                    ptrs.as_ptr() as *const *const libc::c_char,
                );
                Err(std::io::Error::last_os_error())
            });
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = argv;
        let _ = command;
        Err(Error::unsupported(
            crate::Backend::Userspace,
            "guest helper wrap requires Unix",
        ))
    }
}

pub(crate) fn missing_helper_error(message: String) -> Error {
    Error::unavailable(crate::Backend::Userspace, message)
}

#[cfg(feature = "guest")]
fn usage() -> ExitCode {
    eprintln!(
        "usage: kekkai-guest --workspace DIR [--output DIR] [--network deny|allow] [--input DIR]... [--readable DIR]... [--writable DIR]... [--cpu-time-secs N] [--memory-mb N] [--user-processes N] [--file-size-mb N] [--open-files N] -- PROGRAM [ARGS...]"
    );
    ExitCode::from(2)
}

#[cfg(feature = "guest")]
fn parse_u64(value: &OsString) -> Option<u64> {
    value.to_str()?.parse().ok()
}

#[cfg(feature = "guest")]
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

/// Helper protocol: spawn the payload, wait, then drop the sandbox.
#[cfg(feature = "guest")]
pub(crate) fn run() -> ExitCode {
    let mut workspace = None;
    let mut output = None;
    let mut network = Network::Deny;
    let mut inputs = Vec::new();
    let mut readable = Vec::new();
    let mut writable = Vec::new();
    let mut limits = Limits::default();
    let mut program: Option<OsString> = None;
    let mut args: Vec<OsString> = Vec::new();

    let mut argv = env::args_os().skip(1);
    while let Some(arg) = argv.next() {
        if arg == "--" {
            program = argv.next();
            args = argv.collect();
            break;
        }
        let Some(flag) = arg.to_str() else {
            return usage();
        };
        let Some(value) = argv.next() else {
            return usage();
        };
        match flag {
            "--workspace" => workspace = Some(PathBuf::from(value)),
            "--output" => output = Some(PathBuf::from(value)),
            "--network" => {
                network = match value.to_str() {
                    Some("allow") => Network::Allow,
                    Some("deny") => Network::Deny,
                    _ => return usage(),
                };
            }
            "--input" => inputs.push(PathBuf::from(value)),
            "--readable" => readable.push(PathBuf::from(value)),
            "--writable" => writable.push(PathBuf::from(value)),
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
            _ => return usage(),
        }
    }

    let Some(workspace) = workspace else {
        return usage();
    };
    let Some(program) = program else {
        return usage();
    };

    let settings = Settings::builder()
        .backend(Backend::LinuxNative)
        .network(network)
        .inputs(inputs)
        .output(output)
        .readable_roots(readable)
        .writable_roots(writable)
        .limits(limits)
        .build();
    let sandbox = match Sandbox::prepare(&settings, &workspace) {
        Ok(sandbox) => sandbox,
        Err(error) => {
            eprintln!("kekkai-guest prepare: {error}");
            return ExitCode::from(1);
        }
    };
    let mut cmd = Command::new(program);
    cmd.args(args);
    if let Err(error) = sandbox.apply_helper_payload(&mut cmd) {
        eprintln!("kekkai-guest apply: {error}");
        return ExitCode::from(1);
    }
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(error) => {
            eprintln!("kekkai-guest spawn: {error}");
            return ExitCode::from(1);
        }
    };
    #[cfg(unix)]
    {
        // SAFETY: the payload already exec'd with SIG_DFL. Ignore SIGTERM
        // in the helper so a library group SIGTERM kills the payload while
        // the helper waits and drops scratch.
        unsafe {
            libc::signal(libc::SIGTERM, libc::SIG_IGN);
        }
    }
    let status = match child.wait() {
        Ok(status) => status,
        Err(error) => {
            eprintln!("kekkai-guest wait: {error}");
            return ExitCode::from(1);
        }
    };
    exit_from_status(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Limits;

    #[test]
    fn wrap_forwards_memory_limit() {
        let settings = Settings {
            limits: Limits {
                memory_mb: Some(64),
                ..Limits::default()
            },
            ..Settings::default()
        };
        let cmd = wrap_command(
            Path::new("/helper"),
            Path::new("/workspace"),
            &settings,
            "true",
            std::iter::empty::<&OsStr>(),
        );
        let args: Vec<String> = cmd
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert!(
            args.windows(2)
                .any(|pair| pair[0] == "--memory-mb" && pair[1] == "64"),
            "{args:?}"
        );
    }

    #[test]
    fn wrap_into_command_keeps_env_and_cwd() {
        let settings = Settings::default();
        let mut original = Command::new("true");
        original.env("KEKKAI_TEST_GUEST_ENV", "copied");
        original.env_remove("KEKKAI_TEST_GUEST_REMOVED");
        original.current_dir("/tmp");
        wrap_into_command(
            Path::new("/helper"),
            Path::new("/workspace"),
            &settings,
            &mut original,
        )
        .expect("wrap");
        let envs: Vec<(String, Option<String>)> = original
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect();
        assert!(
            envs.iter()
                .any(|(key, value)| key == "KEKKAI_TEST_GUEST_ENV"
                    && value.as_deref() == Some("copied")),
            "{envs:?}"
        );
        assert!(
            envs.iter()
                .any(|(key, value)| key == "KEKKAI_TEST_GUEST_REMOVED" && value.is_none()),
            "{envs:?}"
        );
        assert_eq!(original.get_current_dir(), Some(Path::new("/tmp")));
    }

    #[test]
    fn resolve_helper_canonicalizes_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let helper = dir.path().join("kekkai-guest");
        fs::write(&helper, b"").unwrap();
        let dotted = dir.path().join(".").join("kekkai-guest");
        let settings = Settings {
            guest_helper: Some(dotted),
            ..Settings::default()
        };
        let resolved = resolve_helper(&settings).expect("resolve");
        let canonical = fs::canonicalize(&helper).expect("canonicalize");
        assert_eq!(resolved, canonical);
        assert!(resolved.is_absolute());
    }

    #[test]
    fn wrap_command_passes_an_absolute_workspace() {
        let cmd = wrap_command(
            Path::new("/helper"),
            Path::new("."),
            &Settings::default(),
            "true",
            std::iter::empty::<&OsStr>(),
        );
        let args: Vec<String> = cmd
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        let workspace = args
            .windows(2)
            .find(|pair| pair[0] == "--workspace")
            .map(|pair| pair[1].as_str())
            .expect("workspace flag");
        assert!(
            Path::new(workspace).is_absolute(),
            "workspace must be absolute, got {workspace}"
        );
    }
}
