//! Syscall allowlist profiles on the shipped [`Sandbox::prepare`] / [`apply`]
//! path.
//!
//! Kernel-dependent cases print `skip: ...` and return. They never pass
//! vacuously.

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use kekkai::{Backend, Health, Sandbox, Settings, SyscallProfile, ViolationKind};

fn skip(reason: &str) {
    eprintln!("skip: {reason}");
}

fn probe_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kekkai-probe"))
}

fn linux_native_with(
    profile: SyscallProfile,
    extra_readable: Vec<PathBuf>,
) -> Option<(Settings, tempfile::TempDir, PathBuf)> {
    if !cfg!(target_os = "linux") {
        skip("syscall profile tests require Linux");
        return None;
    }
    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("ws");
    std::fs::create_dir_all(&workspace).unwrap();
    let probe_dir = probe_exe()
        .parent()
        .expect("kekkai-probe has a parent directory")
        .to_path_buf();
    let mut readable = extra_readable;
    readable.push(probe_dir);
    let settings = Settings::builder()
        .backend(Backend::LinuxNative)
        .syscall_profile(profile)
        .readable_roots(readable)
        .build();
    match kekkai::health(&settings) {
        Health::Ok(_) => Some((settings, tmp, workspace)),
        Health::Warning(message) | Health::Error(message) => {
            skip(&format!("linux_native unavailable: {message}"));
            None
        }
        _ => {
            skip("unrecognized health variant");
            None
        }
    }
}

fn run(sandbox: &Sandbox, mut cmd: Command) -> Output {
    sandbox.apply(&mut cmd).expect("apply");
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.output().expect("spawn sandboxed child")
}

fn probe(args: &[&str]) -> Command {
    let mut cmd = Command::new(probe_exe());
    cmd.args(args);
    cmd
}

fn python3() -> Option<PathBuf> {
    let output = Command::new("python3")
        .args(["-c", "import sys; print(sys.executable)"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
}

fn python_readable_roots(python: &std::path::Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    // Do not canonicalize: a venv `bin/python` is a symlink to the system
    // interpreter, and pyvenv.cfg lives in the venv prefix.
    let mut dir = python.parent();
    for _ in 0..2 {
        let Some(d) = dir else { break };
        roots.push(d.to_path_buf());
        dir = d.parent();
    }
    if let Ok(output) = Command::new(python)
        .args(["-c", "import sys; print(sys.prefix)"])
        .output()
        && output.status.success()
    {
        let prefix = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !prefix.is_empty() {
            roots.push(PathBuf::from(prefix));
        }
    }
    roots
}

#[test]
fn health_reports_syscall_profile() {
    let settings = Settings::builder()
        .backend(Backend::LinuxNative)
        .syscall_profile(SyscallProfile::Python)
        .build();
    match kekkai::health(&settings) {
        Health::Ok(message) => {
            assert!(message.contains("syscalls=python"), "{message}");
        }
        Health::Error(_) => skip("linux_native unavailable"),
        Health::Warning(message) => panic!("linux_native must not warn: {message}"),
        _ => skip("unrecognized health variant"),
    }
}

#[test]
fn default_profile_still_allows_personality() {
    let Some((settings, _tmp, workspace)) = linux_native_with(SyscallProfile::Default, Vec::new())
    else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let output = run(&sandbox, probe(&["personality"]));
    assert!(
        output.status.success(),
        "default profile denied personality: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn strict_allows_true() {
    let Some((settings, _tmp, workspace)) = linux_native_with(SyscallProfile::Strict, Vec::new())
    else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let output = run(&sandbox, Command::new("true"));
    assert!(
        output.status.success(),
        "true failed under strict: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn personality_outside_python_is_denied_and_reported() {
    let Some((settings, _tmp, workspace)) = linux_native_with(SyscallProfile::Python, Vec::new())
    else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let output = run(&sandbox, probe(&["personality"]));
    assert!(
        !output.status.success(),
        "personality succeeded under python: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let usage = sandbox.finish();
    if !usage.violations_observed {
        skip("seccomp user notification unavailable");
        return;
    }
    assert!(
        usage.violations.iter().any(|v| {
            v.kind == ViolationKind::Syscall && v.detail == "personality" && v.count >= 1
        }),
        "personality denial was not reported: {usage:?}"
    );
}

#[test]
fn python_profile_still_denies_socket_when_network_is_deny() {
    let Some((settings, _tmp, workspace)) = linux_native_with(SyscallProfile::Python, Vec::new())
    else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let output = run(&sandbox, probe(&["socket"]));
    assert!(
        !output.status.success(),
        "socket() succeeded under python+Network::Deny: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn python_interpreter_runs_under_python_profile() {
    let Some(python) = python3() else {
        skip("python3 not found");
        return;
    };
    let Some((settings, _tmp, workspace)) =
        linux_native_with(SyscallProfile::Python, python_readable_roots(&python))
    else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let mut cmd = Command::new(&python);
    cmd.args(["-c", "print(42)"]);
    let output = run(&sandbox, cmd);
    assert!(
        output.status.success(),
        "python3 -c print failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("42"),
        "python stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn python_duckdb_runs_under_python_profile() {
    let Some(python) = python3() else {
        skip("python3 not found");
        return;
    };
    let probe = Command::new(&python)
        .args(["-c", "import duckdb"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output();
    match probe {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            skip(&format!(
                "duckdb python module missing: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
            return;
        }
        Err(error) => {
            skip(&format!("python3: {error}"));
            return;
        }
    }
    let Some((settings, _tmp, workspace)) =
        linux_native_with(SyscallProfile::Python, python_readable_roots(&python))
    else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let mut cmd = Command::new(&python);
    cmd.args([
        "-c",
        "import duckdb; print(duckdb.sql('select 1').fetchone()[0])",
    ]);
    let output = run(&sandbox, cmd);
    assert!(
        output.status.success(),
        "duckdb failed under python profile: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains('1'),
        "duckdb stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
}
