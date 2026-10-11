//! Violation reporting on the shipped [`Sandbox::prepare`] / [`apply`] path.
//!
//! Kernel-dependent cases print `skip: ...` and return. They never treat an
//! empty `violations` list as a clean run when `violations_observed` is false.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use kekkai::{Backend, Health, Sandbox, Settings, ViolationKind};

fn skip(reason: &str) {
    eprintln!("skip: {reason}");
}

fn probe_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kekkai-probe"))
}

fn linux_native_ready() -> Option<(Settings, tempfile::TempDir, PathBuf)> {
    if !cfg!(target_os = "linux") {
        skip("violation tests require Linux");
        return None;
    }
    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("ws");
    fs::create_dir_all(&workspace).unwrap();
    let mut settings = Settings {
        backend: Backend::LinuxNative,
        ..Settings::default()
    };
    let probe_dir = probe_exe()
        .parent()
        .expect("kekkai-probe has a parent directory")
        .to_path_buf();
    settings.readable_roots.push(probe_dir);
    match kekkai::health(&settings) {
        Health::Ok(_) => Some((settings, tmp, workspace)),
        Health::Warning(message) | Health::Error(message) => {
            skip(&format!("linux_native unavailable: {message}"));
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

#[test]
fn health_reports_violation_capability() {
    let settings = Settings {
        backend: Backend::LinuxNative,
        ..Settings::default()
    };
    match kekkai::health(&settings) {
        Health::Ok(message) => {
            assert!(
                message.contains("violations=user_notif")
                    || message.contains("violations=unavailable"),
                "{message}"
            );
            assert!(message.contains("fs_violations=unavailable"), "{message}");
        }
        Health::Error(_) => skip("linux_native unavailable"),
        Health::Warning(message) => panic!("linux_native must not warn: {message}"),
    }
}

#[test]
fn socket_denial_is_reported_as_a_syscall_violation() {
    let Some((settings, _tmp, workspace)) = linux_native_ready() else {
        return;
    };
    if !kekkai::capabilities().seccomp_user_notif {
        skip("seccomp user notification unavailable");
        return;
    }
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let output = run(&sandbox, probe(&["socket"]));
    assert!(
        !output.status.success(),
        "socket() succeeded: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let usage = sandbox.finish();
    assert!(
        usage.violations_observed,
        "kernel denials were not observed: {usage:?}"
    );
    assert!(
        usage
            .violations
            .iter()
            .any(|v| v.kind == ViolationKind::Syscall && v.detail == "socket" && v.count >= 1),
        "socket denial was not reported: {usage:?}"
    );
}

#[test]
fn clean_run_reports_no_violations() {
    let Some((settings, _tmp, workspace)) = linux_native_ready() else {
        return;
    };
    if !kekkai::capabilities().seccomp_user_notif {
        skip("seccomp user notification unavailable");
        return;
    }
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let inside = workspace.join("ok.txt");
    let output = run(&sandbox, probe(&["write", inside.to_str().unwrap()]));
    assert!(
        output.status.success(),
        "clean write failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let usage = sandbox.finish();
    assert!(
        usage.violations_observed,
        "kernel denials were not observed: {usage:?}"
    );
    assert!(
        usage.violations.is_empty(),
        "clean run reported violations: {usage:?}"
    );
}

#[test]
fn filesystem_denials_are_unavailable_not_an_empty_success() {
    let Some((settings, tmp, workspace)) = linux_native_ready() else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let outside = tmp.path().join("outside.txt");
    let output = run(&sandbox, probe(&["write", outside.to_str().unwrap()]));
    assert!(!outside.exists());
    assert!(!output.status.success());
    let usage = sandbox.finish();
    assert!(
        !usage
            .violations
            .iter()
            .any(|v| v.kind == ViolationKind::Filesystem),
        "filesystem violations must not be invented without an observer: {usage:?}"
    );
    let report = kekkai::health(&settings);
    match report {
        Health::Ok(message) | Health::Warning(message) => {
            assert!(message.contains("fs_violations=unavailable"), "{message}");
        }
        Health::Error(message) => skip(&format!("health error: {message}")),
    }
}
