//! Userspace guest adapter: apply is invalid, missing helper is unavailable,
//! denials run inside the helper.

#![cfg(feature = "guest")]

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use kekkai::{Backend, CaptureKeep, CaptureLimits, Error, Health, Network, Sandbox, Settings};

fn skip(reason: &str) {
    eprintln!("skip: {reason}");
}

fn helper_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kekkai-guest"))
}

fn probe_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kekkai-probe"))
}

fn userspace_settings() -> Settings {
    let mut settings = Settings::builder().backend(Backend::Userspace).build();
    settings.guest_helper = Some(helper_exe());
    let probe_dir = probe_exe()
        .parent()
        .expect("kekkai-probe has a parent directory")
        .to_path_buf();
    settings.readable_roots.push(probe_dir);
    settings
}

fn userspace_ready() -> Option<(Settings, tempfile::TempDir, PathBuf)> {
    if !cfg!(target_os = "linux") {
        skip("userspace denial tests require Linux");
        return None;
    }
    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("ws");
    fs::create_dir_all(&workspace).unwrap();
    let settings = userspace_settings();
    match kekkai::health(&settings) {
        Health::Ok(_) => Some((settings, tmp, workspace)),
        Health::Warning(message) | Health::Error(message) => {
            skip(&format!("userspace unavailable: {message}"));
            None
        }
        _ => {
            skip("unrecognized health variant");
            None
        }
    }
}

fn run(sandbox: &Sandbox, program: PathBuf, args: &[&str]) -> Output {
    let mut cmd = sandbox.command(program).expect("guest command");
    cmd.args(args);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.output().expect("spawn guest child")
}

#[test]
fn apply_on_userspace_is_invalid() {
    let Some((settings, _tmp, workspace)) = userspace_ready() else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let mut command = Command::new("true");
    let error = sandbox.apply(&mut command).expect_err("apply");
    assert!(
        matches!(error, Error::Invalid { ref message } if message.contains("spawn")),
        "{error}"
    );
}

#[test]
fn missing_helper_is_unavailable() {
    if !cfg!(target_os = "linux") {
        skip("missing-helper Unavailable is a Linux health mapping");
        return;
    }
    let settings = Settings::builder()
        .backend(Backend::Userspace)
        .guest_helper(Some(PathBuf::from("/no/such/kekkai-guest-helper")))
        .build();
    let error = Sandbox::prepare(&settings, ".").expect_err("prepare");
    assert!(
        matches!(
            error,
            Error::Unavailable {
                backend: Backend::Userspace,
                ref message
            } if message.contains("missing")
        ),
        "{error}"
    );
}

#[test]
fn userspace_is_unsupported_off_linux() {
    if cfg!(target_os = "linux") {
        skip("unsupported mapping is for non-Linux hosts");
        return;
    }
    let settings = userspace_settings();
    let error = Sandbox::prepare(&settings, ".").expect_err("prepare");
    assert!(
        matches!(
            error,
            Error::Unsupported {
                backend: Backend::Userspace,
                ..
            }
        ),
        "{error}"
    );
}

#[test]
fn spawn_runs_the_payload_inside_the_guest() {
    let Some((settings, _tmp, workspace)) = userspace_ready() else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let inside = workspace.join("spawned.txt");
    let mut child = sandbox
        .spawn(probe_exe(), ["write", inside.to_str().unwrap()])
        .expect("spawn");
    let status = child.wait().expect("wait");
    assert!(status.success(), "spawned child failed");
    assert_eq!(fs::read(&inside).expect("read inside"), b"pwned\n");
}

#[test]
fn write_outside_the_guest_is_denied() {
    let Some((settings, tmp, workspace)) = userspace_ready() else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let outside = tmp.path().join("outside.txt");
    let output = run(&sandbox, probe_exe(), &["write", outside.to_str().unwrap()]);
    assert!(!outside.exists(), "write escaped to {}", outside.display());
    assert!(
        !output.status.success(),
        "child succeeded writing outside the workspace: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn write_inside_the_guest_is_allowed() {
    let Some((settings, _tmp, workspace)) = userspace_ready() else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let inside = workspace.join("inside.txt");
    let output = run(&sandbox, probe_exe(), &["write", inside.to_str().unwrap()]);
    assert!(
        output.status.success(),
        "child failed writing inside the workspace: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(&inside).expect("read inside"), b"pwned\n");
}

#[test]
fn socket_inside_the_guest_is_denied() {
    let Some((mut settings, _tmp, workspace)) = userspace_ready() else {
        return;
    };
    settings.network = Network::Deny;
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let output = run(&sandbox, probe_exe(), &["socket"]);
    assert!(
        !output.status.success(),
        "child created a socket inside the guest: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn spawn_with_deadline_forwards_env_and_cwd() {
    let Some((settings, _tmp, workspace)) = userspace_ready() else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    fs::write(workspace.join("cwd-marker"), "ok").unwrap();

    let mut cwd = Command::new(probe_exe());
    cwd.args(["read", "cwd-marker"]);
    cwd.current_dir(&workspace);
    let (status, _usage, stdout, stderr) = sandbox
        .spawn_with_deadline_captured(
            &mut cwd,
            Duration::from_secs(5),
            Duration::from_millis(50),
            CaptureLimits {
                stdout_max: Some(64),
                stderr_max: Some(256),
                keep: CaptureKeep::Head,
            },
        )
        .expect("cwd spawn");
    assert!(
        status.success(),
        "guest wrap dropped cwd: stderr={}",
        String::from_utf8_lossy(&stderr.bytes)
    );
    assert_eq!(stdout.bytes, b"ok");

    let mut env_cmd = Command::new(probe_exe());
    env_cmd.args(["env", "KEKKAI_TEST_GUEST_ENV"]);
    env_cmd.env("KEKKAI_TEST_GUEST_ENV", "copied");
    env_cmd.current_dir(&workspace);
    let (status, _usage, stdout, stderr) = sandbox
        .spawn_with_deadline_captured(
            &mut env_cmd,
            Duration::from_secs(5),
            Duration::from_millis(50),
            CaptureLimits {
                stdout_max: Some(64),
                stderr_max: Some(256),
                keep: CaptureKeep::Head,
            },
        )
        .expect("env spawn");
    assert!(
        status.success(),
        "guest wrap dropped env: stderr={}",
        String::from_utf8_lossy(&stderr.bytes)
    );
    assert_eq!(stdout.bytes, b"copied\n");
}

#[test]
fn spawn_with_deadline_times_out_a_sleeping_guest() {
    let Some((settings, _tmp, workspace)) = userspace_ready() else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let mut command = Command::new("/bin/sleep");
    command.arg("30");
    let (status, usage) = sandbox
        .spawn_with_deadline(
            &mut command,
            Duration::from_millis(200),
            Duration::from_millis(400),
        )
        .expect("deadline spawn");
    assert!(usage.timed_out, "{usage:?}");
    assert!(!status.success(), "{status:?}");
}

#[test]
fn spawn_with_deadline_captured_reads_payload_stdout() {
    let Some((settings, _tmp, workspace)) = userspace_ready() else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let mut command = Command::new("/bin/echo");
    command.arg("hello-guest");
    let (status, _usage, stdout, _stderr) = sandbox
        .spawn_with_deadline_captured(
            &mut command,
            Duration::from_secs(5),
            Duration::from_millis(50),
            CaptureLimits {
                stdout_max: Some(64),
                stderr_max: None,
                keep: CaptureKeep::Head,
            },
        )
        .expect("captured spawn");
    assert!(status.success(), "echo through the helper failed");
    assert_eq!(stdout.bytes, b"hello-guest\n");
}

#[test]
fn missing_workspace_is_invalid_on_userspace() {
    let Some((settings, _tmp, _workspace)) = userspace_ready() else {
        return;
    };
    let error =
        Sandbox::prepare(&settings, "/no/such/kekkai-userspace-workspace").expect_err("prepare");
    assert!(
        matches!(error, Error::Invalid { ref message } if message.contains("workspace")),
        "{error}"
    );
}

#[test]
fn userspace_does_not_downgrade_when_helper_is_missing() {
    if !cfg!(target_os = "linux") {
        skip("downgrade check is Linux Unavailable");
        return;
    }
    let settings = Settings::builder()
        .backend(Backend::Userspace)
        .guest_helper(Some(PathBuf::from("/no/such/kekkai-guest-helper")))
        .build();
    match kekkai::health(&settings) {
        Health::Error(message) => assert!(message.contains("missing"), "{message}"),
        other => panic!("expected health error, got {other:?}"),
    }
    let error = Sandbox::prepare(&settings, ".").expect_err("prepare");
    assert!(
        !matches!(error, Error::Invalid { .. }),
        "missing helper must not look like a settings mistake: {error}"
    );
    assert!(
        matches!(
            error,
            Error::Unavailable {
                backend: Backend::Userspace,
                ..
            }
        ),
        "{error}"
    );
}
