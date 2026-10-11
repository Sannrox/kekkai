//! Denial tests for the shipped [`Sandbox::prepare`] / [`apply`] path.
//!
//! Kernel-dependent cases print `skip: ...` and return when the host cannot
//! enforce the backend. They never assert success without running the child.
//! The child is `kekkai-probe`. Its build directory is granted as a readable
//! root so Landlock can execute it without copying the ELF (which races with
//! parallel tests on Linux: `ETXTBSY`).

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use kekkai::{Backend, Health, Limits, Network, Sandbox, Settings};

fn skip(reason: &str) {
    eprintln!("skip: {reason}");
}

fn probe_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kekkai-probe"))
}

fn linux_native_ready() -> Option<(Settings, tempfile::TempDir, PathBuf)> {
    if !cfg!(target_os = "linux") {
        skip("linux_native denial tests require Linux");
        return None;
    }
    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("ws");
    fs::create_dir_all(&workspace).unwrap();
    let mut settings = Settings::builder().backend(Backend::LinuxNative).build();
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

#[test]
fn write_outside_allowed_roots_is_denied() {
    let Some((settings, tmp, workspace)) = linux_native_ready() else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let outside = tmp.path().join("outside.txt");
    let output = run(&sandbox, probe(&["write", outside.to_str().unwrap()]));
    assert!(!outside.exists(), "write escaped to {}", outside.display());
    assert!(
        !output.status.success(),
        "child succeeded writing outside the workspace: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn write_inside_workspace_is_allowed() {
    let Some((settings, _tmp, workspace)) = linux_native_ready() else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let inside = workspace.join("ok.txt");
    let output = run(&sandbox, probe(&["write", inside.to_str().unwrap()]));
    assert!(
        output.status.success(),
        "workspace write failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(&inside).unwrap(), "pwned\n");
}

#[test]
fn read_of_non_allowed_root_is_denied() {
    let Some((settings, tmp, workspace)) = linux_native_ready() else {
        return;
    };
    let secret = tmp.path().join("host.secret");
    fs::write(&secret, "plane-token\n").unwrap();
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let output = run(&sandbox, probe(&["read", secret.to_str().unwrap()]));
    assert!(
        !output.status.success(),
        "child read a path outside the allowlist: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("plane-token"),
        "secret leaked on stdout: {stdout}"
    );
}

#[test]
fn extra_readable_root_is_readable() {
    let Some((mut settings, tmp, workspace)) = linux_native_ready() else {
        return;
    };
    let extra = tmp.path().join("toolchain");
    fs::create_dir_all(&extra).unwrap();
    let file = extra.join("tool.txt");
    fs::write(&file, "from-extra\n").unwrap();
    settings.readable_roots.push(extra);
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let output = run(&sandbox, probe(&["read", file.to_str().unwrap()]));
    assert!(
        output.status.success(),
        "readable_roots was not granted: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("from-extra"));
}

#[test]
fn socket_creation_is_denied_when_network_is_off() {
    let Some((settings, _tmp, workspace)) = linux_native_ready() else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let output = run(&sandbox, probe(&["socket"]));
    assert!(
        !output.status.success(),
        "socket() succeeded with network=deny: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn socket_creation_is_allowed_when_network_is_on() {
    let Some((mut settings, _tmp, workspace)) = linux_native_ready() else {
        return;
    };
    settings.network = Network::Allow;
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let output = run(&sandbox, probe(&["socket"]));
    assert!(
        output.status.success(),
        "socket() failed with network=allow: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rlimit_file_size_is_enforced() {
    if !cfg!(unix) {
        skip("rlimit tests require Unix");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("ws");
    fs::create_dir_all(&workspace).unwrap();
    let settings = Settings::builder()
        .backend(Backend::Rlimit)
        .limits(Limits {
            file_size_mb: Some(1),
            ..Limits::default()
        })
        .build();
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let target = workspace.join("big.bin");
    let output = run(
        &sandbox,
        probe(&["write-bytes", target.to_str().unwrap(), "2097152"]),
    );
    let written = fs::metadata(&target).map(|m| m.len()).unwrap_or(0);
    assert!(
        !output.status.success(),
        "RLIMIT_FSIZE was not enforced: status={:?} written={written} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        written <= 1024 * 1024,
        "child wrote {written} bytes under a 1 MiB file-size limit"
    );
}
