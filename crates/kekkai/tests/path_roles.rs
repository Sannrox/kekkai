//! Path-role tests for the shipped [`Sandbox::prepare`] / [`apply`] path.
//!
//! Kernel-dependent cases print `skip: ...` and return when the host cannot
//! enforce `linux_native`. They never assert success without running the child.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use kekkai::{Backend, Health, Sandbox, Settings};

fn skip(reason: &str) {
    eprintln!("skip: {reason}");
}

fn probe_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kekkai-probe"))
}

fn linux_native_ready() -> Option<(Settings, tempfile::TempDir, PathBuf)> {
    if !cfg!(target_os = "linux") {
        skip("path role tests require Linux");
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
fn write_to_input_is_denied() {
    let Some((mut settings, tmp, workspace)) = linux_native_ready() else {
        return;
    };
    let input = tmp.path().join("in");
    fs::create_dir_all(&input).unwrap();
    let file = input.join("data.txt");
    fs::write(&file, "secret\n").unwrap();
    settings.inputs.push(input);
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let output = run(&sandbox, probe(&["write", file.to_str().unwrap()]));
    assert_eq!(fs::read_to_string(&file).unwrap(), "secret\n");
    assert!(
        !output.status.success(),
        "child wrote to an input path: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let read = run(&sandbox, probe(&["read", file.to_str().unwrap()]));
    assert!(
        read.status.success(),
        "input was not readable: stderr={}",
        String::from_utf8_lossy(&read.stderr)
    );
    assert!(String::from_utf8_lossy(&read.stdout).contains("secret"));
}

#[test]
fn output_dir_is_writable_and_workspace_is_not_when_output_is_set() {
    let Some((mut settings, tmp, workspace)) = linux_native_ready() else {
        return;
    };
    let output_dir = tmp.path().join("out");
    fs::create_dir_all(&output_dir).unwrap();
    settings.output = Some(output_dir.clone());
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let dest = output_dir.join("ok.txt");
    let output = run(&sandbox, probe(&["write", dest.to_str().unwrap()]));
    assert!(
        output.status.success(),
        "output write failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(&dest).unwrap(), "pwned\n");
    let ws_file = workspace.join("nope.txt");
    let denied = run(&sandbox, probe(&["write", ws_file.to_str().unwrap()]));
    assert!(
        !denied.status.success(),
        "workspace stayed writable after Settings.output: stderr={}",
        String::from_utf8_lossy(&denied.stderr)
    );
    assert!(!ws_file.exists());
}

#[test]
fn scratch_is_unique_per_run_sets_tmpdir_and_is_cleaned_up() {
    let Some((settings, _tmp, workspace)) = linux_native_ready() else {
        return;
    };
    let first = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let second = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let a = first.scratch_dir().expect("first scratch").to_path_buf();
    let b = second.scratch_dir().expect("second scratch").to_path_buf();
    assert_ne!(a, b, "scratch directories must be unique per prepare");
    assert!(a.is_dir(), "{}", a.display());
    assert!(b.is_dir(), "{}", b.display());

    let env = run(&first, probe(&["env", "TMPDIR"]));
    assert!(
        env.status.success(),
        "TMPDIR missing: stderr={}",
        String::from_utf8_lossy(&env.stderr)
    );
    let tmpdir = String::from_utf8_lossy(&env.stdout).trim().to_string();
    assert_eq!(PathBuf::from(&tmpdir), a);

    let marker = a.join("child.txt");
    let wrote = run(&first, probe(&["write", marker.to_str().unwrap()]));
    assert!(
        wrote.status.success(),
        "scratch write failed: stderr={}",
        String::from_utf8_lossy(&wrote.stderr)
    );

    drop(first);
    drop(second);
    assert!(!a.exists(), "scratch {} was not cleaned up", a.display());
    assert!(!b.exists(), "scratch {} was not cleaned up", b.display());
}
