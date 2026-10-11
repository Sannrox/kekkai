//! Device grants on the shipped [`Sandbox::prepare`] / [`apply`] path.

use std::fs;
use std::path::{Path, PathBuf};
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
        skip("device grant tests require Linux");
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

fn sample_device() -> Option<&'static Path> {
    let path = Path::new("/dev/full");
    if path.exists() {
        Some(path)
    } else {
        skip("/dev/full is missing");
        None
    }
}

#[test]
fn ungranted_device_is_denied() {
    let Some((settings, _tmp, workspace)) = linux_native_ready() else {
        return;
    };
    let Some(device) = sample_device() else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let output = run(&sandbox, probe(&["open", device.to_str().unwrap()]));
    assert!(
        !output.status.success(),
        "ungranted device was opened: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn granted_device_is_usable() {
    let Some((mut settings, _tmp, workspace)) = linux_native_ready() else {
        return;
    };
    let Some(device) = sample_device() else {
        return;
    };
    settings.devices.push(device.to_path_buf());
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let output = run(&sandbox, probe(&["open", device.to_str().unwrap()]));
    assert!(
        output.status.success(),
        "granted device was denied: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn missing_device_is_invalid() {
    let Some((mut settings, _tmp, workspace)) = linux_native_ready() else {
        return;
    };
    settings
        .devices
        .push(PathBuf::from("/no/such/kekkai-device"));
    let error = Sandbox::prepare(&settings, &workspace).expect_err("prepare");
    assert!(
        matches!(error, kekkai::Error::Invalid { ref message } if message.contains("device")),
        "{error}"
    );
}

#[test]
fn regular_file_is_not_a_device_grant() {
    let Some((mut settings, tmp, workspace)) = linux_native_ready() else {
        return;
    };
    let file = tmp.path().join("not-a-device");
    fs::write(&file, b"nope").unwrap();
    settings.devices.push(file);
    let error = Sandbox::prepare(&settings, &workspace).expect_err("prepare");
    assert!(
        matches!(error, kekkai::Error::Invalid { ref message } if message.contains("device")),
        "{error}"
    );
}
