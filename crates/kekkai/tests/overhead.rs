//! Smoke the `/bin/true` payload the overhead bench drives through
//! [`Sandbox::prepare`] / [`apply`] / [`Sandbox::finish`].

use std::process::{Command, Stdio};

use kekkai::{Backend, Health, Sandbox, Settings};

fn skip(reason: &str) {
    eprintln!("skip: {reason}");
}

fn true_bin() -> &'static str {
    if std::path::Path::new("/bin/true").exists() {
        "/bin/true"
    } else if std::path::Path::new("/usr/bin/true").exists() {
        "/usr/bin/true"
    } else {
        panic!("need /bin/true or /usr/bin/true");
    }
}

fn payload() -> Command {
    let mut cmd = Command::new(true_bin());
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());
    cmd
}

fn run(settings: Settings, workspace: &std::path::Path) {
    let sandbox = Sandbox::prepare(&settings, workspace).expect("prepare");
    let mut cmd = payload();
    sandbox.apply(&mut cmd).expect("apply");
    let status = cmd.status().expect("spawn");
    assert!(status.success(), "{} failed: {status}", true_bin());
    let _ = sandbox.finish();
}

#[test]
fn none_runs_true() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("ws");
    std::fs::create_dir_all(&workspace).unwrap();
    run(
        Settings::builder().backend(Backend::None).build(),
        &workspace,
    );
}

#[test]
fn linux_native_runs_true() {
    if !cfg!(target_os = "linux") {
        skip("linux_native overhead smoke requires Linux");
        return;
    }
    let settings = Settings::builder().backend(Backend::LinuxNative).build();
    match kekkai::health(&settings) {
        Health::Ok(_) => {}
        Health::Warning(message) | Health::Error(message) => {
            skip(&format!("linux_native unavailable: {message}"));
            return;
        }
        _ => {
            skip("unrecognized health variant");
            return;
        }
    }
    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("ws");
    std::fs::create_dir_all(&workspace).unwrap();
    run(settings, &workspace);
}
