//! [`kekkai::Host`] snapshot reused across [`Sandbox::prepare_with_host`].

use std::process::{Command, Stdio};

use kekkai::{Backend, Health, Host, Sandbox, Settings};

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

#[test]
fn prepare_with_host_spawns_true() {
    let host = Host::probe();
    let backend = if cfg!(target_os = "linux") {
        Backend::LinuxNative
    } else if cfg!(target_os = "macos") {
        Backend::Macos
    } else {
        Backend::Rlimit
    };
    let settings = Settings::builder().backend(backend).build();
    match host.health(&settings) {
        Health::Ok(_) | Health::Warning(_) => {}
        Health::Error(message) => {
            skip(&format!("{backend} unavailable: {message}"));
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
    let sandbox =
        Sandbox::prepare_with_host(&host, &settings, &workspace).expect("prepare_with_host");
    let mut cmd = Command::new(true_bin());
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    sandbox.apply(&mut cmd).expect("apply");
    let status = cmd.status().expect("spawn");
    assert!(status.success(), "{status}");
    let _ = sandbox.finish();
}

#[test]
fn host_refresh_replaces_the_snapshot() {
    let mut host = Host::probe();
    let first = host.capabilities().clone();
    host.refresh();
    assert_eq!(host.capabilities(), &first);
}
