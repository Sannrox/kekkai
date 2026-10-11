//! Egress allowlist tests on the shipped prepare/apply path.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::thread;

use kekkai::{AllowHost, Backend, Health, Network, Sandbox, Settings, ViolationKind};

fn skip(reason: &str) {
    eprintln!("skip: {reason}");
}

fn probe_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kekkai-probe"))
}

fn allowlist_ready() -> Option<(Settings, tempfile::TempDir, PathBuf, u16)> {
    if !cfg!(target_os = "linux") {
        skip("allowlist tests require Linux");
        return None;
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        if let Ok((mut client, _)) = listener.accept() {
            let mut buf = [0_u8; 16];
            let _ = client.read(&mut buf);
            let _ = client.write_all(b"ok");
        }
    });
    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("ws");
    fs::create_dir_all(&workspace).unwrap();
    let probe_dir = probe_exe()
        .parent()
        .expect("kekkai-probe has a parent directory")
        .to_path_buf();
    let settings = Settings::builder()
        .backend(Backend::LinuxNative)
        .network(Network::Allowlist(vec![AllowHost {
            host: "127.0.0.1".into(),
            port: Some(port),
        }]))
        .readable_roots(vec![probe_dir])
        .build();
    match kekkai::health(&settings) {
        Health::Ok(_) => Some((settings, tmp, workspace, port)),
        Health::Warning(message) | Health::Error(message) => {
            skip(&format!("allowlist unavailable: {message}"));
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
fn allowed_host_succeeds_through_the_proxy() {
    let Some((settings, _tmp, workspace, port)) = allowlist_ready() else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let sock = sandbox.scratch_dir().unwrap().join("proxy.sock");
    let output = run(
        &sandbox,
        probe(&[
            "proxy-connect",
            sock.to_str().unwrap(),
            "127.0.0.1",
            &port.to_string(),
        ]),
    );
    assert!(
        output.status.success(),
        "allowed CONNECT failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let usage = sandbox.finish();
    assert!(
        usage.violations.is_empty(),
        "clean allowlist run reported violations: {usage:?}"
    );
}

#[test]
fn direct_tcp_is_denied() {
    let Some((settings, _tmp, workspace, port)) = allowlist_ready() else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let output = run(
        &sandbox,
        probe(&["connect-tcp", "127.0.0.1", &port.to_string()]),
    );
    assert!(
        !output.status.success(),
        "direct TCP succeeded under allowlist: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn raw_ip_not_on_the_list_is_denied_and_reported() {
    let Some((settings, _tmp, workspace, _port)) = allowlist_ready() else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let sock = sandbox.scratch_dir().unwrap().join("proxy.sock");
    let output = run(
        &sandbox,
        probe(&["proxy-connect", sock.to_str().unwrap(), "8.8.8.8", "53"]),
    );
    assert!(
        !output.status.success(),
        "CONNECT to a raw IP not on the list succeeded: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let usage = sandbox.finish();
    assert!(
        usage
            .violations
            .iter()
            .any(|v| v.kind == ViolationKind::Network
                && v.detail.contains("8.8.8.8")
                && v.count >= 1),
        "denied CONNECT was not reported: {usage:?}"
    );
}

#[test]
fn hostname_allowlist_does_not_match_a_raw_ip() {
    if !cfg!(target_os = "linux") {
        skip("allowlist tests require Linux");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("ws");
    fs::create_dir_all(&workspace).unwrap();
    let probe_dir = probe_exe().parent().unwrap().to_path_buf();
    let settings = Settings::builder()
        .backend(Backend::LinuxNative)
        .network(Network::Allowlist(vec![AllowHost {
            host: "example.com".into(),
            port: Some(443),
        }]))
        .readable_roots(vec![probe_dir])
        .build();
    match kekkai::health(&settings) {
        Health::Ok(_) => {}
        Health::Warning(message) | Health::Error(message) => {
            skip(&format!("allowlist unavailable: {message}"));
            return;
        }
        _ => {
            skip("unrecognized health variant");
            return;
        }
    }
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let sock = sandbox.scratch_dir().unwrap().join("proxy.sock");
    let output = run(
        &sandbox,
        probe(&[
            "proxy-connect",
            sock.to_str().unwrap(),
            "93.184.216.34",
            "443",
        ]),
    );
    assert!(
        !output.status.success(),
        "DNS-bypass CONNECT to the raw IP succeeded: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let usage = sandbox.finish();
    assert!(
        usage
            .violations
            .iter()
            .any(|v| v.detail.contains("93.184.216.34")),
        "DNS-bypass was not reported: {usage:?}"
    );
}
