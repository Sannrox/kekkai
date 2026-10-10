//! Cgroup v2 limit tests on the shipped prepare/apply path.
//!
//! Hosts without a delegated cgroup subtree skip enforcement cases after an
//! explicit `skip:` line. Requesting cgroup limits on those hosts is still
//! proven to fail closed.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use kekkai::{Backend, CgroupLimits, ChildUsage, Health, Limits, Sandbox, Settings};

fn skip(reason: &str) {
    eprintln!("skip: {reason}");
}

fn probe_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kekkai-probe"))
}

fn cgroup_settings(limits: CgroupLimits) -> Settings {
    Settings {
        backend: Backend::Rlimit,
        cgroup: limits,
        ..Settings::default()
    }
}

fn delegated_or_skip() -> Option<Settings> {
    if !cfg!(target_os = "linux") {
        skip("cgroup v2 limits require Linux");
        return None;
    }
    let settings = cgroup_settings(CgroupLimits {
        memory_max: Some(32 * 1024 * 1024),
        ..CgroupLimits::default()
    });
    match kekkai::health(&settings) {
        Health::Ok(_) => Some(settings),
        Health::Warning(message) | Health::Error(message) => {
            skip(&format!("no delegated cgroup v2 subtree: {message}"));
            None
        }
    }
}

fn wait_child(
    sandbox: &Sandbox,
    mut child: std::process::Child,
) -> (std::process::ExitStatus, ChildUsage) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return (status, sandbox.finish()),
            Ok(None) if Instant::now() >= deadline => {
                sandbox.kill_process_group(Some(child.id()));
                let status = child.wait().expect("wait after kill");
                return (status, sandbox.finish());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(error) => panic!("wait: {error}"),
        }
    }
}

fn spawn_probe(sandbox: &Sandbox, args: &[&str]) -> std::process::Child {
    let mut cmd = Command::new(probe_exe());
    cmd.args(args);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    sandbox.apply(&mut cmd).expect("apply");
    cmd.spawn().expect("spawn")
}

fn read_stdout(child: &mut std::process::Child) -> String {
    use std::io::Read;
    let mut buf = String::new();
    if let Some(mut stdout) = child.stdout.take() {
        let _ = stdout.read_to_string(&mut buf);
    }
    buf
}

#[test]
fn requesting_cgroup_without_delegation_is_an_error() {
    let mut settings = cgroup_settings(CgroupLimits {
        memory_max: Some(512 * 1024 * 1024),
        ..CgroupLimits::default()
    });
    settings.cgroup_root = Some("/tmp/kekkai-missing-cgroup".into());
    let report = kekkai::health(&settings);
    if cfg!(target_os = "linux") {
        assert!(
            matches!(report, Health::Error(ref message) if message.contains("cgroup")),
            "{report:?}"
        );
        let error = Sandbox::prepare(&settings, ".").unwrap_err();
        assert!(
            matches!(error, kekkai::Error::Unavailable { .. }),
            "{error}"
        );
    } else {
        assert!(
            matches!(report, Health::Error(ref message) if message.contains("Linux")),
            "{report:?}"
        );
    }
}

#[test]
fn large_virtual_mapping_fails_under_rlimit_as() {
    if !cfg!(target_os = "linux") {
        skip("RLIMIT_AS comparison requires Linux");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let settings = Settings {
        backend: Backend::Rlimit,
        limits: Limits {
            memory_mb: Some(512),
            ..Limits::default()
        },
        ..Settings::default()
    };
    let sandbox = Sandbox::prepare(&settings, tmp.path()).expect("prepare");
    let mut cmd = Command::new(probe_exe());
    cmd.args(["mmap-va", &(512 * 1024 * 1024).to_string()]);
    sandbox.apply(&mut cmd).expect("apply");
    let status = cmd.status().expect("spawn");
    assert!(
        !status.success(),
        "512 MiB mmap succeeded under RLIMIT_AS=512MiB; numeric libraries need cgroup memory.max"
    );
}

#[test]
fn large_virtual_mapping_is_allowed_under_cgroup_memory_max() {
    let Some(mut settings) = delegated_or_skip() else {
        return;
    };
    settings.cgroup.memory_max = Some(512 * 1024 * 1024);
    let tmp = tempfile::tempdir().unwrap();
    let sandbox = Sandbox::prepare(&settings, tmp.path()).expect("prepare");
    let child = spawn_probe(&sandbox, &["mmap-va", &(512 * 1024 * 1024).to_string()]);
    let (status, usage) = wait_child(&sandbox, child);
    assert!(
        status.success(),
        "512 MiB anonymous mmap should succeed under memory.max=512MiB (RSS is not touched); usage={usage:?}"
    );
    assert!(!usage.oom_killed, "{usage:?}");
}

#[test]
fn touching_past_memory_max_is_reported_as_oom() {
    let Some(mut settings) = delegated_or_skip() else {
        return;
    };
    settings.cgroup.memory_max = Some(16 * 1024 * 1024);
    let tmp = tempfile::tempdir().unwrap();
    let sandbox = Sandbox::prepare(&settings, tmp.path()).expect("prepare");
    let child = spawn_probe(&sandbox, &["touch-bytes", &(64 * 1024 * 1024).to_string()]);
    let (status, usage) = wait_child(&sandbox, child);
    assert!(
        !status.success(),
        "child survived touching 64MiB under 16MiB memory.max"
    );
    assert!(
        usage.oom_killed,
        "expected oom_kill in memory.events: {usage:?} status={status:?}"
    );
}

#[test]
fn pids_max_stops_a_fork_bomb() {
    let Some(mut settings) = delegated_or_skip() else {
        return;
    };
    settings.cgroup = CgroupLimits {
        pids_max: Some(8),
        ..CgroupLimits::default()
    };
    let tmp = tempfile::tempdir().unwrap();
    let sandbox = Sandbox::prepare(&settings, tmp.path()).expect("prepare");
    let mut child = spawn_probe(&sandbox, &["fork-count", "32"]);
    let stdout = {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let out = read_stdout(&mut child);
                    let usage = sandbox.finish();
                    break (status, usage, out);
                }
                Ok(None) if Instant::now() >= deadline => {
                    sandbox.kill_process_group(Some(child.id()));
                    let status = child.wait().expect("wait after kill");
                    panic!(
                        "fork-count timed out under pids.max=8; status={status:?} usage={:?}",
                        sandbox.finish()
                    );
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                Err(error) => panic!("wait: {error}"),
            }
        }
    };
    let (status, _usage, out) = stdout;
    let created: u32 = out.trim().parse().unwrap_or(u32::MAX);
    assert!(
        !status.success(),
        "fork-count 32 succeeded under pids.max=8; created={created}"
    );
    assert!(
        created <= 8,
        "fork-count created {created} children under pids.max=8"
    );
}

fn python_module(module: &str) -> bool {
    Command::new("python3")
        .args(["-c", &format!("import {module}")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn numeric_module_under_cgroup(module: &str) {
    let Some(mut settings) = delegated_or_skip() else {
        return;
    };
    if !python_module(module) {
        skip(&format!("python3 module `{module}` is not installed"));
        return;
    }
    settings.cgroup.memory_max = Some(512 * 1024 * 1024);
    let tmp = tempfile::tempdir().unwrap();
    let sandbox = Sandbox::prepare(&settings, tmp.path()).expect("prepare");
    let mut cmd = Command::new("python3");
    cmd.args(["-c", &format!("import {module}")]);
    sandbox.apply(&mut cmd).expect("apply");
    let status = cmd.status().expect("spawn");
    assert!(
        status.success(),
        "`import {module}` failed under 512 MiB memory.max"
    );
}

#[test]
fn numpy_starts_under_512_mib_cgroup() {
    numeric_module_under_cgroup("numpy");
}

#[test]
fn polars_starts_under_512_mib_cgroup() {
    numeric_module_under_cgroup("polars");
}

#[test]
fn duckdb_starts_under_512_mib_cgroup() {
    numeric_module_under_cgroup("duckdb");
}
