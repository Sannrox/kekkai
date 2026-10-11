//! Cgroup v2 limit tests on the shipped prepare/apply path.
//!
//! Hosts without a delegated cgroup subtree skip enforcement cases after an
//! explicit `skip:` line. Requesting cgroup limits on those hosts is still
//! proven to fail closed.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use kekkai::{Backend, CgroupLimits, ChildUsage, Health, IoMax, Limits, Sandbox, Settings};

fn skip(reason: &str) {
    eprintln!("skip: {reason}");
}

fn probe_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kekkai-probe"))
}

fn cgroup_settings(limits: CgroupLimits) -> Settings {
    Settings::builder()
        .backend(Backend::Rlimit)
        .cgroup(limits)
        .build()
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
        _ => {
            skip("unrecognized health variant");
            None
        }
    }
}

fn wait_child(
    sandbox: &Sandbox,
    child: std::process::Child,
) -> (std::process::ExitStatus, ChildUsage) {
    wait_child_for(sandbox, child, Duration::from_secs(5))
}

fn wait_child_for(
    sandbox: &Sandbox,
    mut child: std::process::Child,
    timeout: Duration,
) -> (std::process::ExitStatus, ChildUsage) {
    let deadline = Instant::now() + timeout;
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
    let settings = Settings::builder()
        .backend(Backend::Rlimit)
        .limits(Limits {
            memory_mb: Some(512),
            ..Limits::default()
        })
        .build();
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

fn stat_major_minor(path: &std::path::Path) -> Option<(u32, u32)> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let dev = std::fs::metadata(path).ok()?.dev();
        let major = ((dev >> 8) & 0xfff) as u32;
        let minor = ((dev & 0xff) | ((dev >> 12) & 0xfff00)) as u32;
        Some((major, minor))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        None
    }
}

struct CoveringMount {
    major: u32,
    minor: u32,
    mountpoint: PathBuf,
    fstype: String,
    super_opts: String,
}

fn parse_mountinfo() -> Vec<CoveringMount> {
    let Ok(text) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let Some((pre, post)) = line.split_once(" - ") else {
            continue;
        };
        let pre: Vec<&str> = pre.split_whitespace().collect();
        let post: Vec<&str> = post.split_whitespace().collect();
        if pre.len() < 5 || post.len() < 3 {
            continue;
        }
        let Some((maj, min)) = pre[2].split_once(':') else {
            continue;
        };
        let Ok(major) = maj.parse() else {
            continue;
        };
        let Ok(minor) = min.parse() else {
            continue;
        };
        out.push(CoveringMount {
            major,
            minor,
            mountpoint: PathBuf::from(pre[4]),
            fstype: post[0].to_string(),
            super_opts: post[2].to_string(),
        });
    }
    out
}

fn overlay_upper(super_opts: &str) -> Option<PathBuf> {
    super_opts.split(',').find_map(|opt| {
        opt.strip_prefix("upperdir=")
            .map(PathBuf::from)
            .filter(|path| !path.as_os_str().is_empty())
    })
}

fn backing_block_device(path: &std::path::Path) -> Option<(u32, u32)> {
    let path = if path.exists() {
        path.canonicalize().ok()?
    } else {
        path.parent()
            .and_then(|parent| parent.canonicalize().ok())?
    };
    backing_block_device_inner(&path, 0)
}

fn backing_block_device_inner(path: &std::path::Path, depth: u8) -> Option<(u32, u32)> {
    if depth > 4 {
        return None;
    }
    if let Some((major, minor)) = stat_major_minor(path)
        && major != 0
    {
        return Some((major, minor));
    }
    let mounts = parse_mountinfo();
    let cover = mounts
        .iter()
        .filter(|mount| path.starts_with(&mount.mountpoint))
        .max_by_key(|mount| mount.mountpoint.as_os_str().len())?;
    if cover.major != 0 {
        return Some((cover.major, cover.minor));
    }
    if cover.fstype == "overlay" {
        let upper = overlay_upper(&cover.super_opts)?;
        return backing_block_device_inner(&upper, depth + 1);
    }
    None
}

fn writable_block_dir() -> Option<(tempfile::TempDir, u32, u32)> {
    let mut bases = vec![std::env::temp_dir(), PathBuf::from("/var/tmp")];
    if let Ok(cwd) = std::env::current_dir() {
        bases.push(cwd);
    }
    if let Some(target) = std::env::var_os("CARGO_TARGET_TMPDIR") {
        bases.push(PathBuf::from(target));
    }
    for base in bases {
        if !base.is_dir() {
            continue;
        }
        let Ok(tmp) = tempfile::TempDir::new_in(&base) else {
            continue;
        };
        if let Some((major, minor)) = backing_block_device(tmp.path()) {
            return Some((tmp, major, minor));
        }
    }
    None
}

#[test]
fn missing_io_controller_is_unavailable() {
    let Some(mut settings) = delegated_or_skip() else {
        return;
    };
    settings.cgroup = CgroupLimits {
        io_max: Some(IoMax {
            major: 8,
            minor: 0,
            wbps: Some(1024),
            ..IoMax::default()
        }),
        ..CgroupLimits::default()
    };
    match Sandbox::prepare(&settings, ".") {
        Ok(_) => skip("io controller is delegated; throttle test covers it"),
        Err(error) => {
            assert!(
                matches!(error, kekkai::Error::Unavailable { .. }),
                "{error}"
            );
            assert!(
                error.to_string().contains("io"),
                "missing io controller should name io: {error}"
            );
        }
    }
}

#[test]
fn missing_cpu_controller_is_unavailable() {
    let Some(mut settings) = delegated_or_skip() else {
        return;
    };
    settings.cgroup = CgroupLimits {
        cpu_weight: Some(100),
        ..CgroupLimits::default()
    };
    match Sandbox::prepare(&settings, ".") {
        Ok(_) => skip("cpu controller is delegated"),
        Err(error) => {
            assert!(
                matches!(error, kekkai::Error::Unavailable { .. }),
                "{error}"
            );
            assert!(
                error.to_string().contains("cpu"),
                "missing cpu controller should name cpu: {error}"
            );
        }
    }
}

#[test]
fn io_max_throttles_writer() {
    let Some(base) = delegated_or_skip() else {
        return;
    };
    let Some((tmp, major, minor)) = writable_block_dir() else {
        skip("no block device under the temp dir for io.max");
        return;
    };
    let blob = tmp.path().join("blob");
    let nbytes = 128 * 1024;
    let unthrottled = {
        let sandbox = Sandbox::prepare(&base, tmp.path()).expect("prepare");
        let started = Instant::now();
        let child = spawn_probe(
            &sandbox,
            &[
                "write-sync-bytes",
                blob.to_str().expect("utf8 path"),
                &nbytes.to_string(),
            ],
        );
        let (status, _usage) = wait_child_for(&sandbox, child, Duration::from_secs(10));
        assert!(status.success(), "unthrottled write-sync-bytes failed");
        started.elapsed()
    };
    if unthrottled >= Duration::from_secs(2) {
        skip("disk too slow to prove io.max throttle");
        return;
    }
    let mut settings = base;
    settings.cgroup = CgroupLimits {
        io_max: Some(IoMax {
            major,
            minor,
            wbps: Some(32 * 1024),
            ..IoMax::default()
        }),
        ..CgroupLimits::default()
    };
    let sandbox = match Sandbox::prepare(&settings, tmp.path()) {
        Ok(sandbox) => sandbox,
        Err(error) if error.to_string().contains("io") => {
            skip(&format!("io controller unavailable: {error}"));
            return;
        }
        Err(error) => panic!("prepare io.max: {error}"),
    };
    let started = Instant::now();
    let child = spawn_probe(
        &sandbox,
        &[
            "write-sync-bytes",
            blob.to_str().expect("utf8 path"),
            &nbytes.to_string(),
        ],
    );
    let (status, _usage) = wait_child_for(&sandbox, child, Duration::from_secs(15));
    let elapsed = started.elapsed();
    assert!(
        status.success(),
        "throttled write-sync-bytes failed; elapsed={elapsed:?}"
    );
    assert!(
        elapsed >= Duration::from_secs(2),
        "write of {nbytes} bytes finished in {elapsed:?} under wbps=32KiB (unthrottled {unthrottled:?})"
    );
}

#[test]
fn usage_increases_while_child_runs() {
    let Some(mut settings) = delegated_or_skip() else {
        return;
    };
    settings.cgroup.memory_max = Some(64 * 1024 * 1024);
    let tmp = tempfile::tempdir().unwrap();
    let blob = tmp.path().join("blob");
    let sandbox = Sandbox::prepare(&settings, tmp.path()).expect("prepare");
    let path = blob.to_str().expect("utf8 path");
    let mut child = spawn_probe(&sandbox, &["write-sync-loop", path]);
    let mut first: Option<ChildUsage> = None;
    let mut saw_increase = false;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(status)) => {
                panic!(
                    "write-sync-loop exited early {status:?} usage={:?}",
                    sandbox.usage()
                );
            }
            Ok(None) => {
                let snap = sandbox.usage();
                if let Some(prev) = &first {
                    let cpu_up = snap.cpu_usec.unwrap_or(0) > prev.cpu_usec.unwrap_or(0);
                    let io_up = snap.io_wbytes.unwrap_or(0) > prev.io_wbytes.unwrap_or(0);
                    let mem_up = snap.memory_current_bytes.unwrap_or(0)
                        > prev.memory_current_bytes.unwrap_or(0);
                    if cpu_up || io_up || mem_up {
                        saw_increase = true;
                        break;
                    }
                } else if snap.pids_current.unwrap_or(0) >= 1
                    || snap.memory_current_bytes.is_some()
                    || snap.cpu_usec.is_some()
                {
                    first = Some(snap);
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("wait: {error}"),
        }
    }
    sandbox.kill_process_group(Some(child.id()));
    let _ = child.wait();
    assert!(
        saw_increase,
        "live usage did not increase while the child ran; first={first:?} last={:?}",
        sandbox.usage()
    );
}
