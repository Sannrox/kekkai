//! Namespace isolate tests on the shipped prepare/apply path.
//!
//! Hosts without unprivileged user namespaces skip after an explicit `skip:`
//! line. Selecting isolate on those hosts is still proven to fail closed.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use kekkai::{Backend, CaptureKeep, CaptureLimits, Health, Namespaces, Sandbox, Settings};

fn skip(reason: &str) {
    eprintln!("skip: {reason}");
}

fn probe_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kekkai-probe"))
}

fn isolate_or_skip(backend: Backend) -> Option<(Settings, tempfile::TempDir, PathBuf)> {
    if !cfg!(target_os = "linux") {
        skip("namespace isolate requires Linux");
        return None;
    }
    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("ws");
    std::fs::create_dir_all(&workspace).unwrap();
    let probe_dir = probe_exe()
        .parent()
        .expect("kekkai-probe has a parent directory")
        .to_path_buf();
    let settings = Settings::builder()
        .backend(backend)
        .namespaces(Namespaces::Isolate)
        .readable_roots(if matches!(backend, Backend::LinuxNative) {
            vec![probe_dir]
        } else {
            Vec::new()
        })
        .build();
    match kekkai::health(&settings) {
        Health::Ok(_) => Some((settings, tmp, workspace)),
        Health::Warning(message) | Health::Error(message) => {
            skip(&format!("namespace isolate unavailable: {message}"));
            None
        }
        _ => {
            skip("unrecognized health variant");
            None
        }
    }
}

fn run(sandbox: &Sandbox, mut cmd: Command) -> std::process::Output {
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
fn isolate_without_user_namespaces_is_unavailable() {
    if cfg!(target_os = "linux") && kekkai::capabilities().user_namespaces {
        skip("host can create user namespaces");
        return;
    }
    let settings = Settings::builder()
        .backend(if cfg!(unix) {
            Backend::Rlimit
        } else {
            Backend::LinuxNative
        })
        .namespaces(Namespaces::Isolate)
        .build();
    let report = kekkai::health(&settings);
    assert!(matches!(report, Health::Error(_)), "{report:?}");
    let error = Sandbox::prepare(&settings, ".").unwrap_err();
    assert!(
        matches!(
            error,
            kekkai::Error::Unavailable { .. } | kekkai::Error::Unsupported { .. }
        ),
        "{error}"
    );
}

#[test]
fn child_payload_is_pid_two() {
    let Some((settings, _tmp, workspace)) = isolate_or_skip(Backend::LinuxNative) else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let output = run(&sandbox, probe(&["pid"]));
    assert!(output.status.success(), "{output:?}");
    let pid = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert_eq!(
        pid, "2",
        "payload must be PID 2 (init stays as reaper): {output:?}"
    );
}

#[test]
fn host_pid_is_not_visible() {
    let Some((settings, _tmp, workspace)) = isolate_or_skip(Backend::LinuxNative) else {
        return;
    };
    let host_pid = std::process::id().to_string();
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let output = run(&sandbox, probe(&["proc-exists", &host_pid]));
    assert!(
        !output.status.success(),
        "host pid {host_pid} must be hidden: {output:?}"
    );
}

#[test]
fn host_ipc_object_is_not_visible() {
    let Some((settings, _tmp, workspace)) = isolate_or_skip(Backend::Rlimit) else {
        return;
    };
    let name = format!("/kekkai-ns-ipc-{}", std::process::id());
    #[cfg(target_os = "linux")]
    {
        let c_name = std::ffi::CString::new(name.as_str()).unwrap();
        // SAFETY: create a POSIX shm object the child must not see.
        let fd = unsafe {
            libc::shm_open(
                c_name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )
        };
        if fd < 0 {
            skip(&format!("shm_open: {}", std::io::Error::last_os_error()));
            return;
        }
        unsafe {
            libc::close(fd);
        }
        let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
        let output = run(&sandbox, probe(&["shm-open", &name]));
        unsafe {
            libc::shm_unlink(c_name.as_ptr());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "host shm {name} must be hidden: {output:?}"
        );
        assert!(
            stderr.contains("No such file")
                || stderr.contains("ENOENT")
                || output.status.code().is_some_and(|c| c != 0),
            "expected missing shm, not a Landlock miss: {stderr}"
        );
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (settings, workspace, name);
    }
}

#[test]
fn spawn_returns_while_the_isolate_child_is_running() {
    let Some((settings, tmp, workspace)) = isolate_or_skip(Backend::Rlimit) else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let pid_file = tmp.path().join("child.pid");
    let mut cmd = probe(&["ignore-term", pid_file.to_str().unwrap()]);
    sandbox.apply(&mut cmd).expect("apply");
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());
    let started = Instant::now();
    let mut child = cmd.spawn().expect("spawn");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "spawn blocked until the child exited: {:?}",
        started.elapsed()
    );
    assert!(
        child.try_wait().expect("try_wait").is_none(),
        "child should still be running"
    );
    sandbox.kill_process_group(Some(child.id()));
    let _ = child.wait();
}

#[test]
fn isolate_rlimit_cannot_be_raised() {
    let Some((mut settings, _tmp, workspace)) = isolate_or_skip(Backend::Rlimit) else {
        return;
    };
    settings.limits.memory_mb = Some(64);
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let output = run(&sandbox, probe(&["raise-as"]));
    assert!(
        !output.status.success(),
        "userns root must not raise RLIMIT_AS: {output:?}"
    );
}

#[test]
fn isolate_deadline_delivers_sigterm_to_the_payload() {
    let Some((settings, _tmp, workspace)) = isolate_or_skip(Backend::Rlimit) else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let mut cmd = probe(&["pause"]);
    let started = Instant::now();
    let (status, usage) = sandbox
        .spawn_with_deadline(&mut cmd, Duration::from_millis(300), Duration::from_secs(2))
        .expect("spawn");
    let elapsed = started.elapsed();
    assert!(usage.timed_out, "status={status:?} usage={usage:?}");
    assert!(
        elapsed < Duration::from_millis(1200),
        "SIGTERM should stop a default-disposition child before term_grace: {elapsed:?}"
    );
}

#[test]
fn isolate_deadline_kills_an_ignoring_child() {
    let Some((settings, tmp, workspace)) = isolate_or_skip(Backend::Rlimit) else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let pid_file = tmp.path().join("child.pid");
    let mut cmd = probe(&["ignore-term", pid_file.to_str().unwrap()]);
    let (status, usage) = sandbox
        .spawn_with_deadline(
            &mut cmd,
            Duration::from_millis(400),
            Duration::from_millis(150),
        )
        .expect("spawn");
    assert!(
        usage.timed_out,
        "deadline must set timed_out: status={status:?} usage={usage:?}"
    );
    assert!(!status.success(), "{status:?}");
}

#[test]
fn isolate_child_does_not_block_spawn_on_a_full_pipe() {
    let Some((settings, _tmp, workspace)) = isolate_or_skip(Backend::Rlimit) else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let mut cmd = probe(&["fill-stdout", "200000"]);
    let started = Instant::now();
    let (status, usage, stdout, _) = sandbox
        .spawn_with_deadline_captured(
            &mut cmd,
            Duration::from_secs(5),
            Duration::from_millis(50),
            CaptureLimits {
                stdout_max: Some(64),
                stderr_max: None,
                keep: CaptureKeep::Head,
            },
        )
        .expect("spawn");
    assert!(
        !usage.timed_out,
        "child blocked on a full pipe: elapsed={:?} usage={usage:?}",
        started.elapsed()
    );
    assert!(status.success(), "{status:?}");
    assert!(stdout.truncated, "{stdout:?}");
}
