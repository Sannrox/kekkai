//! Bounded capture tests on the shipped `spawn_with_deadline_captured` path.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use kekkai::{Backend, CaptureKeep, CaptureLimits, ChildUsage, Sandbox, Settings, StreamCapture};

fn probe_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kekkai-probe"))
}

fn rlimit_sandbox() -> Sandbox {
    let settings = Settings::builder().backend(Backend::Rlimit).build();
    Sandbox::prepare(&settings, ".").expect("prepare")
}

fn spawn_fill(
    sandbox: &Sandbox,
    action: &str,
    n: usize,
    capture: CaptureLimits,
    deadline: Duration,
) -> (
    std::process::ExitStatus,
    ChildUsage,
    StreamCapture,
    StreamCapture,
) {
    let mut cmd = Command::new(probe_exe());
    cmd.args([action, &n.to_string()]);
    sandbox
        .spawn_with_deadline_captured(&mut cmd, deadline, Duration::from_millis(50), capture)
        .expect("spawn")
}

#[test]
fn stdout_over_cap_is_truncated_and_kept_bytes_stay_at_cap() {
    let sandbox = rlimit_sandbox();
    let cap = 64;
    let total = 10_000;
    let (status, usage, stdout, stderr) = spawn_fill(
        &sandbox,
        "fill-seq-stdout",
        total,
        CaptureLimits {
            stdout_max: Some(cap),
            stderr_max: None,
            keep: CaptureKeep::Head,
        },
        Duration::from_secs(5),
    );
    assert!(status.success(), "{status:?}");
    assert!(!usage.timed_out, "{usage:?}");
    assert_eq!(stdout.bytes.len(), cap);
    assert_eq!(stdout.bytes, (0u8..64).collect::<Vec<_>>());
    assert!(stdout.truncated);
    assert_eq!(stdout.dropped, (total - cap) as u64);
    assert!(stderr.bytes.is_empty());
    assert!(!stderr.truncated);
    assert_eq!(stderr.dropped, 0);
}

#[test]
fn stderr_truncation_is_reported_independently() {
    let sandbox = rlimit_sandbox();
    let cap = 32;
    let total = 200;
    let (status, usage, stdout, stderr) = spawn_fill(
        &sandbox,
        "fill-seq-stderr",
        total,
        CaptureLimits {
            stdout_max: Some(cap),
            stderr_max: Some(cap),
            keep: CaptureKeep::Head,
        },
        Duration::from_secs(5),
    );
    assert!(status.success(), "{status:?}");
    assert!(!usage.timed_out, "{usage:?}");
    assert!(stdout.bytes.is_empty());
    assert!(!stdout.truncated);
    assert_eq!(stderr.bytes, (0u8..32).collect::<Vec<_>>());
    assert!(stderr.truncated);
    assert_eq!(stderr.dropped, (total - cap) as u64);
}

#[test]
fn tail_keeps_the_last_bytes() {
    let sandbox = rlimit_sandbox();
    let cap = 10;
    let total = 100;
    let (status, _, stdout, _) = spawn_fill(
        &sandbox,
        "fill-seq-stdout",
        total,
        CaptureLimits {
            stdout_max: Some(cap),
            stderr_max: None,
            keep: CaptureKeep::Tail,
        },
        Duration::from_secs(5),
    );
    assert!(status.success(), "{status:?}");
    assert_eq!(stdout.bytes, (90u8..100).collect::<Vec<_>>());
    assert!(stdout.truncated);
    assert_eq!(stdout.dropped, 90);
}

#[test]
fn head_and_tail_keeps_both_ends() {
    let sandbox = rlimit_sandbox();
    let cap = 20;
    let total = 100;
    let (status, _, stdout, _) = spawn_fill(
        &sandbox,
        "fill-seq-stdout",
        total,
        CaptureLimits {
            stdout_max: Some(cap),
            stderr_max: None,
            keep: CaptureKeep::HeadAndTail,
        },
        Duration::from_secs(5),
    );
    assert!(status.success(), "{status:?}");
    let mut want = (0u8..10).collect::<Vec<_>>();
    want.extend(90..100);
    assert_eq!(stdout.bytes, want);
    assert!(stdout.truncated);
    assert_eq!(stdout.dropped, 80);
}

#[test]
fn under_cap_is_complete() {
    let sandbox = rlimit_sandbox();
    let (status, usage, stdout, _) = spawn_fill(
        &sandbox,
        "fill-seq-stdout",
        8,
        CaptureLimits {
            stdout_max: Some(64),
            stderr_max: None,
            keep: CaptureKeep::Head,
        },
        Duration::from_secs(5),
    );
    assert!(status.success(), "{status:?}");
    assert!(!usage.timed_out, "{usage:?}");
    assert_eq!(stdout.bytes, (0u8..8).collect::<Vec<_>>());
    assert!(!stdout.truncated);
    assert_eq!(stdout.dropped, 0);
}

#[test]
fn child_does_not_block_when_output_exceeds_the_pipe_buffer() {
    let sandbox = rlimit_sandbox();
    let cap = 1024;
    let total = 1_000_000;
    let started = Instant::now();
    let (status, usage, stdout, _) = spawn_fill(
        &sandbox,
        "fill-stdout",
        total,
        CaptureLimits {
            stdout_max: Some(cap),
            stderr_max: None,
            keep: CaptureKeep::Head,
        },
        Duration::from_secs(5),
    );
    let elapsed = started.elapsed();
    assert!(status.success(), "{status:?}");
    assert!(
        !usage.timed_out,
        "child blocked on a full pipe until the deadline: elapsed={elapsed:?} usage={usage:?}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "drain took too long for a 1MiB write: {elapsed:?}"
    );
    assert_eq!(stdout.bytes.len(), cap);
    assert!(stdout.truncated);
    assert_eq!(stdout.dropped, (total - cap) as u64);
}

#[cfg(unix)]
#[test]
fn capture_combines_with_the_deadline_helper() {
    let sandbox = rlimit_sandbox();
    let tmp = tempfile::tempdir().unwrap();
    let pid_file = tmp.path().join("grandchild.pid");
    let mut cmd = Command::new(probe_exe());
    cmd.args(["ignore-term", pid_file.to_str().unwrap()]);
    let (status, usage, stdout, stderr) = sandbox
        .spawn_with_deadline_captured(
            &mut cmd,
            Duration::from_millis(500),
            Duration::from_millis(200),
            CaptureLimits {
                stdout_max: Some(64),
                stderr_max: Some(64),
                keep: CaptureKeep::Head,
            },
        )
        .expect("spawn");
    assert!(
        usage.timed_out,
        "deadline must still set timed_out while capturing: status={status:?} usage={usage:?}"
    );
    assert!(!status.success(), "{status:?}");
    assert!(!stdout.truncated);
    assert!(!stderr.truncated);
}

#[cfg(all(unix, feature = "tokio"))]
#[tokio::test]
async fn tokio_captured_truncates_stdout() {
    let sandbox = rlimit_sandbox();
    let mut cmd = tokio::process::Command::new(probe_exe());
    cmd.args(["fill-seq-stdout", "1000"]);
    let (status, usage, stdout, _) = sandbox
        .spawn_with_deadline_captured_tokio(
            &mut cmd,
            Duration::from_secs(5),
            Duration::from_millis(50),
            CaptureLimits {
                stdout_max: Some(32),
                stderr_max: None,
                keep: CaptureKeep::Head,
            },
        )
        .await
        .expect("spawn");
    assert!(status.success(), "{status:?}");
    assert!(!usage.timed_out, "{usage:?}");
    assert_eq!(stdout.bytes, (0u8..32).collect::<Vec<_>>());
    assert!(stdout.truncated);
    assert_eq!(stdout.dropped, 968);
}
