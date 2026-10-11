//! Wall-clock deadline tests on the shipped `spawn_with_deadline` path.

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use kekkai::{Backend, ChildUsage, Sandbox, Settings};

fn probe_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kekkai-probe"))
}

fn rlimit_sandbox() -> Sandbox {
    let settings = Settings {
        backend: Backend::Rlimit,
        ..Settings::default()
    };
    Sandbox::prepare(&settings, ".").expect("prepare")
}

#[cfg(unix)]
fn process_exists(pid: i32) -> bool {
    // SAFETY: `kill(pid, 0)` existence probe; ESRCH means gone.
    unsafe { libc::kill(pid, 0) == 0 }
}

#[test]
fn child_that_exits_before_deadline_is_not_timed_out() {
    let sandbox = rlimit_sandbox();
    let mut cmd = Command::new(probe_exe());
    cmd.args(["write-bytes", "/dev/null", "1"]);
    let (status, usage) = sandbox
        .spawn_with_deadline(&mut cmd, Duration::from_secs(5), Duration::from_millis(50))
        .expect("spawn");
    assert!(status.success(), "{status:?}");
    assert!(
        !usage.timed_out,
        "timed_out must be false when the child exits in time: {usage:?}"
    );
}

#[cfg(unix)]
fn run_deadline_and_assert_grandchild_gone(action: &str) {
    let sandbox = rlimit_sandbox();
    let tmp = tempfile::tempdir().unwrap();
    let pid_file = tmp.path().join("grandchild.pid");
    let mut cmd = Command::new(probe_exe());
    cmd.args([action, pid_file.to_str().unwrap()]);
    let started = std::time::Instant::now();
    let (status, usage) = sandbox
        .spawn_with_deadline(
            &mut cmd,
            Duration::from_millis(500),
            Duration::from_millis(200),
        )
        .expect("spawn");
    assert!(
        usage.timed_out,
        "{action}: deadline expiry must set timed_out: status={status:?} usage={usage:?}"
    );
    assert!(
        !status.success(),
        "{action}: timed-out child must not exit 0: {status:?}"
    );
    assert!(
        started.elapsed() >= Duration::from_millis(500),
        "{action}: deadline returned too early: {:?}",
        started.elapsed()
    );
    let pid_text = std::fs::read_to_string(&pid_file).unwrap_or_else(|error| {
        panic!(
            "{action}: grandchild pid file {pid_file:?}: {error}; status={status:?} usage={usage:?} elapsed={:?}",
            started.elapsed()
        )
    });
    let grandchild: i32 = pid_text
        .lines()
        .nth(1)
        .or_else(|| pid_text.lines().next())
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("{action}: pid file contents {pid_text:?}"));
    let gone = (0..50).any(|_| {
        if !process_exists(grandchild) {
            true
        } else {
            std::thread::sleep(Duration::from_millis(20));
            false
        }
    });
    assert!(
        gone,
        "{action}: grandchild {grandchild} still exists after deadline SIGKILL"
    );
}

#[cfg(unix)]
#[test]
fn ignore_term_child_is_killed_after_grace_and_grandchildren_are_gone() {
    run_deadline_and_assert_grandchild_gone("ignore-term");
}

#[cfg(unix)]
#[test]
fn term_reaped_leader_still_kills_ignoring_grandchildren() {
    run_deadline_and_assert_grandchild_gone("term-parent");
}

#[cfg(all(unix, feature = "tokio"))]
#[tokio::test]
async fn tokio_deadline_times_out_an_ignore_term_child() {
    let sandbox = rlimit_sandbox();
    let tmp = tempfile::tempdir().unwrap();
    let pid_file = tmp.path().join("grandchild.pid");
    let mut cmd = tokio::process::Command::new(probe_exe());
    cmd.args(["ignore-term", pid_file.to_str().unwrap()]);
    let (_status, usage) = sandbox
        .spawn_with_deadline_tokio(
            &mut cmd,
            Duration::from_millis(500),
            Duration::from_millis(200),
        )
        .await
        .expect("spawn");
    assert!(
        usage.timed_out,
        "tokio deadline must set timed_out: {usage:?}"
    );
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn tokio_deadline_does_not_flag_a_fast_child() {
    let sandbox = rlimit_sandbox();
    let mut cmd = tokio::process::Command::new(probe_exe());
    cmd.args(["write-bytes", "/dev/null", "1"]);
    let (status, usage) = sandbox
        .spawn_with_deadline_tokio(&mut cmd, Duration::from_secs(5), Duration::from_millis(50))
        .await
        .expect("spawn");
    assert!(status.success(), "{status:?}");
    assert!(
        !usage.timed_out,
        "fast tokio child must not time out: {usage:?}"
    );
}

#[test]
fn finish_without_deadline_leaves_timed_out_false() {
    let sandbox = rlimit_sandbox();
    let usage: ChildUsage = sandbox.finish();
    assert!(!usage.timed_out);
}
