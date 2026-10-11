//! Agent command: workspace, wall-clock deadline, bounded stdout/stderr.
//!
//! Usage: `agent_shell <workspace> <command> [args...]`

use std::io::{self, Write};
use std::process::Command;
use std::time::Duration;

use kekkai::{Backend, CaptureKeep, CaptureLimits, Health, Sandbox, Settings};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let usage = "usage: agent_shell <workspace> <command> [args...]";
    let Some(workspace) = args.next() else {
        return Err(usage.into());
    };
    let argv: Vec<String> = args.collect();
    if argv.is_empty() {
        return Err(usage.into());
    }

    let settings = Settings {
        backend: Backend::LinuxNative,
        ..Settings::default()
    };
    match kekkai::health(&settings) {
        Health::Ok(message) | Health::Warning(message) => eprintln!("{message}"),
        Health::Error(message) => return Err(message.into()),
    }

    let sandbox = Sandbox::prepare(&settings, &workspace)?;
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]).current_dir(&workspace);

    let (status, usage, stdout, stderr) = sandbox.spawn_with_deadline_captured(
        &mut cmd,
        Duration::from_secs(30),
        Duration::from_millis(200),
        CaptureLimits {
            stdout_max: Some(64 * 1024),
            stderr_max: Some(16 * 1024),
            keep: CaptureKeep::HeadAndTail,
        },
    )?;

    eprintln!(
        "timed_out={} exit={status} stdout_truncated={} stdout_dropped={} stderr_truncated={} stderr_dropped={}",
        usage.timed_out, stdout.truncated, stdout.dropped, stderr.truncated, stderr.dropped
    );
    io::stdout().write_all(&stdout.bytes)?;
    io::stderr().write_all(&stderr.bytes)?;
    if usage.timed_out || !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}
