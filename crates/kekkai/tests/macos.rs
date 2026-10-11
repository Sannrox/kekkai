//! macOS Seatbelt denial tests on the shipped [`Sandbox::prepare`] / [`apply`] path.
//!
//! Off macOS they print `skip:` and return. They never assert success without
//! running the child.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::{Mutex, MutexGuard};

use kekkai::{Backend, Health, Network, Sandbox, Settings};

/// `inherit_fd` dup2s onto a fixed parent fd. Parallel `Command::output`
/// pipes in this binary must not land on that same number.
static ESCAPE_LOCK: Mutex<()> = Mutex::new(());

fn skip(reason: &str) {
    eprintln!("skip: {reason}");
}

fn probe_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kekkai-probe"))
}

fn macos_ready() -> Option<(
    MutexGuard<'static, ()>,
    Settings,
    tempfile::TempDir,
    PathBuf,
)> {
    if !cfg!(target_os = "macos") {
        skip("macos backend tests require macOS");
        return None;
    }
    let guard = ESCAPE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("ws");
    fs::create_dir_all(&workspace).unwrap();
    let probe_dir = probe_exe()
        .parent()
        .expect("kekkai-probe has a parent directory")
        .to_path_buf();
    let settings = Settings::builder()
        .backend(Backend::Macos)
        .readable_roots(vec![probe_dir])
        .build();
    match kekkai::health(&settings) {
        Health::Ok(_) => Some((guard, settings, tmp, workspace)),
        Health::Warning(message) | Health::Error(message) => {
            skip(&format!("macos unavailable: {message}"));
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
fn write_outside_allowed_roots_is_denied() {
    let Some((_lock, settings, tmp, workspace)) = macos_ready() else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let outside = tmp.path().join("outside.txt");
    let output = run(&sandbox, probe(&["write", outside.to_str().unwrap()]));
    assert!(!outside.exists(), "write escaped to {}", outside.display());
    assert!(
        !output.status.success(),
        "child succeeded writing outside the workspace: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn read_of_non_allowed_root_is_denied() {
    let Some((_lock, settings, tmp, workspace)) = macos_ready() else {
        return;
    };
    let secret = tmp.path().join("host.secret");
    fs::write(&secret, "plane-token\n").unwrap();
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let output = run(&sandbox, probe(&["read", secret.to_str().unwrap()]));
    assert!(
        !output.status.success(),
        "child read a path outside the allowlist: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("plane-token"),
        "secret leaked on stdout: {stdout}"
    );
}

#[test]
fn extra_readable_root_is_readable() {
    let Some((_lock, mut settings, tmp, workspace)) = macos_ready() else {
        return;
    };
    let extra = tmp.path().join("toolchain");
    fs::create_dir_all(&extra).unwrap();
    let file = extra.join("tool.txt");
    fs::write(&file, "from-extra\n").unwrap();
    settings.readable_roots.push(extra);
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let output = run(&sandbox, probe(&["read", file.to_str().unwrap()]));
    assert!(
        output.status.success(),
        "readable_roots was not granted: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("from-extra"));
}

#[test]
fn host_system_trees_are_not_readable() {
    let Some((_lock, settings, _tmp, workspace)) = macos_ready() else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    for path in [
        "/etc/passwd",
        "/private/etc/passwd",
        "/Library/Preferences",
        "/private/tmp",
        "/opt",
        "/usr/local",
    ] {
        if !std::path::Path::new(path).exists() {
            continue;
        }
        let output = run(&sandbox, probe(&["read", path]));
        assert!(
            !output.status.success(),
            "child read host path {path}: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    // `/System` as a tree would let `ls` list the data volume. `fs::read` of
    // a directory fails even when listing is allowed, so use `/bin/ls`.
    for listed in ["/Users", "/Volumes", "/private"] {
        if !std::path::Path::new(listed).exists() {
            continue;
        }
        let mut ls = Command::new("/bin/ls");
        ls.arg(listed);
        let output = run(&sandbox, ls);
        assert!(
            !output.status.success(),
            "child listed {listed}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let data = "/System/Volumes/Data";
    if std::path::Path::new(data).exists() {
        let mut ls = Command::new("/bin/ls");
        ls.arg(data);
        let output = run(&sandbox, ls);
        assert!(
            !output.status.success(),
            "child listed {data}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains("Users"),
            "data volume listing leaked"
        );
    }
}

#[test]
fn write_to_input_is_denied() {
    let Some((_lock, mut settings, tmp, workspace)) = macos_ready() else {
        return;
    };
    let input = tmp.path().join("in");
    fs::create_dir_all(&input).unwrap();
    let file = input.join("data.txt");
    fs::write(&file, "secret\n").unwrap();
    settings.inputs.push(input);
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let output = run(&sandbox, probe(&["write", file.to_str().unwrap()]));
    assert_eq!(fs::read_to_string(&file).unwrap(), "secret\n");
    assert!(
        !output.status.success(),
        "child wrote to an input path: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let read = run(&sandbox, probe(&["read", file.to_str().unwrap()]));
    assert!(
        read.status.success(),
        "input was not readable: stderr={}",
        String::from_utf8_lossy(&read.stderr)
    );
    assert!(String::from_utf8_lossy(&read.stdout).contains("secret"));
}

#[test]
fn output_dir_is_writable_and_workspace_is_not_when_output_is_set() {
    let Some((_lock, mut settings, tmp, workspace)) = macos_ready() else {
        return;
    };
    let output_dir = tmp.path().join("out");
    fs::create_dir_all(&output_dir).unwrap();
    settings.output = Some(output_dir.clone());
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let dest = output_dir.join("ok.txt");
    let output = run(&sandbox, probe(&["write", dest.to_str().unwrap()]));
    assert!(
        output.status.success(),
        "output write failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(&dest).unwrap(), "pwned\n");
    let ws_file = workspace.join("nope.txt");
    let denied = run(&sandbox, probe(&["write", ws_file.to_str().unwrap()]));
    assert!(
        !denied.status.success(),
        "workspace stayed writable after Settings.output: stderr={}",
        String::from_utf8_lossy(&denied.stderr)
    );
    assert!(!ws_file.exists());
}

#[test]
fn scratch_is_unique_per_run_sets_tmpdir_and_is_cleaned_up() {
    let Some((_lock, settings, _tmp, workspace)) = macos_ready() else {
        return;
    };
    let first = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let second = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let a = first.scratch_dir().expect("first scratch").to_path_buf();
    let b = second.scratch_dir().expect("second scratch").to_path_buf();
    assert_ne!(a, b, "scratch directories must be unique per prepare");
    assert!(a.is_dir(), "{}", a.display());
    assert!(b.is_dir(), "{}", b.display());

    let env = run(&first, probe(&["env", "TMPDIR"]));
    assert!(
        env.status.success(),
        "TMPDIR missing: stderr={}",
        String::from_utf8_lossy(&env.stderr)
    );
    let tmpdir = String::from_utf8_lossy(&env.stdout).trim().to_string();
    assert_eq!(std::path::PathBuf::from(&tmpdir), a);

    let marker = a.join("child.txt");
    let wrote = run(&first, probe(&["write", marker.to_str().unwrap()]));
    assert!(
        wrote.status.success(),
        "scratch write failed: stderr={}",
        String::from_utf8_lossy(&wrote.stderr)
    );

    drop(first);
    drop(second);
    assert!(!a.exists(), "scratch {} was not cleaned up", a.display());
    assert!(!b.exists(), "scratch {} was not cleaned up", b.display());
}

#[test]
fn write_inside_workspace_is_allowed() {
    let Some((_lock, settings, _tmp, workspace)) = macos_ready() else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let inside = workspace.join("ok.txt");
    let output = run(&sandbox, probe(&["write", inside.to_str().unwrap()]));
    assert!(
        output.status.success(),
        "write inside workspace failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(&inside).unwrap(), b"pwned\n");
}

#[cfg(unix)]
fn inherit_fd(path: &std::path::Path, fd: i32) {
    use std::os::unix::io::IntoRawFd;
    let file = fs::File::open(path).unwrap();
    let src = file.into_raw_fd();
    // SAFETY: test parent; clear CLOEXEC so the child would inherit `src`.
    unsafe {
        libc::fcntl(src, libc::F_SETFD, 0);
        if src != fd {
            libc::dup2(src, fd);
            libc::close(src);
        }
    }
}

#[test]
fn inherited_extra_fd_is_closed() {
    let Some((_lock, settings, tmp, workspace)) = macos_ready() else {
        return;
    };
    let fd = 7;
    let secret = tmp.path().join("fd-secret.txt");
    fs::write(&secret, "plane-token\n").unwrap();
    inherit_fd(&secret, fd);
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let output = run(&sandbox, probe(&["read-fd", &fd.to_string()]));
    assert!(
        !output.status.success(),
        "read of inherited extra fd succeeded: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("plane-token"),
        "secret leaked on stdout: {stdout}"
    );
    // SAFETY: parent still owns `fd`.
    unsafe {
        libc::close(fd);
    }
}

#[test]
fn open_dev_tty_is_denied() {
    let Some((_lock, settings, _tmp, workspace)) = macos_ready() else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let output = run(&sandbox, probe(&["open", "/dev/tty"]));
    assert!(
        !output.status.success(),
        "child opened /dev/tty: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn launch_services_trampoline_is_denied() {
    let Some((_lock, settings, tmp, workspace)) = macos_ready() else {
        return;
    };
    let secret = tmp.path().join("host.secret");
    fs::write(&secret, "plane-token\n").unwrap();
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let mut open = Command::new("/usr/bin/open");
    open.arg(&secret);
    let output = run(&sandbox, open);
    assert!(
        !output.status.success(),
        "/usr/bin/open escaped the allowlist: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn socket_creation_is_denied_when_network_is_off() {
    let Some((_lock, settings, _tmp, workspace)) = macos_ready() else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let output = run(&sandbox, probe(&["socket"]));
    assert!(
        !output.status.success(),
        "socket() succeeded with network=deny: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn socket_creation_is_allowed_when_network_is_on() {
    let Some((_lock, mut settings, _tmp, workspace)) = macos_ready() else {
        return;
    };
    settings.network = Network::Allow;
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let output = run(&sandbox, probe(&["socket"]));
    assert!(
        output.status.success(),
        "socket() failed with network=allow: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}
