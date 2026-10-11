//! Escape attempts that must stay denied on the shipped [`Sandbox::prepare`]
//! / [`apply`] path.
//!
//! Kernel-dependent cases print `skip: ...` and return. They never treat a
//! missing kernel feature as a passing denial.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use kekkai::{Backend, Health, Sandbox, Settings};

fn skip(reason: &str) {
    eprintln!("skip: {reason}");
}

fn probe_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kekkai-probe"))
}

fn linux_native_ready() -> Option<(Settings, tempfile::TempDir, PathBuf)> {
    if !cfg!(target_os = "linux") {
        skip("escape tests require Linux");
        return None;
    }
    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("ws");
    fs::create_dir_all(&workspace).unwrap();
    let mut settings = Settings {
        backend: Backend::LinuxNative,
        ..Settings::default()
    };
    let probe_dir = probe_exe()
        .parent()
        .expect("kekkai-probe has a parent directory")
        .to_path_buf();
    settings.readable_roots.push(probe_dir);
    match kekkai::health(&settings) {
        Health::Ok(_) => Some((settings, tmp, workspace)),
        Health::Warning(message) | Health::Error(message) => {
            skip(&format!("linux_native unavailable: {message}"));
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

fn denied(output: &Output, what: &str) {
    assert!(
        !output.status.success(),
        "{what} succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn symlink_to_outside_path_is_denied() {
    let Some((settings, tmp, workspace)) = linux_native_ready() else {
        return;
    };
    let secret = tmp.path().join("secret.txt");
    fs::write(&secret, "plane-token\n").unwrap();
    let link = workspace.join("link");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&secret, &link).unwrap();
    #[cfg(not(unix))]
    {
        let _ = (settings, link);
        skip("symlink escape test requires Unix");
        return;
    }
    #[cfg(unix)]
    {
        let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
        let output = run(&sandbox, probe(&["read", link.to_str().unwrap()]));
        denied(&output, "read through symlink to outside path");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            !stdout.contains("plane-token"),
            "secret leaked on stdout: {stdout}"
        );
    }
}

#[test]
fn dotdot_write_outside_workspace_is_denied() {
    let Some((settings, tmp, workspace)) = linux_native_ready() else {
        return;
    };
    let outside = tmp.path().join("outside.txt");
    let trick = workspace.join("..").join("outside.txt");
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let output = run(&sandbox, probe(&["write", trick.to_str().unwrap()]));
    assert!(
        !outside.exists(),
        "write escaped through .. to {}",
        outside.display()
    );
    denied(&output, "write via .. outside the workspace");
}

#[test]
fn proc_self_root_outside_path_is_denied() {
    let Some((mut settings, tmp, workspace)) = linux_native_ready() else {
        return;
    };
    // Grant /proc so the open can walk the magic link; the outside inode
    // must still be denied.
    settings.readable_roots.push(PathBuf::from("/proc"));
    let secret = tmp.path().join("proc-secret.txt");
    fs::write(&secret, "plane-token\n").unwrap();
    let via_proc = format!("/proc/self/root{}", secret.display());
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let output = run(&sandbox, probe(&["read", &via_proc]));
    denied(&output, "read via /proc/self/root to an outside path");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("plane-token"),
        "secret leaked on stdout: {stdout}"
    );
}

#[test]
fn ptrace_is_denied() {
    let Some((settings, _tmp, workspace)) = linux_native_ready() else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let output = run(&sandbox, probe(&["ptrace"]));
    denied(&output, "ptrace");
}

#[test]
fn io_uring_setup_is_denied() {
    let Some((settings, _tmp, workspace)) = linux_native_ready() else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let output = run(&sandbox, probe(&["io-uring"]));
    denied(&output, "io_uring_setup");
}

#[test]
fn missing_binary_is_a_spawn_error() {
    let Some((settings, _tmp, workspace)) = linux_native_ready() else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let mut cmd = Command::new(workspace.join("no-such-bin"));
    sandbox.apply(&mut cmd).expect("apply");
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    match cmd.spawn() {
        Err(_) => {}
        Ok(mut child) => {
            let status = child.wait().expect("wait");
            panic!("spawn of a missing binary succeeded: {status:?}");
        }
    }
}

#[test]
fn inherited_extra_fd_is_closed() {
    inherited_fd_denied(7, None);
}

#[test]
fn inherited_fd_above_open_files_limit_is_cloexec() {
    inherited_fd_denied(40, Some(32));
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

fn inherited_fd_denied(fd: i32, open_files: Option<u64>) {
    let Some((mut settings, tmp, workspace)) = linux_native_ready() else {
        return;
    };
    #[cfg(not(unix))]
    {
        let _ = (settings, tmp, workspace, fd, open_files);
        skip("inherited fd test requires Unix");
    }
    #[cfg(unix)]
    {
        settings.limits.open_files = open_files;
        let secret = tmp.path().join("fd-secret.txt");
        fs::write(&secret, "plane-token\n").unwrap();
        inherit_fd(&secret, fd);
        let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
        let output = run(&sandbox, probe(&["read-fd", &fd.to_string()]));
        denied(&output, "read of inherited extra fd");
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
}

#[test]
fn abstract_unix_connect_is_denied() {
    let Some((settings, _tmp, workspace)) = linux_native_ready() else {
        return;
    };
    let abi = kekkai::capabilities().landlock_abi.unwrap_or(0);
    if abi < 6 {
        skip("abstract unix scoping needs Landlock ABI 6");
        return;
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (settings, workspace);
        skip("abstract unix test requires Linux");
    }
    #[cfg(target_os = "linux")]
    {
        let mut settings = settings;
        settings.network = kekkai::Network::Allow;
        let name = format!("k14{}", std::process::id());
        let listen = match bind_abstract(name.as_bytes()) {
            Ok(fd) => fd,
            Err(error) => {
                skip(&format!("abstract unix bind: {error}"));
                return;
            }
        };
        let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
        let output = run(&sandbox, probe(&["connect-abstract", &name]));
        // SAFETY: parent listening socket created for this test.
        unsafe {
            libc::close(listen);
        }
        denied(&output, "connect to an abstract unix socket");
    }
}

#[cfg(target_os = "linux")]
fn bind_abstract(name: &[u8]) -> std::io::Result<i32> {
    // SAFETY: parent listener for the escape test.
    let sock = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: sockaddr_un is filled before bind(2).
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    if name.len() + 1 >= addr.sun_path.len() {
        // SAFETY: `sock` is the descriptor we created.
        unsafe {
            libc::close(sock);
        }
        return Err(std::io::Error::other("abstract name too long"));
    }
    addr.sun_path[0] = 0;
    for (i, b) in name.iter().enumerate() {
        addr.sun_path[i + 1] = *b as libc::c_char;
    }
    let addr_len = (std::mem::size_of::<libc::sa_family_t>() + 1 + name.len()) as u32;
    // SAFETY: `addr` is an abstract unix address of `addr_len` bytes.
    let rc = unsafe {
        libc::bind(
            sock,
            std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
            addr_len,
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        // SAFETY: `sock` is the descriptor we created.
        unsafe {
            libc::close(sock);
        }
        return Err(err);
    }
    // SAFETY: `sock` is bound.
    if unsafe { libc::listen(sock, 1) } != 0 {
        let err = std::io::Error::last_os_error();
        // SAFETY: `sock` is the descriptor we created.
        unsafe {
            libc::close(sock);
        }
        return Err(err);
    }
    Ok(sock)
}
