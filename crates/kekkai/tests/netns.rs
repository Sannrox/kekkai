//! Loopback-only network namespace tests on the shipped prepare/apply path.
//!
//! Hosts without isolate namespaces or a private netns skip with `skip:`.
//! They never pass vacuously.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use kekkai::{Backend, Health, Namespaces, Network, Sandbox, Settings};

fn skip(reason: &str) {
    eprintln!("skip: {reason}");
}

fn probe_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kekkai-probe"))
}

fn loopback_or_skip(backend: Backend) -> Option<(Settings, tempfile::TempDir, PathBuf)> {
    if !cfg!(target_os = "linux") {
        skip("loopback netns requires Linux");
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
        .network(Network::Loopback)
        .readable_roots(if matches!(backend, Backend::LinuxNative) {
            vec![probe_dir]
        } else {
            Vec::new()
        })
        .build();
    match kekkai::health(&settings) {
        Health::Ok(_) => Some((settings, tmp, workspace)),
        Health::Warning(message) | Health::Error(message) => {
            skip(&format!("loopback netns unavailable: {message}"));
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
fn loopback_unavailable_without_netns() {
    if cfg!(target_os = "linux") && kekkai::capabilities().network_namespace {
        skip("host can create a loopback netns");
        return;
    }
    let settings = Settings::builder()
        .backend(if cfg!(unix) {
            Backend::Rlimit
        } else {
            Backend::LinuxNative
        })
        .namespaces(Namespaces::Isolate)
        .network(Network::Loopback)
        .build();
    let error = Sandbox::prepare(&settings, ".").unwrap_err();
    assert!(
        matches!(
            error,
            kekkai::Error::Unavailable { .. }
                | kekkai::Error::Unsupported { .. }
                | kekkai::Error::Invalid { .. }
        ),
        "expected typed failure, got {error}"
    );
}

#[test]
fn loopback_connect_works() {
    let Some((settings, _tmp, workspace)) = loopback_or_skip(Backend::LinuxNative) else {
        return;
    };
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let output = run(&sandbox, probe(&["loopback"]));
    assert!(
        output.status.success(),
        "loopback bind/connect failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn host_tcp_listener_is_unreachable() {
    let Some((settings, _tmp, workspace)) = loopback_or_skip(Backend::LinuxNative) else {
        return;
    };
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("host listener");
    let port = listener.local_addr().expect("local addr").port();
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let output = run(
        &sandbox,
        probe(&["connect-tcp", "127.0.0.1", &port.to_string()]),
    );
    drop(listener);
    assert!(
        !output.status.success(),
        "child reached the host loopback listener: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn host_abstract_unix_is_unreachable() {
    let Some((settings, _tmp, workspace)) = loopback_or_skip(Backend::LinuxNative) else {
        return;
    };
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (settings, workspace);
        skip("abstract unix requires Linux");
    }
    #[cfg(target_os = "linux")]
    {
        let name = format!("k18{}", std::process::id());
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
        assert!(
            !output.status.success(),
            "child reached a host abstract unix socket: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[cfg(target_os = "linux")]
fn bind_abstract(name: &[u8]) -> std::io::Result<i32> {
    // SAFETY: parent listener for the netns test.
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
        return Err(std::io::Error::from_raw_os_error(libc::ENAMETOOLONG));
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
    let rc = unsafe { libc::listen(sock, 1) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        // SAFETY: `sock` is the descriptor we created.
        unsafe {
            libc::close(sock);
        }
        return Err(err);
    }
    Ok(sock)
}
