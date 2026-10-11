//! Parent-side HTTP CONNECT proxy on a unix socket in the scratch directory.
//! The child may only create `AF_UNIX` sockets; cooperating clients use the
//! injected `*_PROXY` variables. Denied CONNECT targets are recorded.

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::{AllowHost, SandboxViolation, ViolationKind};

pub(super) struct EgressProxy {
    pub(super) path: PathBuf,
    denials: Arc<Mutex<Vec<SandboxViolation>>>,
    stop: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for EgressProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EgressProxy")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl EgressProxy {
    pub(super) fn start(path: PathBuf, allow: Vec<AllowHost>) -> io::Result<Arc<Self>> {
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path)?;
        listener.set_nonblocking(true)?;
        let denials = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let allow = Arc::new(allow);
        let denials_thread = denials.clone();
        let stop_thread = stop.clone();
        let thread =
            thread::spawn(move || accept_loop(listener, allow, denials_thread, stop_thread));
        Ok(Arc::new(Self {
            path,
            denials,
            stop,
            thread: Mutex::new(Some(thread)),
        }))
    }

    pub(super) fn violations(&self) -> Vec<SandboxViolation> {
        self.denials.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

impl Drop for EgressProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Ok(mut thread) = self.thread.lock()
            && let Some(handle) = thread.take()
        {
            let _ = handle.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

pub(super) fn host_allowed(allow: &[AllowHost], host: &str, port: u16) -> bool {
    allow.iter().any(|entry| {
        entry.host.eq_ignore_ascii_case(host) && entry.port.is_none_or(|want| want == port)
    })
}

/// Parse `host:port` or `[v6]:port` from a CONNECT target.
pub(super) fn parse_target(target: &str) -> Option<(String, u16)> {
    let target = target.trim();
    if let Some(rest) = target.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = tail.strip_prefix(':')?.parse().ok()?;
        if host.is_empty() || port == 0 {
            return None;
        }
        return Some((host.to_string(), port));
    }
    let (host, port) = target.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    if host.is_empty() || port == 0 || host.contains(':') {
        return None;
    }
    Some((host.to_string(), port))
}

fn accept_loop(
    listener: UnixListener,
    allow: Arc<Vec<AllowHost>>,
    denials: Arc<Mutex<Vec<SandboxViolation>>>,
    stop: Arc<AtomicBool>,
) {
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                let allow = allow.clone();
                let denials = denials.clone();
                thread::spawn(move || handle_client(stream, &allow, &denials));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }
}

fn handle_client(
    mut client: UnixStream,
    allow: &[AllowHost],
    denials: &Mutex<Vec<SandboxViolation>>,
) {
    let _ = client.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = client.set_write_timeout(Some(Duration::from_secs(10)));
    let Some(target) = read_connect_target(&mut client) else {
        let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
        return;
    };
    if !host_allowed(allow, &target.0, target.1) {
        record_denial(denials, &target.0, target.1);
        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
        return;
    }
    let mut upstream = match connect_upstream(&target.0, target.1) {
        Ok(stream) => stream,
        Err(_) => {
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
            return;
        }
    };
    if client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .is_err()
    {
        return;
    }
    let _ = client.set_read_timeout(None);
    let _ = client.set_write_timeout(None);
    let _ = upstream.set_read_timeout(None);
    let _ = upstream.set_write_timeout(None);
    splice(client, upstream);
}

fn connect_upstream(host: &str, port: u16) -> io::Result<TcpStream> {
    let mut last = None;
    for addr in (host, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
            Ok(stream) => return Ok(stream),
            Err(error) => last = Some(error),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addresses")))
}

fn read_connect_target(client: &mut UnixStream) -> Option<(String, u16)> {
    let mut buf = Vec::new();
    let mut tmp = [0_u8; 512];
    loop {
        let n = client.read(&mut tmp).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 8192 {
            return None;
        }
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let text = std::str::from_utf8(&buf).ok()?;
    let line = text.lines().next()?;
    let mut parts = line.split_whitespace();
    if parts.next()?.eq_ignore_ascii_case("CONNECT") {
        return parse_target(parts.next()?);
    }
    None
}

fn record_denial(denials: &Mutex<Vec<SandboxViolation>>, host: &str, port: u16) {
    let detail = format!("{host}:{port}");
    let Ok(mut list) = denials.lock() else {
        return;
    };
    if let Some(existing) = list.iter_mut().find(|v| v.detail == detail) {
        existing.count = existing.count.saturating_add(1);
        return;
    }
    list.push(SandboxViolation {
        kind: ViolationKind::Network,
        detail,
        count: 1,
    });
}

fn splice(mut a: UnixStream, mut b: TcpStream) {
    let mut a2 = a.try_clone().ok();
    let mut b2 = b.try_clone().ok();
    let up = thread::spawn(move || {
        let _ = io::copy(&mut a, &mut b);
        let _ = b.shutdown(std::net::Shutdown::Write);
    });
    if let (Some(ref mut a2), Some(ref mut b2)) = (&mut a2, &mut b2) {
        let _ = io::copy(b2, a2);
        let _ = a2.shutdown(std::net::Shutdown::Write);
    }
    let _ = up.join();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_host_port_and_v6() {
        assert_eq!(
            parse_target("example.com:443"),
            Some(("example.com".into(), 443))
        );
        assert_eq!(parse_target("[::1]:80"), Some(("::1".into(), 80)));
        assert_eq!(parse_target("127.0.0.1:9"), Some(("127.0.0.1".into(), 9)));
        assert_eq!(parse_target("no-port"), None);
        assert_eq!(parse_target("example.com:0"), None);
    }

    #[test]
    fn allowlist_matches_host_and_optional_port() {
        let allow = vec![
            AllowHost {
                host: "Example.COM".into(),
                port: Some(443),
            },
            AllowHost {
                host: "127.0.0.1".into(),
                port: None,
            },
        ];
        assert!(host_allowed(&allow, "example.com", 443));
        assert!(!host_allowed(&allow, "example.com", 80));
        assert!(!host_allowed(&allow, "93.184.216.34", 443));
        assert!(host_allowed(&allow, "127.0.0.1", 9));
        assert!(!host_allowed(&allow, "8.8.8.8", 53));
    }
}
