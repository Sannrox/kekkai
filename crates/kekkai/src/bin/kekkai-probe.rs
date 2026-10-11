//! Tiny child used by denial tests. Not a supported CLI.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

fn mmap_va(n: usize) -> ExitCode {
    #[cfg(unix)]
    {
        // SAFETY: anonymous private mapping; failure is reported to the parent.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                n,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            eprintln!("mmap: {}", std::io::Error::last_os_error());
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        }
    }
    #[cfg(not(unix))]
    {
        let _ = n;
        eprintln!("mmap-va requires Unix");
        ExitCode::from(2)
    }
}

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(action) = args.next() else {
        eprintln!(
            "usage: kekkai-probe write|read|env|socket|write-bytes|mmap-va|touch-bytes|fork-count|ignore-term|term-parent|fill-stdout|fill-stderr|fill-seq-stdout|fill-seq-stderr|connect-tcp|connect-unix|proxy-connect|ptrace|io-uring|read-fd|connect-abstract ..."
        );
        return ExitCode::from(2);
    };
    match action.as_str() {
        "write" => {
            let Some(path) = args.next() else {
                return ExitCode::from(2);
            };
            match fs::write(&path, b"pwned\n") {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("write {path}: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        "read" => {
            let Some(path) = args.next() else {
                return ExitCode::from(2);
            };
            match fs::read(&path) {
                Ok(bytes) => {
                    use std::io::Write;
                    let _ = std::io::stdout().write_all(&bytes);
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("read {path}: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        "env" => {
            let Some(name) = args.next() else {
                return ExitCode::from(2);
            };
            match env::var(&name) {
                Ok(value) => {
                    println!("{value}");
                    ExitCode::SUCCESS
                }
                Err(_) => {
                    eprintln!("env {name} unset");
                    ExitCode::FAILURE
                }
            }
        }
        "socket" => match std::net::UdpSocket::bind("127.0.0.1:0") {
            Ok(_) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("socket: {error}");
                ExitCode::FAILURE
            }
        },
        "write-bytes" => {
            let Some(path) = args.next() else {
                return ExitCode::from(2);
            };
            let Some(n) = args.next().and_then(|s| s.parse::<usize>().ok()) else {
                return ExitCode::from(2);
            };
            match fs::write(&path, vec![0_u8; n]) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("write-bytes {path}: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        "mmap-va" => {
            let Some(n) = args.next().and_then(|s| s.parse::<usize>().ok()) else {
                return ExitCode::from(2);
            };
            mmap_va(n)
        }
        "touch-bytes" => {
            let Some(n) = args.next().and_then(|s| s.parse::<usize>().ok()) else {
                return ExitCode::from(2);
            };
            let mut buf = vec![0_u8; n];
            for page in buf.chunks_mut(4096) {
                page[0] = 1;
            }
            std::hint::black_box(&buf);
            ExitCode::SUCCESS
        }
        "fork-count" => {
            let Some(want) = args.next().and_then(|s| s.parse::<u32>().ok()) else {
                return ExitCode::from(2);
            };
            #[cfg(unix)]
            {
                let mut live = Vec::new();
                for _ in 0..want {
                    // SAFETY: test child; pids.max must stop further forks.
                    let pid = unsafe { libc::fork() };
                    if pid < 0 {
                        break;
                    }
                    if pid == 0 {
                        loop {
                            // SAFETY: child waits to occupy a pid slot until the parent kills it.
                            unsafe {
                                libc::pause();
                            }
                        }
                    }
                    live.push(pid);
                }
                println!("{}", live.len());
                for pid in &live {
                    // SAFETY: `pid` is a child of this process.
                    unsafe {
                        libc::kill(*pid, libc::SIGKILL);
                        libc::waitpid(*pid, std::ptr::null_mut(), 0);
                    }
                }
                if (live.len() as u32) < want {
                    ExitCode::FAILURE
                } else {
                    ExitCode::SUCCESS
                }
            }
            #[cfg(not(unix))]
            {
                let _ = want;
                eprintln!("fork-count requires Unix");
                ExitCode::from(2)
            }
        }
        "ignore-term" => {
            let Some(pid_file) = args.next() else {
                return ExitCode::from(2);
            };
            #[cfg(unix)]
            {
                // SAFETY: test child ignores SIGTERM so the grace period must escalate.
                unsafe {
                    libc::signal(libc::SIGTERM, libc::SIG_IGN);
                }
                // SAFETY: grandchild occupies the process group until SIGKILL.
                let child = unsafe { libc::fork() };
                if child < 0 {
                    eprintln!("fork: {}", std::io::Error::last_os_error());
                    return ExitCode::FAILURE;
                }
                if child == 0 {
                    unsafe {
                        libc::signal(libc::SIGTERM, libc::SIG_IGN);
                    }
                    loop {
                        unsafe {
                            libc::pause();
                        }
                    }
                }
                let record = format!("{}\n{child}\n", std::process::id());
                if let Err(error) = fs::write(&pid_file, record) {
                    eprintln!("write {pid_file}: {error}");
                    return ExitCode::FAILURE;
                }
                loop {
                    unsafe {
                        libc::pause();
                    }
                }
            }
            #[cfg(not(unix))]
            {
                let _ = pid_file;
                eprintln!("ignore-term requires Unix");
                ExitCode::from(2)
            }
        }
        "term-parent" => {
            let Some(pid_file) = args.next() else {
                return ExitCode::from(2);
            };
            #[cfg(unix)]
            {
                // SAFETY: grandchild ignores SIGTERM; parent keeps the default so
                // SIGTERM reaps the leader while the child stays until SIGKILL.
                let child = unsafe { libc::fork() };
                if child < 0 {
                    eprintln!("fork: {}", std::io::Error::last_os_error());
                    return ExitCode::FAILURE;
                }
                if child == 0 {
                    unsafe {
                        libc::signal(libc::SIGTERM, libc::SIG_IGN);
                    }
                    loop {
                        unsafe {
                            libc::pause();
                        }
                    }
                }
                let record = format!("{}\n{child}\n", std::process::id());
                if let Err(error) = fs::write(&pid_file, record) {
                    eprintln!("write {pid_file}: {error}");
                    return ExitCode::FAILURE;
                }
                loop {
                    unsafe {
                        libc::pause();
                    }
                }
            }
            #[cfg(not(unix))]
            {
                let _ = pid_file;
                eprintln!("term-parent requires Unix");
                ExitCode::from(2)
            }
        }
        "fill-stdout" | "fill-stderr" | "fill-seq-stdout" | "fill-seq-stderr" => {
            let Some(n) = args.next().and_then(|s| s.parse::<usize>().ok()) else {
                return ExitCode::from(2);
            };
            let sequential = action.starts_with("fill-seq-");
            let mut chunk = vec![b'A'; 4096];
            let mut left = n;
            let mut seq = 0_u8;
            let stdout = action.ends_with("stdout");
            let out: &mut dyn std::io::Write = if stdout {
                &mut std::io::stdout()
            } else {
                &mut std::io::stderr()
            };
            while left > 0 {
                let take = left.min(chunk.len());
                if sequential {
                    for b in &mut chunk[..take] {
                        *b = seq;
                        seq = seq.wrapping_add(1);
                    }
                }
                if out.write_all(&chunk[..take]).is_err() {
                    return ExitCode::FAILURE;
                }
                left -= take;
            }
            let _ = out.flush();
            ExitCode::SUCCESS
        }
        "connect-tcp" => {
            let Some(host) = args.next() else {
                return ExitCode::from(2);
            };
            let Some(port) = args.next().and_then(|s| s.parse::<u16>().ok()) else {
                return ExitCode::from(2);
            };
            match std::net::TcpStream::connect((host.as_str(), port)) {
                Ok(_) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("connect-tcp {host}:{port}: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        "connect-unix" => {
            let Some(path) = args.next() else {
                return ExitCode::from(2);
            };
            #[cfg(unix)]
            {
                match std::os::unix::net::UnixStream::connect(&path) {
                    Ok(_) => ExitCode::SUCCESS,
                    Err(error) => {
                        eprintln!("connect-unix {path}: {error}");
                        ExitCode::FAILURE
                    }
                }
            }
            #[cfg(not(unix))]
            {
                let _ = path;
                eprintln!("connect-unix requires Unix");
                ExitCode::from(2)
            }
        }
        "proxy-connect" => {
            let Some(path) = args.next() else {
                return ExitCode::from(2);
            };
            let Some(host) = args.next() else {
                return ExitCode::from(2);
            };
            let Some(port) = args.next().and_then(|s| s.parse::<u16>().ok()) else {
                return ExitCode::from(2);
            };
            #[cfg(unix)]
            {
                use std::io::{Read, Write};
                let mut stream = match std::os::unix::net::UnixStream::connect(&path) {
                    Ok(stream) => stream,
                    Err(error) => {
                        eprintln!("proxy-connect {path}: {error}");
                        return ExitCode::FAILURE;
                    }
                };
                let req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
                if stream.write_all(req.as_bytes()).is_err() {
                    return ExitCode::FAILURE;
                }
                let mut buf = [0_u8; 256];
                let n = stream.read(&mut buf).unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]);
                if head.starts_with("HTTP/1.1 200") {
                    let _ = stream.write_all(b"ping");
                    let _ = stream.read(&mut buf);
                    ExitCode::SUCCESS
                } else {
                    eprintln!("proxy-connect {host}:{port}: {head}");
                    ExitCode::FAILURE
                }
            }
            #[cfg(not(unix))]
            {
                let _ = (path, host, port);
                eprintln!("proxy-connect requires Unix");
                ExitCode::from(2)
            }
        }
        "ptrace" => {
            #[cfg(target_os = "linux")]
            {
                // SAFETY: probe only; PTRACE_TRACEME is request 0.
                let rc = unsafe { libc::syscall(libc::SYS_ptrace, 0, 0, 0, 0) };
                if rc == 0 {
                    ExitCode::SUCCESS
                } else {
                    eprintln!("ptrace: {}", std::io::Error::last_os_error());
                    ExitCode::FAILURE
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                eprintln!("ptrace requires Linux");
                ExitCode::from(2)
            }
        }
        "io-uring" => {
            #[cfg(target_os = "linux")]
            {
                let mut params = [0u8; 256];
                // SAFETY: probe only; a denied io_uring_setup must not write params.
                let rc =
                    unsafe { libc::syscall(libc::SYS_io_uring_setup, 8usize, params.as_mut_ptr()) };
                if rc >= 0 {
                    ExitCode::SUCCESS
                } else {
                    eprintln!("io-uring: {}", std::io::Error::last_os_error());
                    ExitCode::FAILURE
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                eprintln!("io-uring requires Linux");
                ExitCode::from(2)
            }
        }
        "read-fd" => {
            let Some(fd) = args.next().and_then(|s| s.parse::<i32>().ok()) else {
                return ExitCode::from(2);
            };
            #[cfg(unix)]
            {
                use std::io::Write;
                let mut buf = [0u8; 64];
                // SAFETY: `fd` is the descriptor the parent asked us to read.
                let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
                if n > 0 {
                    let _ = std::io::stdout().write_all(&buf[..n as usize]);
                    ExitCode::SUCCESS
                } else {
                    eprintln!("read-fd {fd}: {}", std::io::Error::last_os_error());
                    ExitCode::FAILURE
                }
            }
            #[cfg(not(unix))]
            {
                let _ = fd;
                eprintln!("read-fd requires Unix");
                ExitCode::from(2)
            }
        }
        "connect-abstract" => {
            let Some(name) = args.next() else {
                return ExitCode::from(2);
            };
            #[cfg(target_os = "linux")]
            {
                let bytes = name.as_bytes();
                // SAFETY: probe child creating a unix stream socket.
                let sock = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
                if sock < 0 {
                    eprintln!(
                        "connect-abstract socket: {}",
                        std::io::Error::last_os_error()
                    );
                    return ExitCode::FAILURE;
                }
                // SAFETY: sockaddr_un is a C struct we fill before connect(2).
                let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
                addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
                if bytes.len() + 1 >= addr.sun_path.len() {
                    // SAFETY: `sock` is the descriptor we just created.
                    unsafe {
                        libc::close(sock);
                    }
                    eprintln!("connect-abstract name too long");
                    return ExitCode::from(2);
                }
                addr.sun_path[0] = 0;
                for (i, b) in bytes.iter().enumerate() {
                    addr.sun_path[i + 1] = *b as libc::c_char;
                }
                let addr_len = (std::mem::size_of::<libc::sa_family_t>() + 1 + bytes.len()) as u32;
                // SAFETY: `addr` is a valid abstract unix address of `addr_len` bytes.
                let rc = unsafe {
                    libc::connect(
                        sock,
                        std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                        addr_len,
                    )
                };
                let err = std::io::Error::last_os_error();
                // SAFETY: `sock` is the descriptor we created above.
                unsafe {
                    libc::close(sock);
                }
                if rc == 0 {
                    ExitCode::SUCCESS
                } else {
                    eprintln!("connect-abstract: {err}");
                    ExitCode::FAILURE
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = name;
                eprintln!("connect-abstract requires Linux");
                ExitCode::from(2)
            }
        }
        "pid" => {
            println!("{}", std::process::id());
            ExitCode::SUCCESS
        }
        "pause" => {
            #[cfg(unix)]
            {
                loop {
                    unsafe {
                        libc::pause();
                    }
                }
            }
            #[cfg(not(unix))]
            {
                eprintln!("pause requires Unix");
                ExitCode::from(2)
            }
        }
        "raise-as" => {
            #[cfg(unix)]
            {
                let lim = libc::rlimit {
                    rlim_cur: libc::RLIM_INFINITY,
                    rlim_max: libc::RLIM_INFINITY,
                };
                // SAFETY: raise RLIMIT_AS to infinity if the child still can.
                if unsafe { libc::setrlimit(libc::RLIMIT_AS, &lim) } == 0 {
                    ExitCode::SUCCESS
                } else {
                    eprintln!("raise-as: {}", std::io::Error::last_os_error());
                    ExitCode::FAILURE
                }
            }
            #[cfg(not(unix))]
            {
                eprintln!("raise-as requires Unix");
                ExitCode::from(2)
            }
        }
        "proc-exists" => {
            let Some(pid) = args.next() else {
                return ExitCode::from(2);
            };
            if PathBuf::from(format!("/proc/{pid}")).exists() {
                ExitCode::SUCCESS
            } else {
                eprintln!("proc-exists {pid}: missing");
                ExitCode::FAILURE
            }
        }
        "shm-open" => {
            let Some(name) = args.next() else {
                return ExitCode::from(2);
            };
            #[cfg(target_os = "linux")]
            {
                let c_name = match std::ffi::CString::new(name.as_str()) {
                    Ok(value) => value,
                    Err(_) => return ExitCode::from(2),
                };
                // SAFETY: `c_name` is a valid C string; O_RDWR without CREAT.
                let fd = unsafe { libc::shm_open(c_name.as_ptr(), libc::O_RDWR, 0o600) };
                if fd < 0 {
                    eprintln!("shm-open {name}: {}", std::io::Error::last_os_error());
                    ExitCode::FAILURE
                } else {
                    unsafe {
                        libc::close(fd);
                    }
                    ExitCode::SUCCESS
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = name;
                eprintln!("shm-open requires Linux");
                ExitCode::from(2)
            }
        }
        other => {
            eprintln!("unknown action {other}");
            ExitCode::from(2)
        }
    }
}
