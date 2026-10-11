//! Tiny child used by denial tests. Not a supported CLI.

use std::env;
use std::fs;
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
            "usage: kekkai-probe write|read|socket|write-bytes|mmap-va|touch-bytes|fork-count|ignore-term|term-parent|fill-stdout|fill-stderr|fill-seq-stdout|fill-seq-stderr ..."
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
        other => {
            eprintln!("unknown action {other}");
            ExitCode::from(2)
        }
    }
}
