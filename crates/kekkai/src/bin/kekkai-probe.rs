//! Tiny child used by denial tests. Not a supported CLI.

use std::env;
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(action) = args.next() else {
        eprintln!("usage: kekkai-probe write|read|socket|write-bytes ...");
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
        other => {
            eprintln!("unknown action {other}");
            ExitCode::from(2)
        }
    }
}
