#![no_main]

use kekkai::{Backend, CgroupLimits, IoMax, Limits, Network, Sandbox, Settings, SyscallProfile};
use libfuzzer_sys::fuzz_target;
use std::path::PathBuf;

fuzz_target!(|data: &[u8]| {
    let mut settings = Settings::default();
    let b0 = data.first().copied().unwrap_or(0);
    settings.backend = match b0 % 3 {
        0 => Backend::None,
        1 => Backend::Rlimit,
        _ => Backend::LinuxNative,
    };
    settings.network = if b0 & 8 == 0 {
        Network::Deny
    } else {
        Network::Allow
    };
    settings.syscall_profile = match b0 % 3 {
        0 => SyscallProfile::Default,
        1 => SyscallProfile::Strict,
        _ => SyscallProfile::Python,
    };
    if data.len() > 8 {
        let n = u64::from(data[1]);
        settings.limits = Limits {
            cpu_time_secs: Some(n.max(1)),
            memory_mb: Some((n % 64).max(1)),
            user_processes: Some((n % 32).max(1)),
            file_size_mb: Some((n % 16).max(1)),
            open_files: Some((n % 256).max(1)),
        };
    }
    if data.len() > 16 && data[2] & 1 == 1 {
        settings.cgroup = CgroupLimits {
            memory_max: Some(1024 * 1024),
            cpu_weight: (data[2] & 2 == 2).then_some(100),
            io_max: (data[2] & 4 == 4).then_some(IoMax {
                major: 8,
                minor: 0,
                wbps: Some(1024),
                ..IoMax::default()
            }),
            ..CgroupLimits::default()
        };
    }
    if data.len() > 24 {
        let s = String::from_utf8_lossy(&data[8..]);
        let mid = s.len() / 2;
        settings.readable_roots.push(PathBuf::from(format!("/{s}")));
        settings
            .writable_roots
            .push(PathBuf::from(format!("/w{s}")));
        settings
            .inputs
            .push(PathBuf::from(format!("/i{}", &s[..mid])));
        settings.output = Some(PathBuf::from(format!("/o{}", &s[mid..])));
    }
    let Ok(tmp) = tempfile::tempdir() else {
        return;
    };
    let ws = tmp.path().join("ws");
    let _ = std::fs::create_dir_all(&ws);
    let _ = Sandbox::prepare(&settings, &ws);
});
