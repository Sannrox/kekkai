//! Per-architecture syscall numbers for allowlist profiles.
//!
//! Numbers come from the kernel x86_64 syscall table and the generic
//! aarch64 unistd. `u32::MAX` means the name does not exist on that ABI.

use crate::SyscallProfile;

/// `(name, x86_64, aarch64)`.
const NRS: &[(&str, u32, u32)] = &[
    ("read", 0, 63),
    ("write", 1, 64),
    ("open", 2, u32::MAX),
    ("close", 3, 57),
    ("stat", 4, u32::MAX),
    ("statfs", 137, 43),
    ("fstatfs", 138, 44),
    ("fstat", 5, 80),
    ("lstat", 6, u32::MAX),
    ("link", 86, u32::MAX),
    ("linkat", 265, 37),
    ("symlink", 88, u32::MAX),
    ("symlinkat", 266, 36),
    ("utimensat", 280, 88),
    ("fadvise64", 221, 223),
    ("times", 100, 153),
    ("truncate", 76, 45),
    ("poll", 7, u32::MAX),
    ("lseek", 8, 62),
    ("mmap", 9, 222),
    ("mprotect", 10, 226),
    ("munmap", 11, 215),
    ("brk", 12, 214),
    ("rt_sigaction", 13, 134),
    ("rt_sigprocmask", 14, 135),
    ("rt_sigreturn", 15, 139),
    ("ioctl", 16, 29),
    ("pread64", 17, 67),
    ("pwrite64", 18, 68),
    ("readv", 19, 65),
    ("writev", 20, 66),
    ("access", 21, u32::MAX),
    ("pipe", 22, u32::MAX),
    ("select", 23, u32::MAX),
    ("sched_yield", 24, 124),
    ("mremap", 25, 216),
    ("msync", 26, 227),
    ("mincore", 27, 232),
    ("madvise", 28, 233),
    ("dup", 32, 23),
    ("dup2", 33, u32::MAX),
    ("pause", 34, u32::MAX),
    ("nanosleep", 35, 101),
    ("getpid", 39, 172),
    ("sendfile", 40, 71),
    ("socket", 41, 198),
    ("connect", 42, 203),
    ("accept", 43, 202),
    ("sendto", 44, 206),
    ("recvfrom", 45, 207),
    ("sendmsg", 46, 211),
    ("recvmsg", 47, 212),
    ("shutdown", 48, 210),
    ("bind", 49, 200),
    ("listen", 50, 201),
    ("getsockname", 51, 204),
    ("getpeername", 52, 205),
    ("socketpair", 53, 199),
    ("setsockopt", 54, 208),
    ("getsockopt", 55, 209),
    ("clone", 56, 220),
    ("fork", 57, u32::MAX),
    ("vfork", 58, u32::MAX),
    ("execve", 59, 221),
    ("exit", 60, 93),
    ("wait4", 61, 260),
    ("kill", 62, 129),
    ("uname", 63, 160),
    ("fcntl", 72, 25),
    ("flock", 73, 32),
    ("fsync", 74, 82),
    ("fdatasync", 75, 83),
    ("ftruncate", 77, 46),
    ("getdents", 78, u32::MAX),
    ("getcwd", 79, 17),
    ("chdir", 80, 49),
    ("fchdir", 81, 50),
    ("rename", 82, u32::MAX),
    ("mkdir", 83, u32::MAX),
    ("rmdir", 84, u32::MAX),
    ("unlink", 87, u32::MAX),
    ("readlink", 89, u32::MAX),
    ("chmod", 90, u32::MAX),
    ("fchmod", 91, 52),
    ("umask", 95, 166),
    ("gettimeofday", 96, 169),
    ("getrlimit", 97, 163),
    ("getrusage", 98, 165),
    ("sysinfo", 99, 179),
    ("ptrace", 101, 117),
    ("getuid", 102, 174),
    ("getgid", 104, 176),
    ("getgroups", 115, 158),
    ("getresuid", 118, 148),
    ("getresgid", 120, 150),
    ("geteuid", 107, 175),
    ("getegid", 108, 177),
    ("setpgid", 109, 154),
    ("getppid", 110, 173),
    ("getpgid", 121, 155),
    ("getpgrp", 111, u32::MAX),
    ("setsid", 112, 157),
    ("rt_sigqueueinfo", 129, 138),
    ("sigaltstack", 131, 132),
    ("personality", 135, 92),
    ("prctl", 157, 167),
    ("arch_prctl", 158, u32::MAX),
    ("gettid", 186, 178),
    ("futex", 202, 98),
    ("mbind", 237, 235),
    ("get_mempolicy", 239, 236),
    ("set_mempolicy", 238, 237),
    ("sched_setaffinity", 203, 122),
    ("sched_getaffinity", 204, 123),
    ("getdents64", 217, 61),
    ("set_tid_address", 218, 96),
    ("restart_syscall", 219, 128),
    ("clock_gettime", 228, 113),
    ("clock_getres", 229, 114),
    ("clock_nanosleep", 230, 115),
    ("exit_group", 231, 94),
    ("epoll_wait", 232, u32::MAX),
    ("epoll_ctl", 233, 21),
    ("tgkill", 234, 131),
    ("waitid", 247, 95),
    ("openat", 257, 56),
    ("mkdirat", 258, 34),
    ("newfstatat", 262, 79),
    ("unlinkat", 263, 35),
    ("renameat", 264, 38),
    ("readlinkat", 267, 78),
    ("fchmodat", 268, 53),
    ("faccessat", 269, 48),
    ("pselect6", 270, 72),
    ("ppoll", 271, 73),
    ("unshare", 272, 97),
    ("set_robust_list", 273, 99),
    ("fallocate", 285, 47),
    ("accept4", 288, 242),
    ("eventfd2", 290, 19),
    ("epoll_create1", 291, 20),
    ("dup3", 292, 24),
    ("pipe2", 293, 59),
    ("preadv", 295, 69),
    ("pwritev", 296, 70),
    ("rt_tgsigqueueinfo", 297, 240),
    ("prlimit64", 302, 261),
    ("setns", 308, 268),
    ("getcpu", 309, 168),
    ("kcmp", 312, 272),
    ("renameat2", 316, 276),
    ("getrandom", 318, 278),
    ("memfd_create", 319, 279),
    ("execveat", 322, 281),
    ("membarrier", 324, 283),
    ("copy_file_range", 326, 285),
    ("statx", 332, 291),
    ("rseq", 334, 293),
    ("pidfd_send_signal", 424, 424),
    ("io_uring_setup", 425, 425),
    ("io_uring_enter", 426, 426),
    ("io_uring_register", 427, 427),
    ("clone3", 435, 435),
    ("close_range", 436, 436),
    ("openat2", 437, 437),
    ("faccessat2", 439, 439),
    ("epoll_pwait2", 441, 441),
    ("futex_waitv", 449, 449),
];

/// Syscalls the child still needs after the filter is installed: `sendmsg`
/// ships the user-notif listener to the parent, then `execve` loads the
/// payload. Omitting them deadlocks the handshake.
const ALWAYS: &[&str] = &[
    "close",
    "execve",
    "execveat",
    "exit",
    "exit_group",
    "sendmsg",
];

const STRICT: &[&str] = &[
    "arch_prctl",
    "brk",
    "clock_gettime",
    "close",
    "exit",
    "exit_group",
    "fcntl",
    "fstat",
    "futex",
    "getpid",
    "getrandom",
    "gettid",
    "ioctl",
    "lseek",
    "mmap",
    "mprotect",
    "munmap",
    "nanosleep",
    "newfstatat",
    "openat",
    "prctl",
    "pread64",
    "pwrite64",
    "read",
    "restart_syscall",
    "rseq",
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "set_tid_address",
    "write",
];

const PYTHON: &[&str] = &[
    "accept",
    "accept4",
    "access",
    "arch_prctl",
    "bind",
    "brk",
    "chdir",
    "chmod",
    "clock_getres",
    "clock_gettime",
    "clock_nanosleep",
    "clone",
    "clone3",
    "close",
    "close_range",
    "connect",
    "copy_file_range",
    "dup",
    "dup2",
    "dup3",
    "epoll_create1",
    "epoll_ctl",
    "epoll_pwait2",
    "epoll_wait",
    "eventfd2",
    "execve",
    "execveat",
    "exit",
    "exit_group",
    "faccessat",
    "faccessat2",
    "fadvise64",
    "fallocate",
    "fchdir",
    "fchmod",
    "fchmodat",
    "fcntl",
    "fdatasync",
    "flock",
    "fork",
    "fstat",
    "fstatfs",
    "fsync",
    "ftruncate",
    "futex",
    "futex_waitv",
    "getcwd",
    "getcpu",
    "getdents",
    "getdents64",
    "getegid",
    "geteuid",
    "getgid",
    "getgroups",
    "getresgid",
    "getresuid",
    "getpeername",
    "getpgid",
    "getpgrp",
    "getpid",
    "getppid",
    "getrandom",
    "getrlimit",
    "getrusage",
    "getsockname",
    "getsockopt",
    "gettid",
    "gettimeofday",
    "getuid",
    "ioctl",
    "kill",
    "listen",
    "lseek",
    "link",
    "linkat",
    "lstat",
    "madvise",
    "mbind",
    "get_mempolicy",
    "membarrier",
    "memfd_create",
    "mincore",
    "mkdir",
    "mkdirat",
    "mmap",
    "mprotect",
    "mremap",
    "msync",
    "munmap",
    "nanosleep",
    "newfstatat",
    "open",
    "openat",
    "openat2",
    "pause",
    "pipe",
    "pipe2",
    "poll",
    "ppoll",
    "prctl",
    "pread64",
    "preadv",
    "prlimit64",
    "pselect6",
    "pwrite64",
    "pwritev",
    "read",
    "readlink",
    "readlinkat",
    "readv",
    "recvfrom",
    "recvmsg",
    "rename",
    "renameat",
    "renameat2",
    "restart_syscall",
    "rmdir",
    "rseq",
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "sched_getaffinity",
    "sched_setaffinity",
    "sched_yield",
    "select",
    "sendfile",
    "sendmsg",
    "sendto",
    "set_mempolicy",
    "set_robust_list",
    "set_tid_address",
    "setsockopt",
    "shutdown",
    "sigaltstack",
    "socket",
    "socketpair",
    "stat",
    "statfs",
    "statx",
    "symlink",
    "symlinkat",
    "sysinfo",
    "times",
    "truncate",
    "tgkill",
    "umask",
    "uname",
    "unlink",
    "unlinkat",
    "utimensat",
    "vfork",
    "wait4",
    "waitid",
    "write",
    "writev",
];

pub(super) fn nr_of(name: &str) -> Option<u32> {
    for &(n, x86, arm) in NRS {
        if n == name {
            let nr = native(x86, arm);
            return (nr != u32::MAX).then_some(nr);
        }
    }
    None
}

pub(super) fn name_of(nr: i32) -> Option<&'static str> {
    let want = nr as u32;
    for &(n, x86, arm) in NRS {
        if native(x86, arm) == want {
            return Some(n);
        }
    }
    None
}

pub(super) fn allowlist(profile: SyscallProfile, out: &mut [u32]) -> usize {
    let names = match profile {
        SyscallProfile::Default => return 0,
        SyscallProfile::Strict => STRICT,
        SyscallProfile::Python => PYTHON,
    };
    let mut len = 0usize;
    for name in names.iter().copied().chain(ALWAYS.iter().copied()) {
        let Some(nr) = nr_of(name) else {
            continue;
        };
        let mut i = 0usize;
        while i < len && out[i] < nr {
            i += 1;
        }
        if i < len && out[i] == nr {
            continue;
        }
        if len + 1 > out.len() {
            break;
        }
        let mut j = len;
        while j > i {
            out[j] = out[j - 1];
            j -= 1;
        }
        out[i] = nr;
        len += 1;
    }
    len
}

fn native(x86: u32, arm: u32) -> u32 {
    if cfg!(target_arch = "x86_64") {
        x86
    } else if cfg!(target_arch = "aarch64") {
        arm
    } else {
        u32::MAX
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_cover_both_arches() {
        assert!(
            NRS.iter()
                .any(|&(n, x, a)| n == "read" && x == 0 && a == 63)
        );
        assert!(
            NRS.iter()
                .any(|&(n, x, a)| n == "write" && x == 1 && a == 64)
        );
        assert!(
            NRS.iter()
                .any(|&(n, _, a)| n == "arch_prctl" && a == u32::MAX)
        );
        assert!(
            NRS.iter()
                .any(|&(n, x, a)| n == "clone3" && x == 435 && a == 435)
        );
    }

    #[test]
    fn native_read_matches_libc() {
        assert_eq!(nr_of("read"), Some(libc::SYS_read as u32));
        assert_eq!(nr_of("write"), Some(libc::SYS_write as u32));
        assert_eq!(nr_of("exit_group"), Some(libc::SYS_exit_group as u32));
        assert_eq!(name_of(libc::SYS_ptrace as i32), Some("ptrace"));
    }

    #[test]
    fn python_is_a_superset_of_strict() {
        for name in STRICT {
            if nr_of(name).is_some() {
                assert!(PYTHON.contains(name), "python missing {name}");
            }
        }
    }

    #[test]
    fn allowlist_fits_and_is_sorted() {
        let mut buf = [0u32; 256];
        let n = allowlist(SyscallProfile::Python, &mut buf);
        assert!(n > 20 && n < 256, "python nrs={n}");
        for i in 1..n {
            assert!(buf[i - 1] < buf[i], "unsorted at {i}");
        }
        let strict = allowlist(SyscallProfile::Strict, &mut buf);
        assert!(strict > 8 && strict < n, "strict={strict} python={n}");
        assert_eq!(allowlist(SyscallProfile::Default, &mut buf), 0);
        let mut nrs = [0u32; 256];
        let n = allowlist(SyscallProfile::Strict, &mut nrs);
        for name in ["execve", "sendmsg", "exit_group", "close"] {
            let nr = nr_of(name).expect(name);
            assert!(
                nrs[..n].contains(&nr),
                "strict allowlist missing handshake/exec {name}"
            );
        }
    }

    #[test]
    fn allowlists_omit_escape_syscalls() {
        for name in [
            "personality",
            "ptrace",
            "unshare",
            "setns",
            "setpgid",
            "setsid",
            "io_uring_setup",
            "io_uring_enter",
            "io_uring_register",
            "pidfd_send_signal",
        ] {
            assert!(nr_of(name).is_some(), "{name} missing from nr table");
            assert!(!STRICT.contains(&name), "strict allows {name}");
            assert!(!PYTHON.contains(&name), "python allows {name}");
        }
    }
}
