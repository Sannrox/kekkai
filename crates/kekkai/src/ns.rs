//! Opt-in user, mount, PID, IPC, and UTS namespaces.
//!
//! Entered in `pre_exec` with async-signal-safe syscalls. A PID namespace
//! needs a fork after `unshare`: the original child waits and `_exit`s, the
//! grandchild is PID 1 and execs.

use std::ffi::CStr;
use std::io;
use std::os::unix::process::CommandExt;
use std::process::Command;

use crate::{Backend, Error};

/// True when this process can create an unprivileged user namespace and
/// the rest of the isolate set.
pub(super) fn probe() -> Result<(), Error> {
    let mut command = Command::new("true");
    // SAFETY: probe child only; `enter` is async-signal-safe.
    unsafe {
        command.pre_exec(enter);
    }
    match command.status() {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(Error::unavailable(
            Backend::LinuxNative,
            format!("namespace isolate probe exited {status}"),
        )),
        Err(error) => Err(Error::unavailable(
            Backend::LinuxNative,
            format!("namespace isolate probe: {error}"),
        )),
    }
}

/// Create the isolate namespaces. On success the caller is PID 1 in a fresh
/// PID namespace with `/proc` remounted. The original `Command` child becomes
/// a wait-proxy and does not return.
pub(super) fn enter() -> io::Result<()> {
    enter_with_view(None)
}

/// Isolate namespaces, then optionally the filesystem view, then drop caps.
pub(super) fn enter_with_view(view: Option<&crate::view::ViewPlan>) -> io::Result<()> {
    // SAFETY: `unshare` is async-signal-safe. `CLONE_NEWUSER` requires a
    // single-threaded process; `pre_exec` runs after fork.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
        return Err(io::Error::last_os_error());
    }
    write_id_maps()?;
    let rest = libc::CLONE_NEWNS | libc::CLONE_NEWPID | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS;
    // SAFETY: maps are installed so this process has CAP_SYS_ADMIN in the
    // new user namespace, which is required for the remaining unshares.
    if unsafe { libc::unshare(rest) } != 0 {
        return Err(io::Error::last_os_error());
    }
    remount_shm()?;
    if let Some(view) = view {
        crate::view::apply(view)?;
    }
    become_pid1()?;
    remount_proc()?;
    drop_privileges()?;
    Ok(())
}

fn write_id_maps() -> io::Result<()> {
    write_file(c"/proc/self/setgroups", b"deny")?;
    // SAFETY: getuid/getgid are async-signal-safe.
    let uid = unsafe { libc::getuid() } as u32;
    let gid = unsafe { libc::getgid() } as u32;
    write_map(c"/proc/self/uid_map", uid)?;
    write_map(c"/proc/self/gid_map", gid)?;
    Ok(())
}

fn write_map(path: &CStr, outer: libc::uid_t) -> io::Result<()> {
    let mut buf = [0u8; 32];
    buf[0] = b'0';
    buf[1] = b' ';
    let n = u32_dec(outer, &mut buf[2..]);
    let i = 2 + n;
    buf[i] = b' ';
    buf[i + 1] = b'1';
    buf[i + 2] = b'\n';
    write_file(path, &buf[..i + 3])
}

fn u32_dec(mut n: u32, out: &mut [u8]) -> usize {
    if n == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 10];
    let mut len = 0usize;
    while n > 0 {
        tmp[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    for i in 0..len {
        out[i] = tmp[len - 1 - i];
    }
    len
}

fn write_file(path: &CStr, data: &[u8]) -> io::Result<()> {
    // SAFETY: `path` is a static C string; open/write/close are
    // async-signal-safe.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut written = 0usize;
    while written < data.len() {
        let n = unsafe { libc::write(fd, data.as_ptr().add(written).cast(), data.len() - written) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            unsafe {
                libc::close(fd);
            }
            return Err(err);
        }
        written += n as usize;
    }
    unsafe {
        libc::close(fd);
    }
    Ok(())
}

fn become_pid1() -> io::Result<()> {
    // SAFETY: fork is async-signal-safe. The caller is the `Command` child.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid > 0 {
        // Ignore group SIGTERM so spawn_with_deadline can signal PID 1
        // first. Close every fd, including the standard library exec-error
        // pipe and inherited stdout, so `Command::spawn` returns and pipe
        // EOF tracks the exec'd child.
        unsafe {
            libc::signal(libc::SIGTERM, libc::SIG_IGN);
            libc::signal(libc::SIGINT, libc::SIG_IGN);
            libc::signal(libc::SIGHUP, libc::SIG_IGN);
        }
        close_all_fds();
        let mut status = 0;
        loop {
            // SAFETY: waitpid on the PID 1 child we just created.
            let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                unsafe {
                    libc::_exit(1);
                }
            }
            break;
        }
        let code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else if libc::WIFSIGNALED(status) {
            128 + libc::WTERMSIG(status)
        } else {
            1
        };
        unsafe {
            libc::_exit(code);
        }
    }
    // SAFETY: if the wait-proxy dies, PID 1 should not outlive it.
    unsafe {
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
    }
    // Exec as PID 2 so group SIGTERM is not swallowed by PID 1
    // (SIGNAL_UNKILLABLE). PID 1 only reaps.
    let payload = unsafe { libc::fork() };
    if payload < 0 {
        return Err(io::Error::last_os_error());
    }
    if payload > 0 {
        close_all_fds();
        let mut status = 0;
        loop {
            let rc = unsafe { libc::waitpid(payload, &mut status, 0) };
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                unsafe {
                    libc::_exit(1);
                }
            }
            break;
        }
        let code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else if libc::WIFSIGNALED(status) {
            128 + libc::WTERMSIG(status)
        } else {
            1
        };
        unsafe {
            libc::_exit(code);
        }
    }
    unsafe {
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
    }
    Ok(())
}

fn close_all_fds() {
    loop {
        // SAFETY: close_range with flags 0 closes the range. The wait-proxy
        // never execs, so the exec-error socket must actually close.
        let rc = unsafe { libc::syscall(libc::SYS_close_range, 0u32, u32::MAX, 0u32) };
        if rc == 0 {
            return;
        }
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::ENOSYS | libc::EINVAL) => break,
            _ => break,
        }
    }
    for fd in 0..1024 {
        unsafe {
            libc::close(fd);
        }
    }
}

fn remount_proc() -> io::Result<()> {
    // SAFETY: make mounts private so the proc remount stays in this namespace.
    let rc = unsafe {
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let rc = unsafe {
        libc::mount(
            c"proc".as_ptr(),
            c"/proc".as_ptr(),
            c"proc".as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn remount_shm() -> io::Result<()> {
    let shm = c"/dev/shm";
    // SAFETY: overlay a private tmpfs so POSIX shm is not the host's.
    let rc = unsafe {
        libc::mount(
            c"tmpfs".as_ptr(),
            shm.as_ptr(),
            c"tmpfs".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV,
            c"mode=1777".as_ptr().cast(),
        )
    };
    if rc == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() != Some(libc::ENOENT) {
        return Err(err);
    }
    // SAFETY: create the mount point if the host has no /dev/shm.
    if unsafe { libc::mkdir(shm.as_ptr(), 0o1777) } != 0 {
        let mkdir_err = io::Error::last_os_error();
        if mkdir_err.raw_os_error() != Some(libc::EEXIST) {
            return Err(mkdir_err);
        }
    }
    let rc = unsafe {
        libc::mount(
            c"tmpfs".as_ptr(),
            shm.as_ptr(),
            c"tmpfs".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV,
            c"mode=1777".as_ptr().cast(),
        )
    };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

const SECBIT_NOROOT: libc::c_ulong = 1;
const SECBIT_NOROOT_LOCKED: libc::c_ulong = 1 << 1;
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn drop_privileges() -> io::Result<()> {
    // SAFETY: lock out-root and drop the bounding set so exec as uid 0
    // does not keep CAP_SYS_RESOURCE to undo rlimits.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe {
        libc::prctl(
            libc::PR_SET_SECUREBITS,
            SECBIT_NOROOT | SECBIT_NOROOT_LOCKED,
            0,
            0,
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    for cap in 0..=40 {
        let rc = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) };
        if rc != 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINVAL) {
                return Err(err);
            }
        }
    }
    let mut header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    // SAFETY: empty V3 capset; header/data are stack.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_capset,
            std::ptr::addr_of_mut!(header),
            data.as_mut_ptr(),
        )
    };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
