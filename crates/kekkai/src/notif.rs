//! Seccomp user-notification supervisor: record denied syscalls and reply
//! `EPERM`. Landlock has no unprivileged denial fd; filesystem observation
//! stays unavailable unless a later kernel interface exists.

use std::io;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use crate::{SandboxViolation, ViolationKind};

const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;
const SECCOMP_GET_NOTIF_SIZES: libc::c_ulong = 3;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;

#[repr(C)]
struct NotifSizes {
    notif: u16,
    resp: u16,
    data: u16,
}

pub(super) fn probe_user_notif() -> bool {
    let mut sizes = NotifSizes {
        notif: 0,
        resp: 0,
        data: 0,
    };
    // SAFETY: `sizes` is the kernel `seccomp_notif_sizes` layout; the syscall
    // only writes those three u16 fields.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_GET_NOTIF_SIZES,
            0,
            std::ptr::addr_of_mut!(sizes),
        )
    };
    rc == 0 && sizes.notif >= 20 && sizes.resp >= 24
}

pub(super) struct ViolationCollector {
    inner: Arc<Inner>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

struct Inner {
    stop: AtomicBool,
    observed: AtomicBool,
    listener: AtomicI32,
    handshake: AtomicI32,
    child_sock: AtomicI32,
    violations: Mutex<Vec<SandboxViolation>>,
}

impl std::fmt::Debug for ViolationCollector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ViolationCollector")
            .field("observed", &self.inner.observed.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl ViolationCollector {
    /// Parent socket is CLOEXEC. The returned raw fd is the child's end and
    /// must stay inherited into `pre_exec`.
    pub(super) fn listen() -> io::Result<(Arc<Self>, RawFd)> {
        let mut pair = [0i32; 2];
        // SAFETY: `pair` has room for two fds. SOCK_CLOEXEC so later execs in
        // this process do not inherit the handshake sockets. Fork still copies
        // them into pre_exec, which closes the child end after the handshake.
        let rc = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                pair.as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        let inner = Arc::new(Inner {
            stop: AtomicBool::new(false),
            observed: AtomicBool::new(false),
            listener: AtomicI32::new(-1),
            handshake: AtomicI32::new(pair[0]),
            child_sock: AtomicI32::new(pair[1]),
            violations: Mutex::new(Vec::new()),
        });
        let thread_inner = inner.clone();
        let parent = pair[0];
        let thread = thread::spawn(move || supervisor(parent, thread_inner));
        Ok((
            Arc::new(Self {
                inner,
                thread: Mutex::new(Some(thread)),
            }),
            pair[1],
        ))
    }

    pub(super) fn observed(&self) -> bool {
        self.inner.observed.load(Ordering::SeqCst)
    }

    pub(super) fn violations(&self) -> Vec<SandboxViolation> {
        self.inner
            .violations
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }
}

impl Drop for ViolationCollector {
    fn drop(&mut self) {
        self.inner.stop.store(true, Ordering::SeqCst);
        for field in [
            &self.inner.listener,
            &self.inner.handshake,
            &self.inner.child_sock,
        ] {
            let fd = field.swap(-1, Ordering::SeqCst);
            if fd >= 0 {
                // SAFETY: swap takes ownership of an fd this collector stored.
                unsafe {
                    libc::close(fd);
                }
            }
        }
        if let Ok(mut thread) = self.thread.lock()
            && let Some(handle) = thread.take()
        {
            let _ = handle.join();
        }
    }
}

fn supervisor(sock: RawFd, inner: Arc<Inner>) {
    let mut dummy = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: dummy.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut cmsg_buf = [0u8; 256];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast();
    msg.msg_controllen = cmsg_buf.len() as _;
    let n = loop {
        // SAFETY: `msg` points at stack buffers we own for the duration of recvmsg.
        let n = unsafe { libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC) };
        if n >= 0 {
            break n;
        }
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted && !inner.stop.load(Ordering::SeqCst) {
            continue;
        }
        return;
    };
    if n < 1 || dummy[0] != 1 {
        return;
    }
    let mut listener = -1i32;
    // SAFETY: kernel filled `msg`; walk CMSG headers for SCM_RIGHTS.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                std::ptr::copy_nonoverlapping(
                    libc::CMSG_DATA(cmsg).cast::<i32>(),
                    &mut listener,
                    1,
                );
                break;
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    if listener < 0 {
        return;
    }
    // SAFETY: listener is a newly received fd; CLOEXEC so later execs cannot
    // inherit a CONTINUE-capable notification fd.
    unsafe {
        libc::fcntl(listener, libc::F_SETFD, libc::FD_CLOEXEC);
    }
    inner.listener.store(listener, Ordering::SeqCst);
    inner.observed.store(true, Ordering::SeqCst);
    let Some(sizes) = notif_sizes() else {
        close_stored_listener(&inner);
        return;
    };
    let recv_cmd = ioc_rw(0, sizes.notif as u32);
    let send_cmd = ioc_rw(1, sizes.resp as u32);
    let mut notif = vec![0u8; sizes.notif as usize];
    let mut resp = vec![0u8; sizes.resp as usize];
    while !inner.stop.load(Ordering::SeqCst) {
        notif.fill(0);
        // SAFETY: `notif` is sized from GET_NOTIF_SIZES; ioctl writes that many bytes.
        let rc = unsafe { libc::ioctl(listener, recv_cmd, notif.as_mut_ptr()) };
        if rc != 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted && !inner.stop.load(Ordering::SeqCst) {
                continue;
            }
            break;
        }
        let id = u64::from_ne_bytes(notif[0..8].try_into().unwrap_or([0; 8]));
        let nr = i32::from_ne_bytes(notif[16..20].try_into().unwrap_or([0; 4]));
        record_syscall(&inner.violations, nr);
        resp.fill(0);
        resp[0..8].copy_from_slice(&id.to_ne_bytes());
        // val stays 0; error = -EPERM at offset 16; flags at 20 stay 0.
        let err = (-libc::EPERM).to_ne_bytes();
        resp[16..20].copy_from_slice(&err);
        // SAFETY: `resp` is sized from GET_NOTIF_SIZES.
        let send_rc = unsafe { libc::ioctl(listener, send_cmd, resp.as_mut_ptr()) };
        if send_rc != 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted && !inner.stop.load(Ordering::SeqCst) {
                let _ = unsafe { libc::ioctl(listener, send_cmd, resp.as_mut_ptr()) };
            }
        }
    }
    close_stored_listener(&inner);
}

fn close_stored_listener(inner: &Inner) {
    let fd = inner.listener.swap(-1, Ordering::SeqCst);
    if fd >= 0 {
        // SAFETY: swap takes ownership of the stored listener fd.
        unsafe {
            libc::close(fd);
        }
    }
}

fn notif_sizes() -> Option<NotifSizes> {
    let mut sizes = NotifSizes {
        notif: 0,
        resp: 0,
        data: 0,
    };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_GET_NOTIF_SIZES,
            0,
            std::ptr::addr_of_mut!(sizes),
        )
    };
    (rc == 0).then_some(sizes)
}

fn ioc_rw(nr: u8, size: u32) -> libc::c_ulong {
    const IOC_READ: u32 = 2;
    const IOC_WRITE: u32 = 1;
    let dir = IOC_READ | IOC_WRITE;
    ((dir as libc::c_ulong) << 30)
        | ((b'!' as libc::c_ulong) << 8)
        | (nr as libc::c_ulong)
        | ((size as libc::c_ulong) << 16)
}

fn record_syscall(denials: &Mutex<Vec<SandboxViolation>>, nr: i32) {
    let detail = syscall_name(nr);
    let Ok(mut list) = denials.lock() else {
        return;
    };
    if let Some(existing) = list
        .iter_mut()
        .find(|v| v.kind == ViolationKind::Syscall && v.detail == detail)
    {
        existing.count = existing.count.saturating_add(1);
        return;
    }
    list.push(SandboxViolation {
        kind: ViolationKind::Syscall,
        detail,
        count: 1,
    });
}

fn syscall_name(nr: i32) -> String {
    crate::syscalls::name_of(nr)
        .map(str::to_string)
        .unwrap_or_else(|| format!("syscall:{nr}"))
}

pub(super) const SECCOMP_SET_MODE_FILTER_NR: libc::c_ulong = SECCOMP_SET_MODE_FILTER;
pub(super) const SECCOMP_FILTER_FLAG_NEW_LISTENER_NR: libc::c_ulong =
    SECCOMP_FILTER_FLAG_NEW_LISTENER;
