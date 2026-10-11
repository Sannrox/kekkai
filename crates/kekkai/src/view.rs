//! Isolated filesystem view: read-only binds, tmpfs scratch, overlay, pivot.
//!
//! Applied in `pre_exec` after namespace enter. Paths are precomputed in the
//! parent so the hook stays async-signal-safe.

use std::collections::BTreeSet;
use std::ffi::{CStr, CString};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{Backend, Error, OverlayPersist};

const SYSTEM_DIRS: &[&str] = &[
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/lib32",
    "/etc/alternatives",
    "/etc/ssl/certs",
];

const SYSTEM_FILES: &[&str] = &[
    "/etc/ld.so.cache",
    "/etc/passwd",
    "/etc/group",
    "/etc/nsswitch.conf",
    "/etc/localtime",
];

const DEV_NODES: &[&str] = &["/dev/null", "/dev/zero", "/dev/urandom", "/dev/random"];

/// Precomputed mounts captured into `pre_exec`.
#[derive(Debug)]
pub(super) struct ViewPlan {
    overlay_target: CString,
    overlay_data: CString,
    overlay_tmpfs: Option<CString>,
    overlay_upper: CString,
    overlay_work: CString,
    ro_binds: Vec<CString>,
    extra_binds: Vec<Bind>,
    tmpfs: Vec<CString>,
    newroot: CString,
    owned_scratch: Option<PathBuf>,
}

impl Drop for ViewPlan {
    fn drop(&mut self) {
        if let Some(path) = self.owned_scratch.take() {
            let _ = fs::remove_dir_all(path);
        }
    }
}

impl ViewPlan {
    pub(super) fn landlock_paths(&self) -> impl Iterator<Item = &CStr> {
        std::iter::once(self.overlay_target.as_c_str())
            .chain(self.tmpfs.iter().map(|path| path.as_c_str()))
    }
}

#[derive(Debug)]
struct Bind {
    src: CString,
    dest: CString,
    is_dir: bool,
}

/// Probe overlay + tmpfs + pivot inside an isolate namespace.
pub(super) fn probe() -> Result<(), Error> {
    if crate::ns::probe().is_err() {
        return Err(Error::unavailable(
            Backend::LinuxNative,
            "filesystem view requires namespace isolate",
        ));
    }
    let tmp = std::env::temp_dir().join(format!("kekkai-view-probe-{}", std::process::id()));
    let lower = tmp.join("lower");
    let ov = tmp.join("ov");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&lower).map_err(|error| {
        Error::unavailable(
            Backend::LinuxNative,
            format!("filesystem view probe: {error}"),
        )
    })?;
    std::fs::create_dir_all(&ov).map_err(|error| {
        Error::unavailable(
            Backend::LinuxNative,
            format!("filesystem view probe: {error}"),
        )
    })?;
    let plan = match prepare(
        &lower,
        &OverlayPersist::Discard,
        &ov,
        &[],
        &[],
        &[],
        &[],
        None,
    ) {
        Ok(plan) => plan,
        Err(error) => {
            let _ = std::fs::remove_dir_all(&tmp);
            return Err(error);
        }
    };
    let mut command = Command::new("true");
    // SAFETY: probe child only; enter_with_view is async-signal-safe.
    unsafe {
        command.pre_exec(move || crate::ns::enter_with_view(Some(&plan)));
    }
    let result = match command.status() {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(Error::unavailable(
            Backend::LinuxNative,
            format!("filesystem view probe exited {status}"),
        )),
        Err(error) => Err(Error::unavailable(
            Backend::LinuxNative,
            format!("filesystem view probe: {error}"),
        )),
    };
    let _ = std::fs::remove_dir_all(&tmp);
    result
}

#[allow(clippy::too_many_arguments)]
pub(super) fn prepare(
    overlay_target: &Path,
    overlay: &OverlayPersist,
    scratch: &Path,
    inputs: &[PathBuf],
    readable_roots: &[PathBuf],
    writable_roots: &[PathBuf],
    extra: &[PathBuf],
    owned_scratch: Option<PathBuf>,
) -> Result<ViewPlan, Error> {
    let overlay_target = fs::canonicalize(overlay_target).map_err(|error| {
        Error::invalid(format!(
            "filesystem view overlay target {}: {error}",
            overlay_target.display()
        ))
    })?;
    reject_mount_option_path(&overlay_target, "overlay target")?;
    let scratch = fs::canonicalize(scratch).map_err(|error| {
        Error::invalid(format!(
            "filesystem view scratch {}: {error}",
            scratch.display()
        ))
    })?;
    reject_mount_option_path(&scratch, "scratch")?;
    let tmpdir = scratch.join("tmp");
    fs::create_dir_all(&tmpdir)
        .map_err(|error| Error::invalid(format!("filesystem view tmpfs scratch: {error}")))?;
    reject_mount_option_path(&tmpdir, "scratch tmp")?;

    let (overlay_tmpfs, overlay_upper, overlay_work) = match overlay {
        OverlayPersist::Discard => {
            let base = scratch.join("ov");
            std::fs::create_dir_all(&base).map_err(|error| {
                Error::invalid(format!("filesystem view overlay tmpfs: {error}"))
            })?;
            (Some(base.clone()), base.join("upper"), base.join("work"))
        }
        OverlayPersist::Keep(path) => {
            let path = fs::canonicalize(path).map_err(|error| {
                Error::invalid(format!("overlay keep `{}`: {error}", path.display()))
            })?;
            if !path.is_dir() {
                return Err(Error::invalid(format!(
                    "overlay keep `{}` must be a directory",
                    path.display()
                )));
            }
            reject_mount_option_path(&path, "overlay keep")?;
            let upper = path.join("upper");
            let work = path.join("work");
            std::fs::create_dir_all(&upper)
                .map_err(|error| Error::invalid(format!("overlay keep upper: {error}")))?;
            std::fs::create_dir_all(&work)
                .map_err(|error| Error::invalid(format!("overlay keep work: {error}")))?;
            reject_mount_option_path(&upper, "overlay keep upper")?;
            reject_mount_option_path(&work, "overlay keep work")?;
            (None, upper, work)
        }
    };

    let overlay_data = format!(
        "lowerdir={},upperdir={},workdir={},userxattr",
        overlay_target.display(),
        overlay_upper.display(),
        overlay_work.display()
    );

    let mut ro_binds = Vec::new();
    for path in inputs {
        let path = fs::canonicalize(path).map_err(|error| {
            Error::invalid(format!("filesystem view input {}: {error}", path.display()))
        })?;
        ro_binds.push(cstring(&path)?);
    }

    let mut extra_binds = Vec::new();
    let mut seen = BTreeSet::new();
    let mut push_bind = |path: &Path, keep_dest: bool| -> Result<(), Error> {
        if !path.exists() {
            return Ok(());
        }
        let dest = if keep_dest {
            path.to_path_buf()
        } else {
            fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
        };
        if !seen.insert(dest.clone()) {
            return Ok(());
        }
        let src = fs::canonicalize(&dest).unwrap_or_else(|_| dest.clone());
        extra_binds.push(Bind {
            is_dir: dest.is_dir(),
            src: cstring(&src)?,
            dest: cstring(&dest)?,
        });
        Ok(())
    };

    for dir in SYSTEM_DIRS {
        push_bind(Path::new(dir), true)?;
    }
    for file in SYSTEM_FILES {
        push_bind(Path::new(file), true)?;
    }
    for dev in DEV_NODES {
        push_bind(Path::new(dev), true)?;
    }
    push_bind(Path::new("/proc"), true)?;
    push_bind(Path::new("/dev/shm"), true)?;
    push_bind(&overlay_target, false)?;
    push_bind(&scratch, false)?;
    for path in readable_roots {
        push_bind(path, false)?;
    }
    for path in writable_roots {
        push_bind(path, false)?;
    }
    for path in extra {
        push_bind(path, false)?;
    }
    for path in inputs {
        push_bind(path, false)?;
    }

    Ok(ViewPlan {
        overlay_target: cstring(&overlay_target)?,
        overlay_data: CString::new(overlay_data).map_err(|_| {
            Error::invalid("filesystem view overlay options contain an interior NUL")
        })?,
        overlay_tmpfs: overlay_tmpfs.as_deref().map(cstring).transpose()?,
        overlay_upper: cstring(&overlay_upper)?,
        overlay_work: cstring(&overlay_work)?,
        ro_binds,
        extra_binds,
        tmpfs: vec![cstring(&tmpdir)?],
        newroot: c"/tmp/kekkai-newroot".to_owned(),
        owned_scratch,
    })
}

fn reject_mount_option_path(path: &Path, label: &str) -> Result<(), Error> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.contains(&b',') || bytes.contains(&b':') || bytes.contains(&0) {
        return Err(Error::invalid(format!(
            "{label} `{}` cannot contain comma, colon, or NUL",
            path.display()
        )));
    }
    Ok(())
}

fn cstring(path: &Path) -> Result<CString, Error> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        Error::invalid(format!(
            "filesystem view path `{}` contains an interior NUL",
            path.display()
        ))
    })
}

/// Mount the view. Async-signal-safe.
pub(super) fn apply(plan: &ViewPlan) -> io::Result<()> {
    if let Some(tmpfs) = &plan.overlay_tmpfs {
        mkdir_p(tmpfs)?;
        mount_tmpfs(tmpfs)?;
        mkdir_p(&plan.overlay_upper)?;
        mkdir_p(&plan.overlay_work)?;
    }
    mount_overlay(&plan.overlay_target, &plan.overlay_data)?;
    for path in &plan.ro_binds {
        bind_ro(path)?;
    }
    for path in &plan.tmpfs {
        mount_tmpfs(path)?;
    }
    mkdir_p(&plan.newroot)?;
    // pivot_root requires a mount point, not a directory on an existing tmpfs.
    mount_tmpfs(&plan.newroot)?;
    for bind in &plan.extra_binds {
        bind_into_root(&plan.newroot, &bind.src, &bind.dest, bind.is_dir)?;
    }
    for path in &plan.ro_binds {
        bind_into_root(&plan.newroot, path, path, true)?;
    }
    for path in &plan.tmpfs {
        bind_into_root(&plan.newroot, path, path, true)?;
    }
    pivot(&plan.newroot)
}

fn mount_overlay(target: &CStr, data: &CStr) -> io::Result<()> {
    // SAFETY: overlay mount; data is a parent-prepared C string.
    let rc = unsafe {
        libc::mount(
            c"overlay".as_ptr(),
            target.as_ptr(),
            c"overlay".as_ptr(),
            0,
            data.as_ptr().cast(),
        )
    };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn mount_tmpfs(target: &CStr) -> io::Result<()> {
    mkdir_p(target)?;
    let rc = unsafe {
        libc::mount(
            c"tmpfs".as_ptr(),
            target.as_ptr(),
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

fn bind_ro(path: &CStr) -> io::Result<()> {
    bind_one(path, path)?;
    let flags = libc::MS_BIND | libc::MS_REC | libc::MS_REMOUNT | libc::MS_RDONLY;
    let rc = unsafe {
        libc::mount(
            std::ptr::null(),
            path.as_ptr(),
            std::ptr::null(),
            flags,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn bind_one(src: &CStr, dst: &CStr) -> io::Result<()> {
    let rc = unsafe {
        libc::mount(
            src.as_ptr(),
            dst.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REC,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn bind_into_root(root: &CStr, src: &CStr, dest: &CStr, is_dir: bool) -> io::Result<()> {
    let mut dest_buf = [0u8; 4096];
    let dest = join_root(root, dest, &mut dest_buf)?;
    if is_dir {
        mkdir_p(dest)?;
    } else {
        mkdir_parent(dest)?;
        touch(dest)?;
    }
    bind_one(src, dest)
}

fn join_root<'a>(root: &CStr, abs: &CStr, buf: &'a mut [u8]) -> io::Result<&'a CStr> {
    let root_b = root.to_bytes();
    let abs_b = abs.to_bytes();
    let n = root_b.len() + abs_b.len();
    if n + 1 > buf.len() {
        return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
    }
    buf[..root_b.len()].copy_from_slice(root_b);
    buf[root_b.len()..n].copy_from_slice(abs_b);
    buf[n] = 0;
    // SAFETY: we just wrote a trailing NUL at `n`.
    Ok(unsafe { CStr::from_bytes_with_nul_unchecked(&buf[..=n]) })
}

fn mkdir_parent(path: &CStr) -> io::Result<()> {
    let bytes = path.to_bytes();
    let Some(slash) = bytes.iter().rposition(|&b| b == b'/') else {
        return Ok(());
    };
    if slash == 0 {
        return Ok(());
    }
    let mut buf = [0u8; 4096];
    if slash >= buf.len() {
        return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
    }
    buf[..slash].copy_from_slice(&bytes[..slash]);
    buf[slash] = 0;
    // SAFETY: `buf[..=slash]` is a single NUL-terminated path.
    mkdir_p(unsafe { CStr::from_bytes_with_nul_unchecked(&buf[..=slash]) })
}

fn touch(path: &CStr) -> io::Result<()> {
    // SAFETY: create the bind target file if missing.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_CREAT | libc::O_WRONLY | libc::O_CLOEXEC,
            0o644,
        )
    };
    if fd < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EEXIST) {
            return Ok(());
        }
        return Err(err);
    }
    unsafe {
        libc::close(fd);
    }
    Ok(())
}

fn mkdir_p(path: &CStr) -> io::Result<()> {
    let bytes = path.to_bytes();
    if bytes.is_empty() {
        return Ok(());
    }
    let mut buf = [0u8; 4096];
    if bytes.len() >= buf.len() {
        return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
    }
    buf[..bytes.len()].copy_from_slice(bytes);
    buf[bytes.len()] = 0;
    let mut i = 1usize;
    while i < bytes.len() {
        if buf[i] == b'/' {
            buf[i] = 0;
            mkdir_one(buf.as_ptr().cast())?;
            buf[i] = b'/';
        }
        i += 1;
    }
    mkdir_one(buf.as_ptr().cast())
}

fn mkdir_one(path: *const libc::c_char) -> io::Result<()> {
    // SAFETY: `path` is a NUL-terminated stack buffer.
    let rc = unsafe { libc::mkdir(path, 0o755) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EEXIST) {
            return Err(err);
        }
    }
    Ok(())
}

fn pivot(newroot: &CStr) -> io::Result<()> {
    let mut old = [0u8; 4096];
    let old = join_root(newroot, c"/.old", &mut old)?;
    mkdir_p(old)?;
    // SAFETY: chdir/pivot_root/umount2 are async-signal-safe.
    if unsafe { libc::chdir(newroot.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::syscall(libc::SYS_pivot_root, c".".as_ptr(), c".old".as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::umount2(c"/.old".as_ptr(), libc::MNT_DETACH) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let _ = unsafe { libc::rmdir(c"/.old".as_ptr()) };
    if unsafe { libc::chdir(c"/".as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
