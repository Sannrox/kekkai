//! Opt-in cgroup v2 limits: `memory.max`, optional `memory.high`, `pids.max`,
//! and `cpu.max`. Applied by writing `0` into `cgroup.procs` in `pre_exec`.

use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::{Backend, CgroupLimits, ChildUsage, Error};

const DEFAULT_CPU_PERIOD_US: u64 = 100_000;

#[derive(Debug)]
pub(super) struct CgroupPrepared {
    dir: PathBuf,
    procs: OwnedFd,
}

impl Drop for CgroupPrepared {
    fn drop(&mut self) {
        let _ = fs::write(self.dir.join("cgroup.kill"), b"1");
        for _ in 0..20 {
            if fs::remove_dir(&self.dir).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl CgroupPrepared {
    pub(super) fn procs_fd(&self) -> i32 {
        self.procs.as_raw_fd()
    }

    pub(super) fn usage(&self) -> ChildUsage {
        ChildUsage {
            oom_killed: oom_kill_count(&self.dir).unwrap_or(0) > 0,
            memory_peak_bytes: read_u64_file(&self.dir.join("memory.peak")),
            cpu_usec: cpu_usage_usec(&self.dir),
            timed_out: false,
        }
    }

    pub(super) fn kill(&self) {
        let _ = fs::write(self.dir.join("cgroup.kill"), b"1");
    }
}

/// Join the prepared cgroup. Async-signal-safe: `write` only.
pub(super) fn join(procs_fd: i32) -> io::Result<()> {
    let buf = b"0\n";
    loop {
        // SAFETY: `procs_fd` is an inherited writable `cgroup.procs` descriptor.
        // `write` is async-signal-safe.
        let n = unsafe { libc::write(procs_fd, buf.as_ptr().cast(), buf.len()) };
        if n < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(error);
        }
        if n != buf.len() as isize {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        return Ok(());
    }
}

pub(super) fn probe(root: Option<&Path>) -> Result<PathBuf, Error> {
    probe_with(Backend::Rlimit, root)
}

pub(super) fn probe_with(backend: Backend, root: Option<&Path>) -> Result<PathBuf, Error> {
    let mount = cgroup2_mount()
        .ok_or_else(|| Error::unavailable(backend, "cgroup v2 is not mounted on this host"))?;
    let parent = match root {
        Some(path) => {
            if !path.is_absolute() {
                return Err(Error::invalid(format!(
                    "cgroup_root `{}` must be an absolute path",
                    path.display()
                )));
            }
            path.to_path_buf()
        }
        None => current_cgroup_dir(backend, &mount)?,
    };
    if !parent.join("cgroup.controllers").is_file() {
        return Err(Error::unavailable(
            backend,
            format!(
                "cgroup_root `{}` is not a cgroup v2 directory",
                parent.display()
            ),
        ));
    }
    let probe_dir = parent.join(format!(
        ".kekkai-cgroup-probe-{}-{}",
        std::process::id(),
        nanos()
    ));
    fs::create_dir(&probe_dir).map_err(|error| {
        Error::unavailable(
            backend,
            format!(
                "no delegated cgroup v2 subtree at `{}`: {error}",
                parent.display()
            ),
        )
    })?;
    let write = fs::write(probe_dir.join("memory.max"), b"max")
        .and_then(|_| fs::write(probe_dir.join("pids.max"), b"max"));
    let _ = fs::remove_dir(&probe_dir);
    write.map_err(|error| {
        Error::unavailable(
            backend,
            format!(
                "delegated cgroup `{}` cannot set memory.max/pids.max (enable memory and pids in cgroup.subtree_control): {error}",
                parent.display()
            ),
        )
    })?;
    Ok(parent)
}

pub(super) fn prepare(
    backend: Backend,
    limits: &CgroupLimits,
    root: Option<&Path>,
) -> Result<CgroupPrepared, Error> {
    let parent = probe_with(backend, root)?;
    let dir = parent.join(format!("kekkai-{}-{}", std::process::id(), nanos()));
    fs::create_dir(&dir).map_err(|error| {
        Error::unavailable(
            backend,
            format!("create cgroup `{}`: {error}", dir.display()),
        )
    })?;
    if let Err(error) = apply_limits(backend, &dir, limits) {
        let _ = fs::remove_dir(&dir);
        return Err(error);
    }
    let procs = open_write(&dir.join("cgroup.procs")).map_err(|error| {
        let _ = fs::remove_dir(&dir);
        Error::unavailable(backend, format!("open cgroup.procs: {error}"))
    })?;
    Ok(CgroupPrepared { dir, procs })
}

fn apply_limits(backend: Backend, dir: &Path, limits: &CgroupLimits) -> Result<(), Error> {
    if let Some(bytes) = limits.memory_max {
        write_file(backend, dir.join("memory.max"), bytes.to_string())?;
    }
    if let Some(bytes) = limits.memory_high {
        write_file(backend, dir.join("memory.high"), bytes.to_string())?;
    }
    if let Some(pids) = limits.pids_max {
        write_file(backend, dir.join("pids.max"), pids.to_string())?;
    }
    if let Some(quota) = limits.cpu_quota_us {
        let period = limits.cpu_period_us.unwrap_or(DEFAULT_CPU_PERIOD_US);
        write_file(backend, dir.join("cpu.max"), format!("{quota} {period}"))?;
    }
    Ok(())
}

fn write_file(backend: Backend, path: PathBuf, contents: String) -> Result<(), Error> {
    fs::write(&path, contents.as_bytes())
        .map_err(|error| Error::unavailable(backend, format!("write {}: {error}", path.display())))
}

fn open_write(path: &Path) -> io::Result<OwnedFd> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "cgroup path contains NUL"))?;
    // SAFETY: `c_path` is a valid C string; O_CLOEXEC keeps the fd out of exec.
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn cgroup2_mount() -> Option<PathBuf> {
    let path = Path::new("/sys/fs/cgroup/cgroup.controllers");
    if path.is_file() {
        Some(PathBuf::from("/sys/fs/cgroup"))
    } else {
        None
    }
}

fn current_cgroup_dir(backend: Backend, mount: &Path) -> Result<PathBuf, Error> {
    let text = fs::read_to_string("/proc/self/cgroup")
        .map_err(|error| Error::unavailable(backend, format!("read /proc/self/cgroup: {error}")))?;
    let rel = text
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| Error::unavailable(backend, "no cgroup v2 path in /proc/self/cgroup"))?;
    if rel == "/" {
        Ok(mount.to_path_buf())
    } else {
        Ok(mount.join(rel.trim_start_matches('/')))
    }
}

fn oom_kill_count(dir: &Path) -> Option<u64> {
    let text = fs::read_to_string(dir.join("memory.events")).ok()?;
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() == Some("oom_kill") {
            return parts.next()?.parse().ok();
        }
    }
    None
}

fn cpu_usage_usec(dir: &Path) -> Option<u64> {
    let text = fs::read_to_string(dir.join("cpu.stat")).ok()?;
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() == Some("usage_usec") {
            return parts.next()?.parse().ok();
        }
    }
    None
}

fn read_u64_file(path: &Path) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_skips_or_finds_a_delegated_subtree() {
        match probe(None) {
            Ok(path) => assert!(path.join("cgroup.controllers").is_file(), "{path:?}"),
            Err(error) => eprintln!("skip: cgroup v2 probe: {error}"),
        }
    }
}
