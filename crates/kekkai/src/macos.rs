//! In-process `macos` isolation: a Seatbelt profile applied in the child's
//! `pre_exec` hook via `sandbox_init`.

use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr;
use std::sync::Arc;

use crate::{Error, Limits, Network};

// 0 means `profile` is an SBPL string. Apple's SANDBOX_NAMED (0x1) would
// treat the argument as a named builtin profile and reject this buffer.
const SANDBOX_PROFILE_STRING: u64 = 0;

unsafe extern "C" {
    fn sandbox_init(
        profile: *const libc::c_char,
        flags: u64,
        errorbuf: *mut *mut libc::c_char,
    ) -> i32;
}

#[derive(Debug)]
pub(super) struct MacosPrepared {
    pub(super) scratch: PathBuf,
    profile: CString,
}

impl Drop for MacosPrepared {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.scratch);
    }
}

pub(super) fn prepare(
    workspace: &Path,
    inputs: &[PathBuf],
    output: Option<&Path>,
    readable_roots: &[PathBuf],
    writable_roots: &[PathBuf],
    network: &Network,
) -> Result<Arc<MacosPrepared>, Error> {
    let workspace = canonicalize(workspace, "macos workspace")?;
    let inputs = canonicalize_all(inputs, "inputs")?;
    let readable_roots = canonicalize_all(readable_roots, "readable_roots")?;
    let writable_roots = canonicalize_all(writable_roots, "writable_roots")?;
    let output = match output {
        Some(path) => canonicalize(path, "output")?,
        None => workspace.clone(),
    };
    crate::reject_inputs_under_writables(
        &inputs,
        &[("output", output.as_path())],
        &writable_roots,
    )?;
    let scratch = create_scratch()?;
    if let Err(error) = crate::reject_inputs_under_writables(
        &inputs,
        &[("output", output.as_path()), ("scratch", scratch.as_path())],
        &writable_roots,
    ) {
        let _ = fs::remove_dir_all(&scratch);
        return Err(error);
    }
    let profile = match build_profile(
        &output,
        &scratch,
        &inputs,
        &readable_roots,
        &writable_roots,
        network,
    ) {
        Ok(profile) => profile,
        Err(error) => {
            let _ = fs::remove_dir_all(&scratch);
            return Err(error);
        }
    };
    Ok(Arc::new(MacosPrepared { scratch, profile }))
}

pub(super) fn apply(
    prepared: &MacosPrepared,
    command: &mut Command,
    limits: Limits,
) -> Result<(), Error> {
    command.env("TMPDIR", &prepared.scratch);
    let profile = prepared.profile.clone();
    // SAFETY: `pre_exec` runs between fork and exec. setpgid and setrlimit
    // are async-signal-safe. `sandbox_init` is the platform apply and is not
    // async-signal-safe (it may allocate); apply() is defined as `pre_exec`
    // hooks, so this is the install point. `profile` is a CString owned by
    // the closure. On failure the child returns before exec. errorbuf from a
    // failed `sandbox_init` is leaked; the child is exiting.
    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            close_extra_fds()?;
            crate::apply_rlimit_values(limits)?;
            let mut errorbuf: *mut libc::c_char = ptr::null_mut();
            if sandbox_init(profile.as_ptr(), SANDBOX_PROFILE_STRING, &mut errorbuf) != 0 {
                if !errorbuf.is_null() {
                    // `errorbuf` is a C string from `sandbox_init`.
                    // `strlen`/`write` are async-signal-safe; the child is
                    // exiting, so the buffer is not freed.
                    let len = libc::strlen(errorbuf);
                    let _ = libc::write(libc::STDERR_FILENO, errorbuf.cast(), len);
                }
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            Ok(())
        });
    }
    Ok(())
}

fn build_profile(
    output: &Path,
    scratch: &Path,
    inputs: &[PathBuf],
    extra_read: &[PathBuf],
    extra_write: &[PathBuf],
    network: &Network,
) -> Result<CString, Error> {
    // System read/exec matches linux_native: loader and POSIX dirs, not
    // `/usr/local`. `/System/Library` is enough for dyld; `/System` would
    // also match `/System/Volumes/Data` (the data volume). `(literal "/")`
    // is the root directory inode so dyld can stat `/`; it is not a tree
    // grant. Unfiltered `file-read-metadata` is required to walk parents
    // of allowlisted paths; it does not grant content reads.
    let mut rules = String::from(
        "(version 1)\n\
         (deny default)\n\
         (allow process-exec*)\n\
         (allow process-fork)\n\
         (allow signal (target self) (target same-sandbox))\n\
         (allow sysctl-read)\n\
         (allow file-read-metadata)\n\
         (allow file-read*\n\
           (subpath \"/usr/bin\")\n\
           (subpath \"/usr/lib\")\n\
           (subpath \"/usr/sbin\")\n\
           (subpath \"/usr/libexec\")\n\
           (subpath \"/usr/share\")\n\
           (subpath \"/bin\")\n\
           (subpath \"/sbin\")\n\
           (subpath \"/System/Library\")\n\
           (literal \"/\"))\n\
         (allow file-read* file-write*\n\
           (literal \"/dev/null\")\n\
           (literal \"/dev/zero\")\n\
           (literal \"/dev/urandom\")\n\
           (literal \"/dev/random\"))\n",
    );
    append_path_rule(&mut rules, "file-read* file-write*", output)?;
    if scratch != output {
        append_path_rule(&mut rules, "file-read* file-write*", scratch)?;
    }
    for path in extra_write {
        if path != output && path != scratch {
            append_path_rule(&mut rules, "file-read* file-write*", path)?;
        }
    }
    for path in inputs.iter().chain(extra_read) {
        append_path_rule(&mut rules, "file-read*", path)?;
    }
    match network {
        Network::Allow => rules.push_str("(allow network*)\n"),
        Network::Deny => rules.push_str("(deny network*)\n"),
        Network::Allowlist(_) | Network::Loopback => {
            return Err(Error::invalid(
                "Network::Allowlist and Network::Loopback are not applied by backend macos",
            ));
        }
    }
    CString::new(rules).map_err(|_| Error::invalid("macos profile contained an interior NUL"))
}

fn append_path_rule(rules: &mut String, ops: &str, path: &Path) -> Result<(), Error> {
    let encoded = sbpl_path(path)?;
    if path.is_dir() {
        rules.push_str(&format!("(allow {ops} (subpath \"{encoded}\"))\n"));
    } else {
        rules.push_str(&format!("(allow {ops} (literal \"{encoded}\"))\n"));
    }
    Ok(())
}

fn sbpl_path(path: &Path) -> Result<String, Error> {
    let text = path.to_str().ok_or_else(|| {
        Error::invalid(format!(
            "macos path `{}` is not valid UTF-8",
            path.display()
        ))
    })?;
    Ok(text.replace('\\', "\\\\").replace('"', "\\\""))
}

fn canonicalize(path: &Path, label: &str) -> Result<PathBuf, Error> {
    fs::canonicalize(path)
        .map_err(|error| Error::invalid(format!("{label} `{}`: {error}", path.display())))
}

fn canonicalize_all(paths: &[PathBuf], label: &str) -> Result<Vec<PathBuf>, Error> {
    paths.iter().map(|path| canonicalize(path, label)).collect()
}

/// Mark descriptors above stderr CLOEXEC so inherited host files do not
/// survive exec. Flags rather than close, matching `linux_native`.
fn close_extra_fds() -> io::Result<()> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit is async-signal-safe; we write into stack `lim`.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let last = if lim.rlim_cur == libc::RLIM_INFINITY {
        1_048_576
    } else {
        lim.rlim_cur.min(i32::MAX as libc::rlim_t)
    } as i32;
    for fd in 3..last {
        // SAFETY: F_SETFD is async-signal-safe; EBADF on a hole is ignored.
        unsafe {
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
    }
    Ok(())
}

fn create_scratch() -> Result<PathBuf, Error> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    for n in 0..128u32 {
        let path = std::env::temp_dir().join(format!("kekkai-macos-{pid}-{nanos}-{n}"));
        let c_path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| Error::invalid("macos scratch name contained an interior NUL"))?;
        // SAFETY: `c_path` is a valid C string; 0700 keeps TMPDIR private on a
        // shared host temp directory regardless of umask. Exclusive create
        // retries on EEXIST so two prepares in the same nanosecond still
        // get distinct directories.
        let rc = unsafe { libc::mkdir(c_path.as_ptr(), 0o700) };
        if rc == 0 {
            return fs::canonicalize(&path)
                .map_err(|error| Error::invalid(format!("macos scratch: {error}")));
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EEXIST) {
            return Err(Error::invalid(format!("macos scratch: {err}")));
        }
    }
    Err(Error::invalid(
        "macos scratch: exclusive create exhausted unique names",
    ))
}
