//! kekkai (結界): sandbox child processes on Linux.
//!
//! kekkai applies a filesystem allowlist (Landlock), a syscall and network
//! gate (seccomp) and resource limits to a `std::process::Command` before it
//! spawns.
//!
//! This is a skeleton: it defines the backend vocabulary only. The backends
//! are tracked in the repository issues and in
//! `docs/decisions/0002-reusable-process-sandbox-library.md`.

use std::fmt;

/// Isolation backend for spawned child processes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Backend {
    /// No isolation (development only).
    #[default]
    None,
    /// Unix resource limits and a process group, no filesystem or network rules.
    Rlimit,
    /// Landlock filesystem rules plus a seccomp socket gate, applied in `pre_exec`.
    LinuxNative,
}

impl fmt::Display for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Backend::None => "none",
            Backend::Rlimit => "rlimit",
            Backend::LinuxNative => "linux_native",
        })
    }
}

/// Health of a configured backend on the current host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Health {
    Ok(String),
    Warning(String),
    Error(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_names_are_stable() {
        assert_eq!(Backend::None.to_string(), "none");
        assert_eq!(Backend::Rlimit.to_string(), "rlimit");
        assert_eq!(Backend::LinuxNative.to_string(), "linux_native");
        assert_eq!(Backend::default(), Backend::None);
    }
}
