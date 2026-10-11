# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/). Any change to what the
sandbox enforces is listed here.

## [Unreleased]

### Added

- `none`, `rlimit`, and `linux_native` backends: `Settings` in,
  `Sandbox::prepare` out, `apply` on `std::process::Command` before spawn.
- Landlock filesystem allowlist with ABI 3 as the floor, a seccomp socket
  gate when `Network::Deny`, rlimits, and a child process group.
- Host capability detection (`capabilities`) and `health` reporting.
  Selecting a backend the host cannot provide returns `Error::Unsupported`
  or `Error::Unavailable`; there is no silent downgrade.
- Optional `tokio` cargo feature: `Sandbox::apply_tokio` for
  `tokio::process::Command`.
- Opt-in cgroup v2 limits (`memory.max`, `memory.high`, `pids.max`,
  `cpu.max`) on `rlimit` and `linux_native`. Missing delegation is an
  error; there is no fallback to `RLIMIT_AS`. `Sandbox::finish` reports
  `oom_killed`, peak memory, and CPU usage.
- ADR 0002: provide a reusable process sandbox library.
- ADR 0003: guest backend interface for per-run isolation (userspace
  kernel or KVM microVM). The crate does not ship an adapter yet.
- `Sandbox::spawn_with_deadline` (and `spawn_with_deadline_tokio`):
  wall-clock `SIGTERM`, then `SIGKILL` of the process group and
  `cgroup.kill`. `ChildUsage.timed_out` is set only when the deadline
  expires.
- `Sandbox::spawn_with_deadline_captured` (and
  `spawn_with_deadline_captured_tokio`): optional stdout and stderr
  capture with per-stream byte caps, head/tail/both retention, and a
  `truncated` marker plus dropped count. Overflow is drained so the
  child does not block on a full pipe.
- Consumer guide (`docs/consumer-guide.md`) and `examples/` for a
  read-only Python/DuckDB transform and an agent shell with deadline
  plus output caps. CI runs `cargo build --examples`.
- `Network::Allowlist`: the child may only create `AF_UNIX` sockets. A
  parent CONNECT proxy on a unix socket in scratch injects `*_PROXY`
  environment variables and permits listed hosts/ports. Direct IP
  sockets fail. Matching is by CONNECT target, not DNS. Denied CONNECT
  targets are recorded on `ChildUsage.violations`. Requires Landlock
  ABI 6.
- Named path roles on `Settings`: `inputs` (read-only) and `output`
  (writable directory; default is the workspace root). An input that
  overlaps a writable role is `Error::Invalid`. Scratch stays a unique
  per-run directory, exported as `TMPDIR`, and is removed when the
  sandbox is dropped.
- Sandbox violation reporting: seccomp user notification records denied
  syscalls on `ChildUsage.violations` (`ViolationKind::Syscall`) when
  the kernel supports it. `violations_observed` is false when the host
  cannot observe kernel denials, so an empty list is not a clean run.
  `health` reports `violations=user_notif|unavailable` and
  `fs_violations=unavailable` (Landlock has no unprivileged denial fd).
  CONNECT denials remain `ViolationKind::Network`.
- Escape regression suite: symlink, `..`, `/proc/self` paths, `ptrace`,
  `io_uring`, inherited extra file descriptors, and abstract unix sockets
  (Landlock ABI 6). cargo-fuzz targets for `Settings` and path handling,
  with an optional CI job that is not a required merge check.

- `Settings::builder`, `#[non_exhaustive]` on public enums and settings
  structs, `#![deny(missing_docs)]`, and `rust-version = "1.97.1"`. Adding
  a field to `Settings` is not a breaking change for builder callers.
  Enforcement changes stay versioned; they are never a patch-level surprise.
- Opt-in `Namespaces::Isolate`: user, mount, PID, IPC, and UTS namespaces
  with a private `/proc`. Requires unprivileged user namespaces. Missing
  support is `Error::Unavailable`; there is no silent fallback.

### Changed

- `linux_native` denies `ptrace` in the seccomp filter.
- `linux_native` sets `FD_CLOEXEC` on file descriptors above stderr in
  `pre_exec` after Landlock and seccomp, so an inherited host fd does
  not survive `exec` and cannot bypass the filesystem allowlist. Pass
  data on stdin or through an allowed path.
