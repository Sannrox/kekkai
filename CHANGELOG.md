# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/). Any change to what the
sandbox enforces is listed here.

## [Unreleased]

### Added

- `kekkai run` CLI: flags or a JSON settings file in, `Sandbox::prepare` /
  `spawn` of a real command out. The child inherits stdio. After it
  exits, a JSON `RunReport` (`schema_version` 1) is written to stderr
  (or `--report PATH`, `--json` for stdout). The process exit code is
  the child's (or `128+N` on signal). Usage and prepare/apply/spawn
  failures exit 2. Default backend is `linux_native` on Linux, `macos`
  on macOS, `rlimit` elsewhere; `--backend` and a settings `backend`
  key override. There is no silent downgrade.
- `macos` backend: Seatbelt filesystem allowlist and network deny/allow,
  applied in `pre_exec` via `sandbox_init`. Path roles match
  `linux_native` (`inputs`, `output`, extra roots, scratch `TMPDIR`).
  System read/exec is `/usr/bin`, `/usr/lib`, `/usr/sbin`, `/usr/libexec`,
  `/usr/share`, `/bin`, `/sbin`, `/System/Library`, and the root directory inode
  (not a tree grant; `/usr/local` stays denied). When `output` is set the
  workspace is not writable. Scratch is an exclusive `0700` directory.
  `Allowlist`, `Loopback`, namespaces, cgroup, devices, and syscall
  profiles stay Linux-only (`Error::Invalid`). Missing support is
  `Error::Unsupported`. CI runs denial tests on a macOS runner.
- `none`, `rlimit`, and `linux_native` backends: `Settings` in,
  `Sandbox::prepare` out, `apply` on `std::process::Command` before spawn.
- Landlock filesystem allowlist with ABI 3 as the floor, a seccomp socket
  gate when `Network::Deny`, rlimits, and a child process group.
- Sandbox overhead benches (`cargo bench --bench overhead`): `prepare` +
  `apply` + spawn `/bin/true` + `finish` for each backend and opt-in
  feature, with p50/p95/p99 and sequential/parallel jobs per second. A
  scheduled Linux job fails when p95 exceeds 20% of the checked-in
  runner baseline. Published budgets: `rlimit` ≤ 2 ms p95 overhead,
  `linux_native` with namespaces + filesystem view + cgroup ≤ 25 ms,
  `linux_native` ≥ 50 sequential jobs/s.
- Explicit device grants (`Settings.devices`): extra character or block
  device nodes under `linux_native` / `userspace`. Default is none beyond
  `/dev/null`, `/dev/zero`, `/dev/urandom`, and `/dev/random`. Missing
  or non-device paths are `Error::Invalid`. Enforcement is Landlock
  (open, and ioctl on ABI 5+).
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
  kernel or KVM microVM).
- `Backend::Userspace` behind the `guest` cargo feature: a helper owns
  spawn (`Sandbox::spawn` / `Sandbox::command`). `apply` on a guest
  sandbox is `Error::Invalid`. A missing helper is `Error::Unavailable`;
  a non-Linux host is `Error::Unsupported`. There is no downgrade to
  `linux_native`. The default helper is `kekkai-guest` (or
  `Settings.guest_helper` / `KEKKAI_GUEST_HELPER`). The helper is the
  process-group leader; the payload stays in that group. The helper
  applies `linux_native` to the payload, waits, and removes scratch on a
  clean or `SIGTERM` exit. A KVM adapter is not shipped.
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
- Opt-in `FilesystemView::Isolate` (requires `Namespaces::Isolate`):
  read-only bind mounts for inputs, tmpfs scratch, overlay on the output
  tree (`OverlayPersist::Discard` or `Keep`), then a new root so paths
  outside the view do not exist. Missing overlay or pivot support is
  `Error::Unavailable`.
- Opt-in `Network::Loopback` (requires `Namespaces::Isolate`): the child
  runs in a private network namespace with only loopback up. External
  routes and host abstract unix sockets are unreachable. Missing netns
  support is `Error::Unavailable`.
- Named seccomp syscall profiles on `Settings.syscall_profile`
  (`SyscallProfile::Default`, `Strict`, `Python`). Default keeps the
  historical denylist. Strict and Python are per-architecture allowlists
  (x86_64 and aarch64). A syscall outside the selected allowlist is
  denied (`EPERM`) and recorded on `ChildUsage.violations` when user
  notification is available. `Network` still gates `socket()` even when
  the profile names it. Strict and Python require `linux_native`.
  `health` reports `syscalls=default|strict|python`. CI runs the test
  suite on aarch64 as well as x86_64.
- Cgroup `io.max` (per-device `IoMax`) and `cpu.weight` (1..=10000) on
  `CgroupLimits`. A missing `io` or `cpu` controller is
  `Error::Unavailable`. `Sandbox::usage` returns a live snapshot
  (`memory.current`, `cpu.stat`, `io.stat`, `pids.current`) while the
  child may still be running. `CgroupLimits` stays exhaustive; adding a
  field is a 0.x minor change.
- `Sandbox::report` returns a serializable `RunReport` (schema version 1)
  with a settings summary, `ChildUsage`, and timing. `to_json` /
  `from_json` round-trip. Optional `tracing` cargo feature records
  `kekkai.prepare`, `kekkai.apply`, and `kekkai.finish` spans.

### Changed

- `linux_native` denies `ptrace` in the seccomp filter.
- `linux_native` sets `FD_CLOEXEC` on file descriptors above stderr in
  `pre_exec` after Landlock and seccomp, so an inherited host fd does
  not survive `exec` and cannot bypass the filesystem allowlist. Pass
  data on stdin or through an allowed path.
