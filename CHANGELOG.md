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
