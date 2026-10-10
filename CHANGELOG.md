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
- ADR 0002: provide a reusable process sandbox library.
