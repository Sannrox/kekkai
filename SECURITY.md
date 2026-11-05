# Security policy

kekkai is a sandbox, so a way for a sandboxed child to escape or bypass its
rules is a security vulnerability.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub private vulnerability
reporting: <https://github.com/Sannrox/kekkai/security/advisories/new>.
Do not open a public issue, pull request, or discussion.

Please include the OS and kernel version, the backend and settings used,
and a minimal reproduction.

We aim to acknowledge reports within a week and to publish a fix and an
advisory before the details become public.

## In scope

A child that does something its `Settings` deny, on a host where `health`
reported the backend as usable. For example:

- `linux_native`: reading or writing a path outside the Landlock
  allowlist, creating a network socket under `Network::Deny`, opening an
  IP socket under `Network::Allowlist`, a `CONNECT` through the allowlist
  proxy to a target that is not listed, a syscall the selected
  `SyscallProfile` denies succeeding, or an extra file descriptor above
  stderr surviving `exec`.
- `macos`: reading or writing a path outside the Seatbelt profile's
  allowlist, opening a network connection under `Network::Deny`, or an
  extra file descriptor above stderr surviving `exec`.
- `rlimit`, `linux_native`, and `macos`: exceeding a configured rlimit,
  or a cgroup limit where cgroups apply.
- Any backend: silently downgrading instead of failing with
  `Error::Unavailable` or `Error::Unsupported`.

## Out of scope

- Vulnerabilities in the kernel or OS mechanisms kekkai configures
  (Landlock, seccomp, namespaces, cgroups, Seatbelt). Report those
  upstream.
- Anything the configured `Settings` allow: `Network::Allow`, paths in
  `inputs`, `readable_roots`, `writable_roots`, or `devices`, the system
  read/exec trees each backend grants (see the
  [consumer guide](docs/consumer-guide.md#what-is-enforced)), and the
  `none` and `rlimit` backends, which apply no filesystem or network
  rules.
- What the embedder hands the child before spawn: stdin, stdout, stderr,
  environment variables, and anything readable through an allowed path.
- Limits listed under
  [What is not enforced](docs/consumer-guide.md#what-is-not-enforced),
  such as isolation on Windows.

## Supported versions

Only the latest release receives security fixes. See
[Releases](https://github.com/Sannrox/kekkai/releases/latest).

## Test suite

CI runs denial tests that spawn `kekkai-probe` through
`Sandbox::prepare` / `apply` on Linux and macOS. A case that needs a
kernel feature skips with an explicit `skip:` message; it never passes
when the host cannot enforce the rule.

The escape regression suite (`crates/kekkai/tests/escape.rs`) runs under
`linux_native` and keeps these attempts denied:

- a read through a symlink inside the workspace that points outside the
  allowlist
- a write through `..` out of the workspace
- a read through `/proc/self/root` of a file outside the allowlist, with
  `/proc` readable
- `ptrace`
- `io_uring_setup`
- a read of an inherited extra file descriptor, including one numbered
  above the `open_files` limit (already-open host fds above stderr are
  marked `CLOEXEC` in `pre_exec` and do not survive `exec`)
- a connect to an abstract unix socket under `Network::Allow` (skipped
  below Landlock ABI 6)

It also checks that spawning a missing binary is a spawn error.

`ptrace` and `io_uring_setup` are denied by the seccomp filter, which also
denies `io_uring_enter` and `io_uring_register`. Landlock does not revoke
access through an already-open descriptor, so extra descriptors are
marked `CLOEXEC` in `pre_exec` and an inherited host fd is not a
filesystem bypass.

Fuzz targets in `fuzz/` (not a workspace member) exercise `Settings` and
path-role handling. The `Fuzz` workflow runs them briefly on nightly for
pull requests and weekly; it is not a required merge check.
