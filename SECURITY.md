# Security policy

kekkai is a sandbox, so a way for a sandboxed child to escape or bypass its
rules is a security vulnerability.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub private vulnerability
reporting: <https://github.com/Sannrox/kekkai/security/advisories/new>.
Do not open a public issue, pull request, or discussion.

Please include the kernel version, the backend and settings used, and a
minimal reproduction. In scope are, for example: writing or reading outside
the allowed paths, creating network sockets under `linux_native`, exceeding
configured limits, or a backend silently downgrading.

We aim to acknowledge reports within a week and to publish a fix and an
advisory before the details become public.

## Supported versions

Only the latest release receives security fixes. The current release is
`v0.1.0`.

## Test suite

Merge CI runs denial tests that spawn `kekkai-probe` through
`Sandbox::prepare` / `apply`. A case that needs a kernel feature skips with
an explicit `skip:` message; it never passes when the host cannot enforce
the rule.

The escape regression suite (`crates/kekkai/tests/escape.rs`) keeps these
attempts denied:

- a symlink inside the workspace that points outside the allowlist
- `..` traversal out of the workspace
- `/proc/self` paths to a file outside the allowlist
- `ptrace`
- `io_uring_setup`
- an inherited extra file descriptor (already-open host fds above stderr
  are marked `CLOEXEC` in `pre_exec` and do not survive `exec`)
- connect to an abstract unix socket (skipped below Landlock ABI 6)

`ptrace` is denied by the seccomp filter. Extra descriptors are marked
`CLOEXEC` after Landlock and seccomp are installed so an inherited host
fd is not a filesystem bypass.

Fuzz targets in `fuzz/` (not a workspace member) exercise `Settings` and
path-role handling. An optional GitHub Actions workflow runs them briefly
on nightly; that job is not a required merge check.
