# ADR 0002: Provide a reusable process sandbox library

- Status: Accepted
- Date: 2026-10-09
- Supersedes: —
- Related: [0003](0003-guest-backend-interface.md)

## Context

Programs that run untrusted or semi-trusted child processes (agent tool
calls, user-supplied data transforms, build steps, plugins) all need the same
boundary: limit what the child can read and write, block network access,
and cap its resources. Getting this right on Linux is subtle (Landlock ABI
detection, seccomp filters, async-signal-safe `pre_exec` code, cgroup
delegation), and copies of it drift apart and miss security fixes.

The initial implementation comes from the sandbox in
[Sannrox/shikigami](https://github.com/Sannrox/shikigami), where it was built
and tested for agent tool execution.

## Decision

1. kekkai is a standalone Rust library for sandboxing a child process on
   Linux. Its input is a settings value and a workspace root; its output is a
   prepared sandbox applied to a `std::process::Command` before spawn.
2. Backends, selected explicitly:
   - `none`: no isolation, for development only;
   - `rlimit`: resource limits and a process group;
   - `linux_native`: Landlock filesystem allowlist and a seccomp filter that
     denies network sockets, applied in `pre_exec`, without user namespaces
     or a helper binary.
   Opt-in cgroup v2 memory, pids, and CPU limits ship with those backends.
   Stronger guest isolation is [ADR 0003](0003-guest-backend-interface.md).
3. Fail closed: selecting a backend the host cannot provide is an error, never
   a silent downgrade. Host detection reports what the kernel supports.
4. kekkai has no dependency on any control plane, scheduler, or application.
   Deciding what runs, retries, and auditing belong to the caller.
5. kekkai is versioned on its own with semver. Any change to what is enforced
   is documented in the CHANGELOG.

## Consequences

- Several programs can share one reviewed implementation and get security
  fixes through a version bump.
- Denial tests (Landlock, seccomp, limits) live and run here.
- The first release ports the existing implementation as-is; redesigns come
  after.
- Linux only for real isolation. Other platforms get `none` or `rlimit`.

## Alternatives considered

- **Each program keeps its own copy.** Rejected: drifting copies of
  security-critical code.
- **Keep it as a module inside its original application.** Rejected: users
  would depend on an unrelated runtime, and releases would be coupled.
- **Use bubblewrap or nsjail.** Rejected for the first tier: they rely on
  unprivileged user namespaces, which several common distributions and
  default container profiles restrict. They remain options for a later
  backend.
