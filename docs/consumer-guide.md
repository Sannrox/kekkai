# Consumer guide

kekkai is a library. You pass a [`Settings`](../crates/kekkai/src/lib.rs)
value and a workspace root into `Sandbox::prepare`, then apply the result
to a `std::process::Command` before spawn (or use a spawn helper). It does
not schedule work, pick a command, retry, or audit.

## Backends

Choose one. There is no fallback.

| Backend | Isolation | When to use |
| --- | --- | --- |
| `none` | None. `health` is a warning. | Development only. |
| `rlimit` | Unix rlimits and a new process group. No filesystem or socket rules. | Resource caps on a host that cannot run Landlock/seccomp, or as a first cut. |
| `linux_native` | Landlock filesystem allowlist (ABI 3 floor) plus a seccomp filter that denies `socket()` when `Network::Deny`. Rlimits and a process group. | Default for untrusted children on Linux. |

Opt-in cgroup v2 limits (`memory.max`, `memory.high`, `pids.max`, `cpu.max`)
attach to `rlimit` or `linux_native`. They require a writable delegated
subtree. Missing delegation is `Error::Unavailable`; kekkai never falls
back to `RLIMIT_AS`.

Guest isolation (a userspace kernel or a KVM microVM) is an accepted
interface, not a shipped adapter. See
[ADR 0003](decisions/0003-guest-backend-interface.md).

## Host detection

Call `kekkai::capabilities()` for what this process can enforce, and
`kekkai::health(&settings)` for the configured backend:

- `Health::Ok` — prepare can proceed.
- `Health::Warning` — prepare can proceed (`none` always warns).
- `Health::Error` — `Sandbox::prepare` returns `Error::Unsupported` (wrong
  OS) or `Error::Unavailable` (kernel or cgroup missing). Do not spawn.

`Error::Invalid` is a settings mistake (zero limits, relative extra roots,
overlapping path roles, cgroup on `none`).

## What is enforced

Under `linux_native`:

- Named path roles: `inputs` are read-only (read and execute). `output`
  is the writable directory; when unset, the workspace root is the
  output. Extra `readable_roots` get read and execute. Extra
  `writable_roots` get read and write. Paths must be absolute.
  Everything else is denied by Landlock. An input that is the same as,
  or lives under, a writable role (output, workspace-as-output,
  `writable_roots`, or scratch) is `Error::Invalid`.
- `TMPDIR` is a private scratch directory created for the run and
  removed when the sandbox is dropped. Each `prepare` gets a unique
  directory.
- `Network::Deny` (the default) makes `socket()` fail with `EPERM`.
  `Network::Allow` leaves sockets to the host; filesystem rules still apply.
  `Network::Allowlist` allows only `AF_UNIX` sockets, starts a CONNECT
  proxy on a unix socket in scratch, and injects `KEKKAI_PROXY` plus
  `ALL_PROXY` / `HTTP_PROXY` / `HTTPS_PROXY` as `unix://` URLs (and
  clears `NO_PROXY`). Clients that only understand `http://host:port`
  proxies cannot open IP sockets to reach a TCP proxy; they must speak
  CONNECT to `KEKKAI_PROXY`. Direct IP (including raw IP and DNS-bypass)
  fails at `socket()`. CONNECT matching is the target string, not DNS.
  Requires Landlock ABI 6 (abstract unix scoping). Denied CONNECT
  targets appear in `ChildUsage.violations`.
- Rlimits from `Settings.limits` are installed in `pre_exec`.
- The child is placed in its own process group so timeout and shutdown
  can signal the whole group.
- Denied syscalls are recorded on `ChildUsage.violations` when seccomp
  user notification is available (`health` contains
  `violations=user_notif`, `capabilities.seccomp_user_notif`).
  `violations_observed` is false when that path is missing; an empty
  list is then not a clean kernel run. Landlock filesystem denials have
  no unprivileged observer (`fs_violations=unavailable`). CONNECT
  denials from `Network::Allowlist` are always recorded as
  `ViolationKind::Network`.

Under `rlimit`, only rlimits and the process group apply.

When cgroup limits are set, the child joins the prepared cgroup in
`pre_exec`. After exit, `Sandbox::finish` reports `oom_killed`, peak
memory, and CPU usage.

`Sandbox::spawn_with_deadline` sends `SIGTERM` at a wall-clock limit,
waits `term_grace`, then `SIGKILL`s the process group and writes
`cgroup.kill`. `ChildUsage.timed_out` is true only on that path.
`Sandbox::spawn_with_deadline_captured` does the same while keeping
stdout and stderr under per-stream byte caps (head, tail, or both).
Overflow is drained so the child cannot fill the pipe.

`pre_exec` code is async-signal-safe: no allocation, locks, or logging.

## What is not enforced

- Letting the child open its own TCP/UDP sockets to listed hosts.
  `Network::Allowlist` is proxy-mediated: IP `socket()` stays denied.
- Scheduling, image management, or orchestration.
- What command to run, retries, or audit logs. Those belong to the caller.
- Real isolation on non-Linux hosts. `linux_native` is unsupported there;
  `rlimit` still applies Unix resource limits.
- A guest adapter. ADR 0003 is the interface only.
- Syscall allowlists beyond the socket gate, mount/PID/IPC/UTS namespaces,
  and filesystem views (bind, tmpfs, overlay). Those are later work.

## Recommended settings

**Data transform** (Python/DuckDB): `linux_native`, `Network::Deny`,
`inputs` = input directory, `output` or workspace = output directory,
`cgroup.memory_max` around 512 MiB. See [`examples/transform.rs`](../examples/transform.rs).

**Agent shell command**: `linux_native`, workspace = the run directory,
`spawn_with_deadline_captured` with a short wall-clock limit and per-stream
caps so a runaway child cannot pin memory or a pipe. See
[`examples/agent_shell.rs`](../examples/agent_shell.rs).

Call `health` before `prepare`. Treat `Error::Unavailable` as "do not run
this job here", not as a cue to switch backends.

## Failure modes

| Symptom | Cause |
| --- | --- |
| `Error::Unsupported` | Backend is not implemented on this OS. |
| `Error::Unavailable` | Kernel lacks Landlock ABI 3, seccomp, or a delegated cgroup v2 subtree. |
| `Error::Invalid` | Zero limits, relative roots, overlapping path roles, cgroup on `none`, `cpu_period_us` without quota. |
| Child `EACCES` / Landlock denial | Path not on the allowlist. |
| Child `EPERM` on `socket()` | `Network::Deny`, or IP sockets under `Allowlist`. |
| `ChildUsage.violations` with `ViolationKind::Network` | CONNECT to a host/port not on the allowlist. |
| `ChildUsage.violations` with `ViolationKind::Syscall` | Seccomp denied the named syscall (`socket`, …). |
| `violations_observed` is false | Kernel denials could not be recorded; do not treat an empty list as a clean run. |
| `timed_out` | Wall-clock helper expired; the group was killed. |
| `oom_killed` | cgroup `memory.max` (or `memory.events`) fired. |
| Truncated capture | Stream exceeded its byte cap; `dropped` is the discarded count. |

Denial tests in `crates/kekkai/tests/` spawn `kekkai-probe` through
`prepare` / `apply`. On hosts without the kernel feature they skip with
an explicit `skip:` message; they never pass vacuously.
