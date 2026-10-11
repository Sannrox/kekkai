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

Opt-in cgroup v2 limits (`memory.max`, `memory.high`, `pids.max`, `cpu.max`,
`cpu.weight`, `io.max`) attach to `rlimit` or `linux_native`. They require
a writable delegated subtree. Missing delegation or a missing controller
is `Error::Unavailable`; kekkai never falls back to `RLIMIT_AS`.

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
  `Network::Loopback` (requires isolate namespaces) puts the child in a
  private network namespace with only loopback up. Host routes and host
  abstract unix sockets are gone. Missing netns support is
  `Error::Unavailable`.
- Rlimits from `Settings.limits` are installed in `pre_exec`.
- The child is placed in its own process group so timeout and shutdown
  can signal the whole group.
- File descriptors above stderr are marked `CLOEXEC` in `pre_exec` and
  do not survive `exec`. Pass data on stdin or through an allowed path,
  not an inherited fd.
- `ptrace` is denied, as are `io_uring_setup` / `io_uring_enter` /
  `io_uring_register`.
- `Settings.syscall_profile` selects the seccomp program under
  `linux_native`. `Default` is the historical denylist (those syscalls
  plus identity-change and namespace-escape). `Strict` is a small
  allowlist for a simple child. `Python` is sized for CPython and
  in-process analytics. Strict and Python require `linux_native`. A
  syscall outside the allowlist fails with `EPERM`. `Network` still
  gates `socket()` even when the profile names it. `health` reports
  `syscalls=default|strict|python`.
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
`pre_exec`. `Sandbox::usage` is a live snapshot (`memory.current`, CPU,
IO, pids). After exit, `Sandbox::finish` reports `oom_killed`, those
counters, and violations.

`Sandbox::spawn_with_deadline` sends `SIGTERM` at a wall-clock limit,
waits `term_grace`, then `SIGKILL`s the process group and writes
`cgroup.kill`. `ChildUsage.timed_out` is true only on that path.
`Sandbox::spawn_with_deadline_captured` does the same while keeping
stdout and stderr under per-stream byte caps (head, tail, or both).
Overflow is drained so the child cannot fill the pipe.

`Namespaces::Isolate` (opt-in on `rlimit` or `linux_native`) creates
user, mount, PID, IPC, and UTS namespaces and remounts `/proc`. The
child is PID 1 and does not see host processes or host IPC objects.
The host must allow unprivileged user namespaces; otherwise `health`
is an error and `prepare` returns `Error::Unavailable`.

`FilesystemView::Isolate` (requires isolate namespaces) bind-mounts
inputs read-only, puts scratch on tmpfs, and overlays the output tree.
`OverlayPersist::Discard` throws those writes away with the namespace;
`Keep(path)` stores them under `path/upper`. After pivot, paths outside
the view are gone (`ENOENT`), not merely denied.

`Network::Loopback` (requires isolate namespaces) unshares a network
namespace and brings loopback up. The child can use `127.0.0.1`; it
cannot reach host interfaces or host abstract unix sockets.

`pre_exec` code is async-signal-safe: no allocation, locks, or logging.

## What is not enforced

- Letting the child open its own TCP/UDP sockets to listed hosts.
  `Network::Allowlist` is proxy-mediated: IP `socket()` stays denied.
- Scheduling, image management, or orchestration.
- What command to run, retries, or audit logs. Those belong to the caller.
- Real isolation on non-Linux hosts. `linux_native` is unsupported there;
  `rlimit` still applies Unix resource limits.
- A guest adapter. ADR 0003 is the interface only.

## Recommended settings

Construct `Settings` with `Settings::builder`. Public enums and
`Settings` are `#[non_exhaustive]`, so adding a field later is not a
breaking change on that path.

**Data transform** (Python/DuckDB): `linux_native`, `Network::Deny`,
`SyscallProfile::Python`, `inputs` = input directory, `output` or
workspace = output directory, `cgroup.memory_max` around 512 MiB. See
[`examples/transform.rs`](../examples/transform.rs).

**Agent shell command**: `linux_native`, workspace = the run directory,
`spawn_with_deadline_captured` with a short wall-clock limit and per-stream
caps so a runaway child cannot pin memory or a pipe. See
[`examples/agent_shell.rs`](../examples/agent_shell.rs).

Call `health` before `prepare`. Treat `Error::Unavailable` as "do not run
this job here", not as a cue to switch backends.

`Sandbox::report` is a JSON run report (`schema_version` 1): backend,
network, syscall profile, namespaces, filesystem view, whether cgroup
limits were set, `ChildUsage` (including violations), and timing in
milliseconds (`prepare_ms`, `apply_ms`, `since_prepare_ms`). Paths are
omitted. `RunReport::to_json` / `from_json` round-trip. Enable the
`tracing` cargo feature to emit `kekkai.prepare`, `kekkai.apply`, and
`kekkai.finish` spans.

## Failure modes

| Symptom | Cause |
| --- | --- |
| `Error::Unsupported` | Backend is not implemented on this OS. |
| `Error::Unavailable` | Kernel lacks Landlock ABI 3, seccomp, a delegated cgroup v2 subtree, or a requested cgroup controller (`io`, `cpu`). |
| `Error::Invalid` | Zero limits, relative roots, overlapping path roles, cgroup on `none`, `cpu_period_us` without quota, `cpu_weight` outside 1..=10000, empty `io.max`. |
| Child `EACCES` / Landlock denial | Path not on the allowlist. |
| Child `EPERM` on `socket()` | `Network::Deny`, or IP sockets under `Allowlist`. |
| Child `EPERM` on another syscall | `SyscallProfile::Strict` or `Python` does not allow that syscall. |
| `ChildUsage.violations` with `ViolationKind::Network` | CONNECT to a host/port not on the allowlist. |
| `ChildUsage.violations` with `ViolationKind::Syscall` | Seccomp denied the named syscall (`socket`, …). |
| `violations_observed` is false | Kernel denials could not be recorded; do not treat an empty list as a clean run. |
| `timed_out` | Wall-clock helper expired; the group was killed. |
| `oom_killed` | cgroup `memory.max` (or `memory.events`) fired. |
| Truncated capture | Stream exceeded its byte cap; `dropped` is the discarded count. |

Denial tests in `crates/kekkai/tests/` spawn `kekkai-probe` through
`prepare` / `apply`. On hosts without the kernel feature they skip with
an explicit `skip:` message; they never pass vacuously. The escape
suite (`tests/escape.rs`) and optional fuzz job are described in
[SECURITY.md](../SECURITY.md).
