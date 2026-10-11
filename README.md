# kekkai (結界)

A small Rust library for sandboxing child processes on Linux: a filesystem
allowlist (Landlock), a syscall and network gate (seccomp), and resource
limits, applied to a `std::process::Command` before it spawns.

See the [consumer guide](docs/consumer-guide.md) for backends, `health`,
recommended settings, and failure modes. Examples live in
[`examples/`](examples/). Architecture:
[ADR 0002](docs/decisions/0002-reusable-process-sandbox-library.md) and
[ADR 0003](docs/decisions/0003-guest-backend-interface.md).
Not yet published to crates.io.

## What it does

- **Filesystem allowlist:** the child can read and write only the paths you
  allow (Landlock, ABI 3 or newer). Named roles: read-only `inputs`, a
  writable `output` directory (the workspace when unset), and a private
  per-run scratch dir (`TMPDIR`). Overlapping roles are rejected.
- **No network by default:** a seccomp filter denies socket creation.
  `Network::Allow` leaves sockets to the host; filesystem rules still apply.
  `Network::Allowlist` permits listed hosts through a parent CONNECT proxy
  on a unix socket; direct IP sockets fail.
- **Resource limits:** rlimits, plus opt-in cgroup v2 `memory.max`,
  `pids.max`, and `cpu.max` when a delegated subtree is available.
  Requesting cgroup limits without one is an error, never a fallback to
  `RLIMIT_AS`.
- **Explicit backends:** `none` (development only), `rlimit`, and
  `linux_native`. Selecting a backend the kernel cannot provide is an error,
  never a silent downgrade.
- **Host detection:** `health` and `capabilities` report which backends the
  running kernel supports. `ChildUsage.violations` records seccomp-denied
  syscalls when user notification is available, and CONNECT denials from
  the egress proxy. Filesystem Landlock denials are reported as unavailable
  until the host exposes an unprivileged event stream.
- **No helper binary, no user namespaces:** rules are installed in
  `pre_exec`, so it works in unprivileged containers.

Guest isolation (userspace kernel or KVM microVM) is an accepted
interface, not a shipped adapter: [ADR 0003](docs/decisions/0003-guest-backend-interface.md).

## Intended usage

```rust,no_run
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use std::process::Command;
use kekkai::{Backend, Sandbox, Settings};

let mut settings = Settings::default();
settings.backend = Backend::LinuxNative;
let sandbox = kekkai::Sandbox::prepare(&settings, "/path/to/workspace")?;
let mut cmd = Command::new("python3");
sandbox.apply(&mut cmd)?;
let status = cmd.status()?;
# let _ = status;
# Ok(())
# }
```

`tokio::process::Command` is supported behind the `tokio` cargo feature
(`Sandbox::apply_tokio`, `Sandbox::spawn_with_deadline_tokio`,
`Sandbox::spawn_with_deadline_captured_tokio`).
`Sandbox::spawn_with_deadline` kills the process group after a wall-clock
limit (`SIGTERM`, then `SIGKILL` and `cgroup.kill`).
`Sandbox::spawn_with_deadline_captured` keeps stdout and stderr under
per-stream byte caps (head, tail, or both) and drains overflow so the
child cannot fill the pipe. The tokio captured helper waits on the
calling thread.

## Non-goals

- Scheduling, image management, or orchestration of containers or VMs.
- Deciding what runs, retries, or auditing. That belongs to the caller.
- Letting the child open its own IP sockets to listed hosts.
  `Network::Allowlist` is a parent CONNECT proxy on a unix socket.
- Real isolation on non-Linux platforms.

Known users: [shikigami](https://github.com/Sannrox/shikigami) (agent tool
calls), where this code originated, and [kako](https://github.com/Sannrox/kako)
(data transforms).

## Development

```bash
cargo build
cargo build --examples
cargo test
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

The toolchain is pinned in `rust-toolchain.toml`.

Denial tests spawn a real child through `Sandbox::prepare` / `apply`. On
hosts without Landlock or seccomp they skip with an explicit `skip:`
message.

## Security

Report sandbox escapes privately; see [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
