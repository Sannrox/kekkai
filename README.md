# kekkai (結界)

A small Rust library for sandboxing child processes on Linux and macOS:
on Linux a filesystem allowlist (Landlock), a syscall and network gate
(seccomp), and resource limits; on macOS a Seatbelt profile for
filesystem and network rules. Applied to a `std::process::Command`
before it spawns.

See the [consumer guide](docs/consumer-guide.md) for backends, `health`,
recommended settings, and failure modes. Examples live in
[`examples/`](examples/). Architecture:
[ADR 0002](docs/decisions/0002-reusable-process-sandbox-library.md) and
[ADR 0003](docs/decisions/0003-guest-backend-interface.md).
Not yet published to crates.io.

## What it does

- **Filesystem allowlist:** the child can read and write only the paths you
  allow (Landlock ABI 3+ on Linux, Seatbelt on macOS). Named roles:
  read-only `inputs`, a writable `output` directory (the workspace when
  unset), and a private per-run scratch dir (`TMPDIR`). Overlapping roles
  are rejected. Extra device nodes are listed in `Settings.devices` on
  Linux; none are granted by default beyond `/dev/null`, `/dev/zero`,
  `/dev/urandom`, and `/dev/random`.
- **No network by default:** on Linux a seccomp filter denies socket
  creation; on macOS the Seatbelt profile denies `network*`.
  `Network::Allow` leaves sockets to the host; filesystem rules still apply.
  `Network::Allowlist` permits listed hosts through a parent CONNECT proxy
  on a unix socket; direct IP sockets fail. `Network::Loopback` places the
  child in a private network namespace with only loopback up.
- **Resource limits:** rlimits, plus opt-in cgroup v2 `memory.max`,
  `pids.max`, `cpu.max`, `cpu.weight`, and `io.max` when a delegated
  subtree is available. Requesting cgroup limits without one, or a
  controller the subtree does not provide, is an error, never a
  fallback to `RLIMIT_AS`. `Sandbox::usage` snapshots live usage;
  `finish` reports after exit.
- **Explicit backends:** `none` (development only), `rlimit`,
  `linux_native`, `macos` (Seatbelt filesystem and network profile), and
  `userspace` (opt-in `guest` cargo feature). Selecting a backend the
  kernel cannot provide is an error, never a silent downgrade.
- **Host detection:** `health` and `capabilities` report which backends the
  running kernel supports. `Host::probe` snapshots that once;
  `Sandbox::prepare_with_host` reuses the snapshot so a runner does not
  re-probe between jobs. A stale snapshot fails closed. `ChildUsage.violations` records seccomp-denied
  syscalls when user notification is available, and CONNECT denials from
  the egress proxy. Filesystem Landlock denials are reported as unavailable
  until the host exposes an unprivileged event stream.
- **In-process by default:** `rlimit`, `linux_native`, and `macos` install
  rules in `pre_exec`, so they work without a helper. Extra file
  descriptors above stderr do not survive `exec`; `ptrace` is denied.
  `SyscallProfile::Default` is the historical denylist; `Strict` and
  `Python` are per-architecture allowlists. `Namespaces::Isolate` is
  opt-in user/mount/PID/IPC/UTS namespaces when the host allows them.
  `FilesystemView::Isolate` adds read-only binds, tmpfs scratch, and an
  overlay whose writes are discarded or kept. `Network::Loopback` adds a
  private network namespace with only loopback up.
- **Userspace guest:** `Backend::Userspace` (cargo feature `guest`)
  launches a helper that owns spawn. The helper is the process-group
  leader; the payload stays in that group. `apply` is invalid on that
  sandbox. A missing helper is unavailable. See
  [ADR 0003](docs/decisions/0003-guest-backend-interface.md).

## Intended usage

```rust,no_run
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use std::process::Command;
use kekkai::{Backend, Sandbox, Settings};

let settings = Settings::builder()
    .backend(Backend::LinuxNative)
    .build();
let sandbox = kekkai::Sandbox::prepare(&settings, "/path/to/workspace")?;
let mut cmd = Command::new("python3");
sandbox.apply(&mut cmd)?;
let status = cmd.status()?;
# let _ = status;
# Ok(())
# }
```

## CLI

`kekkai run` prepares the same sandbox as the library and spawns a command:

```bash
kekkai run --settings job.json --workspace ./ws -- python3 job.py
kekkai run --backend none --report out.json -- /usr/bin/true
```

The child inherits stdin, stdout, and stderr. After it exits, a JSON
`RunReport` (`schema_version` 1) is written to stderr, or to `--report PATH`
(`-` or `--json` for stdout). The process exit code is the child's
(or `128+N` when signaled). Usage errors and prepare/apply/spawn failures
exit 2. Default backend is `linux_native` on Linux, `macos` on macOS, and
`rlimit` elsewhere. `kekkai --help` documents flags and the JSON file.

`tokio::process::Command` is supported behind the `tokio` cargo feature
(`Sandbox::apply_tokio`, `Sandbox::spawn_with_deadline_tokio`,
`Sandbox::spawn_with_deadline_captured_tokio`).
`Sandbox::report` is a JSON run report (schema version 1). The `tracing`
cargo feature adds `kekkai.prepare`, `kekkai.apply`, and `kekkai.finish`
spans.
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
- Real isolation on Windows. macOS uses `Backend::Macos`.

Known users: [shikigami](https://github.com/Sannrox/shikigami) (agent tool
calls), where this code originated, and [kako](https://github.com/Sannrox/kako)
(data transforms).

## Compatibility

kekkai follows semver. A change to what the sandbox allows or denies, which
backend is selected, or how `health` is reported is a versioned change,
never a patch-level surprise. In 0.x that is a minor bump.

Public enums and `Settings` are `#[non_exhaustive]`. Construct `Settings`
with [`Settings::builder`](crates/kekkai/src/lib.rs). Adding a field is
not a breaking change on that path. The crate denies missing docs
(`#![deny(missing_docs)]`) and declares `rust-version = "1.97.1"`.

## Development

```bash
cargo build
cargo build --examples
cargo test
cargo bench --bench overhead
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

`cargo bench --bench overhead` times `prepare` / `apply` / spawn of
`/bin/true` / `finish`. The Linux x86_64 baseline and 20% p95 gate live
in [`crates/kekkai/benches/`](crates/kekkai/benches/).

The toolchain is pinned in `rust-toolchain.toml`.

Denial tests spawn a real child through `Sandbox::prepare` / `apply`. On
hosts without Landlock or seccomp they skip with an explicit `skip:`
message.

## Security

Report sandbox escapes privately; see [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
