# kekkai (結界)

A small Rust library for sandboxing child processes on Linux: a filesystem
allowlist (Landlock), a syscall and network gate (seccomp), and resource
limits, applied to a `std::process::Command` before it spawns.

> Status: early skeleton. The API below is the plan; see
> [ADR 0002](docs/decisions/0002-reusable-process-sandbox-library.md).
> Not yet published to crates.io.

## What it does

- **Filesystem allowlist:** the child can read and write only the paths you
  allow (Landlock, ABI 3 or newer).
- **No network:** a seccomp filter denies socket creation.
- **Resource limits:** rlimits today; cgroup v2 memory and CPU limits are
  planned.
- **Explicit backends:** `none` (development only), `rlimit`, and
  `linux_native`. Selecting a backend the kernel cannot provide is an error,
  never a silent downgrade.
- **Host detection:** report which backends the running kernel supports.
- **No helper binary, no user namespaces:** rules are installed in
  `pre_exec`, so it works in unprivileged containers.

Planned: an optional backend interface for stronger isolation such as gVisor
or Firecracker.

## Intended usage

```rust,ignore
let sandbox = kekkai::Sandbox::prepare(&settings, workspace_root)?;
let mut cmd = std::process::Command::new("python3");
sandbox.apply(&mut cmd)?;
let status = cmd.status()?;
```

## Non-goals

- Scheduling, image management, or orchestration of containers or VMs.
- Deciding what runs, retries, or auditing. That belongs to the caller.
- Network policy by destination address (Landlock and seccomp cannot express
  it).
- Real isolation on non-Linux platforms.

Known users: [shikigami](https://github.com/Sannrox/shikigami) (agent tool
calls), where this code originated, and [kako](https://github.com/Sannrox/kako)
(data transforms).

## Development

```bash
cargo build
cargo test
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

The toolchain is pinned in `rust-toolchain.toml`.

## Security

Report sandbox escapes privately; see [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
