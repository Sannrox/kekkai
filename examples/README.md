# Examples

Runnable sketches for the two known workloads. They compile with
`cargo build --examples` and fail closed at runtime when the host cannot
enforce the selected backend.

| Example | Workload |
| --- | --- |
| `transform` | Python/DuckDB: read-only input, writable output, no sockets, `SyscallProfile::Python`, 512 MiB cgroup memory |
| `agent_shell` | Command in a workspace with a 30s deadline and capped stdout/stderr |

See the [consumer guide](../docs/consumer-guide.md) for recommended
settings and failure modes.
