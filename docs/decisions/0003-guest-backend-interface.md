# ADR 0003: Guest backend interface for per-run isolation

- Status: Accepted
- Date: 2026-10-10
- Supersedes: —
- Relates: [0002](0002-reusable-process-sandbox-library.md)
- Source: [Issue #3](https://github.com/Sannrox/kekkai/issues/3)
- Research: [guest-isolation.md](../research/guest-isolation.md)

## Context

`none`, `rlimit`, and `linux_native` isolate a child in-process: Landlock,
seccomp, rlimits, and optional cgroup v2, installed in `pre_exec`. The
child shares the caller's user and the host kernel. That is enough for
trusted code. It is not enough when mutually distrusting users share a
machine: a host-kernel bug or a gap in the in-process rules can expose
another run.

Callers should not each invent a guest. kekkai already owns settings,
health, and typed errors. ADR 0002 forbids orchestration, image pulls, and
scheduling.

## Decision

1. kekkai will grow an optional **guest** backend family: run this command,
   with this workspace and these limits, in an isolated guest. Two shapes
   are in scope: a userspace kernel (syscall intercept, no guest kernel
   image) and a KVM microVM (separate guest kernel, virtio, jailer).
2. Guest backends **own spawn**. `Sandbox::apply` remains the in-process
   path. Calling `apply` on a guest sandbox is `Error::Invalid`. A later
   `Sandbox::spawn` (or equivalent) starts the helper or VMM. Existing
   `prepare` / `apply` callers are unchanged.
3. The public vocabulary stays `Settings`, `Health`, `Error`, and
   `ChildUsage`. A missing helper, missing `/dev/kvm`, or missing rootfs
   is `Unavailable`. A guest backend on a non-Linux host is `Unsupported`.
   There is no silent downgrade to `linux_native` or `rlimit`.
4. Callers select a backend explicitly. kekkai does not rank a "minimum
   tier" inside `Settings`. A caller that needs a guest picks a guest
   backend and fails closed when `health` is an error.
5. kekkai defines the interface and may ship thin adapters behind cargo
   features. It does not pull images, keep a VM pool, or schedule hosts.
   The caller provides the workspace, the command, and any kernel/rootfs
   paths the adapter needs.
6. This change records the interface. The crate does not grow a public
   trait or a `Backend` variant until an adapter compiles against it.
   The first adapter is a follow-up Issue. Prefer a userspace kernel
   adapter first; add a microVM adapter where the host has KVM and the
   caller can supply a guest kernel and rootfs.

## Consequences

- Known users can require a guest in their own policy without forking
  kekkai's settings types.
- In-process enforcement (Landlock, seccomp, cgroup) stays the default
  and keeps working in unprivileged containers without KVM.
- A guest adapter will add a helper binary (and for microVMs, KVM plus
  images). That is an opt-in cargo feature and a fail-closed `health`
  probe, not a new default.
- Numeric-library memory caps remain cgroup `memory.max` on the guest
  process or VM; guest isolation does not replace resource limits.

## Alternatives considered

- **Leave guests to each caller.** Rejected: duplicated settings, health,
  and guarantees, which is the problem ADR 0002 already rejected for
  in-process isolation.
- **Ship a public trait with no adapter.** Rejected: it freezes a shape
  before spawn, rootfs, and usage reporting have a second implementation.
- **Add `Backend::Guest` now that always returns `Unavailable`.** Rejected:
  a name in the enum with no enforcement is a compatibility liability.
- **A minimum-tier field on `Settings`.** Rejected: backend selection is
  already explicit and fail-closed. Ranking tiers belongs to the caller.
- **Orchestrate hosts or pull images inside kekkai.** Rejected: ADR 0002
  non-goals.
