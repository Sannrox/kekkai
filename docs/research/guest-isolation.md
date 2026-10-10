# Guest isolation for sandboxed children

Research for [Issue #3](https://github.com/Sannrox/kekkai/issues/3). Decision:
[ADR 0003](../decisions/0003-guest-backend-interface.md).

In-process backends (`rlimit`, `linux_native`, cgroup v2) run the child as
the caller's OS user on the host kernel. That is the right default for
trusted or single-user code. Mutually distrusting users need a guest: a
kernel surface that is not the host's.

Two guest shapes show up in production isolation runtimes. This note
compares them in kekkai terms. It does not pick a vendor.

## Userspace kernel

A helper process intercepts the child's Linux syscalls and implements the
ABI itself. The child is still a host process, but `open`, `socket`,
`mount`, and friends never reach the host kernel.

| | |
| --- | --- |
| Startup | About 80–300 ms for create+start of a fresh sandbox, dominated by helper init rather than intercept. |
| Numeric libraries | mmap, thread arenas, and compute loops are cheap once loaded. Syscall-heavy import and IO pay intercept cost. Systrap-class intercept is the usual default; a KVM intercept helps on bare metal and loses under nested virt. |
| Host | A helper binary on PATH. Trap-based intercept works inside ordinary VMs. KVM intercept needs `/dev/kvm` and is a poor nested-virt citizen. Bind-mount or overlay a root and workspace; no guest kernel image. |
| Filesystem | Explicit mounts into the sandbox. Host paths that are not mounted do not exist. |
| Network | Off unless the helper is given a stack. Matches kekkai's default deny. |
| Kernel surface | Host kernel still schedules the process. A helper bug is an escape to that kernel. Stronger than Landlock+seccomp, weaker than a separate guest kernel. |

## KVM microVM

A VMM builds a tiny VM with its own kernel. The child runs in that guest.
The host sees virtio and a jailer process.

| | |
| --- | --- |
| Startup | Published kernel-to-init figures are around 125 ms on a minimal 1 vCPU / 128 MiB guest. A usable userspace (init, mounts, exec of the real command) is typically 100–400 ms cold. Snapshot restore can drop that; kekkai will not own snapshots. |
| Numeric libraries | Inside the guest, syscalls are native. Cross-guest file IO goes through virtio. CPU-bound Polars / DuckDB work after load is near bare metal (published guest CPU figures are above 95% of host). The cost is packaging: a rootfs that contains the interpreter and native libs. |
| Host | `/dev/kvm`, a VMM, a jailer, a guest kernel image, and a rootfs. Nested virt is often unavailable. Unprivileged containers without KVM cannot select this backend. |
| Filesystem | Only what the VMM mapped (typically a scratch tree and a read-only rootfs). |
| Network | Off unless a tap/vsock is attached. |
| Kernel surface | Separate kernel. A guest kernel bug does not become a host kernel bug. Strongest of the options kekkai would wrap. |

## Fit with kekkai

`Sandbox::apply` installs rules in `pre_exec` on a host `Command`. A guest
cannot use that path: the command has to be started by a helper or VMM.
The guest interface therefore owns spawn. `apply` stays for in-process
backends.

Health and errors stay the existing vocabulary. Missing helper, missing
KVM, or missing rootfs is `Unavailable`. Selecting a guest backend on
macOS or Windows is `Unsupported`. There is no fallback to `linux_native`.

kekkai still does not pull images, keep a VM pool, or schedule hosts. The
caller supplies the workspace, the command, and (for a microVM) the kernel
and rootfs paths. Resource limits map onto the guest's cgroup or the VMM's
balloon/quota.

## Workload note

A 512 MiB real-memory cap for numpy / Polars / DuckDB is already a cgroup
concern, not a guest concern. Guest isolation answers a different
question: can this child see the host or another run? Startup of those
interpreters is often hundreds of milliseconds, so a 100–300 ms guest boot
is in the same band as the workload itself.

## Recommendation

Accept a guest backend interface in kekkai (ADR 0003). Do not ship an
adapter until one compiles against that interface. Prefer a userspace
kernel adapter first: it matches the current "no extra images" host story
and works without KVM. Add a microVM adapter where the caller can provide
KVM and a rootfs and needs a separate kernel.
