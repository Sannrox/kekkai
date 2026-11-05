# Sandbox overhead

`cargo bench --bench overhead` times `Sandbox::prepare`, `apply`, spawn of
`/bin/true`, wait, and `finish` for each backend and opt-in feature.

The Bench workflow runs the bench twice on one Linux runner: first at
the base commit (the pull request base, or the latest `v*` tag on a
schedule or manual run), then at the change, with
`--check base.json`. It fails when a sandboxed scenario's p50, as a
multiple of the unsandboxed p50 from the same run, is more than 20%
above that multiple in the base run. The unsandboxed scenario runs no
kekkai code: it is the reference, so drift between the two runs does
not fail the check on its own. Scenarios the host cannot enforce print
`skip:` and are left out of the comparison.

The base is measured in the same job because a stored report does not
hold across hosted runners. Across 12 runs of an unchanged tree, the
largest p50 deviation from a stored baseline was 22%. It came from
machine types whose relative seccomp and spawn costs differ. The largest
p95 deviation was 2.4x, from a few slow samples in one run (#93).

Published budgets (enforced when the scenario ran):

- `rlimit` p95 overhead over unsandboxed spawn ≤ 2 ms
- `linux_native` with isolate namespaces, filesystem view, and cgroup
  p95 overhead ≤ 25 ms
- `linux_native` sequential ≥ 50 jobs/s
- `linux_native_cached_host` (one `Host::probe`, then `prepare_with_host`)
  sequential ≥ 50 jobs/s
