# Sandbox overhead

`cargo bench --bench overhead` times `Sandbox::prepare`, `apply`, spawn of
`/bin/true`, wait, and `finish` for each backend and opt-in feature.

The Linux x86_64 runner stores percentiles in
`baseline-linux-x86_64.json`. The scheduled Bench workflow fails when a
measured p95 is more than 20% above that baseline. Scenarios the host
cannot enforce print `skip:` and are left out of the comparison.

Published budgets (enforced when the scenario ran):

- `rlimit` p95 overhead over unsandboxed spawn ≤ 2 ms
- `linux_native` with isolate namespaces, filesystem view, and cgroup
  p95 overhead ≤ 25 ms
- `linux_native` sequential ≥ 50 jobs/s
- `linux_native_cached_host` (one `Host::probe`, then `prepare_with_host`)
  sequential ≥ 50 jobs/s
