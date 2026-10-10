# Project profile for agent-kit skills

<!-- Read by the shared skills in https://github.com/Sannrox/agent-kit (pinned in .agents/agent-kit.lock). Keep repo-specific facts here, not in the shared skills. Section headings are a contract: do not rename them. -->

## Project

- Name: kekkai
- Feature means: a new observable operator or integration outcome

## Ownership boundaries

Kekkai is a library with no application dependency; users pin it by version.

Route work owned by another repository (claim protocol, sandbox enforcement, delivery) to that repository.

## Affected areas

api/landlock/seccomp/limits/detection/consumers/security

## Shared surfaces

Issues touching the same shared surface run in sequence, never as parallel lanes:
the public API, the Landlock ruleset, the seccomp filter, or resource-limit enforcement.

## Impact boundaries

- enforcement semantics: what each backend (`none`, `rlimit`, `linux_native`, later cgroup) allows and denies;
- backend selection and host detection: an unavailable backend is an error, never a silent downgrade;
- Landlock ruleset and ABI floor, seccomp filter, rlimits and process group, cgroup v2 limits;
- `pre_exec` safety between fork and exec;
- public API and semver: settings types, prepare/apply, health report;
- user impact: known users pinning a version must be able to upgrade;
- independence: no dependency on any application or control plane.

## Compatibility and failure obligations

Semver class of the change, consumers that must bump their pin, hosts whose kernel lacks a feature, and behavior parity with the code this was ported from.

## Evidence map

Unit tests for pure logic; denial tests that spawn a child and assert the forbidden action fails; explicit skips for missing kernel features; ported tests for moved behavior.

## Verification matrix

| Surface | Required evidence |
| --- | --- |
| enforcement (Landlock, seccomp, rlimit, cgroup) | tests that prove denial: the forbidden action fails in the child; kernel-dependent tests skip with an explicit message, never pass vacuously |
| `pre_exec` code | review for async-signal safety (no allocation, locks, logging); `// SAFETY:` on every `unsafe` |
| backend selection / host detection | unsupported backend is an error, not a downgrade; health output covered by tests |
| public API | semver impact stated; docs updated; impact on known users named |
| behavior ported from another project | the original tests for that behavior ported and passing here |

## Release audit

- workspace `Cargo.toml` version, lockfile, and the git tag consumers pin;
- SemVer class: any change to what is allowed or denied, backend selection, or health reporting is at least a minor change before `1.0` and is called out explicitly;
- impact on known users and the upgrade each needs;
- supported kernels and behavior when a feature is missing;
- security notes for any enforcement fix.
