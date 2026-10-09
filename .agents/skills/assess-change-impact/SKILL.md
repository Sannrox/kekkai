---
name: assess-change-impact
description: Assess a proposed or implemented kekkai change across trust, API, dependency, and operations boundaries. Use when scoping an Issue, planning tests, reviewing a diff, or identifying compatibility, documentation, and security obligations.
---

<!-- Ported from Sannrox/shikigami@331897846885e4a55697b0f1006d03b4f2a7495e .agents/skills/assess-change-impact/SKILL.md (rewritten for kekkai; structure kept). Compare against the source to detect drift. -->

# Assess Change Impact

Build an evidence-backed impact map before implementation or review.

## Procedure

1. Read the linked Issue or request, `README.md`, accepted ADRs under
   `docs/decisions/`, and the relevant code. For a diff, inspect every changed
   file and its direct callers or implementors. Complete when the claimed
   outcome and actual change surface are both known.
2. Trace applicable boundaries:
   - enforcement semantics: what each backend (`none`, `rlimit`,
     `linux_native`, later cgroup) allows and denies;
   - backend selection and host detection: an unavailable backend is an
     error, never a silent downgrade;
   - Landlock ruleset and ABI floor, seccomp filter, rlimits and process
     group, cgroup v2 limits;
   - `pre_exec` safety between fork and exec;
   - public API and semver: settings types, prepare/apply, health report;
   - user impact: known users pinning a version must be able to upgrade;
   - independence: no dependency on any application or control
     plane.
   Complete when each applicable boundary has an owner and expected invariant.
3. Identify compatibility obligations: semver class of the change, consumers
   that must bump their pin, hosts whose kernel lacks a feature, and behavior
   parity with the code this was ported from. Complete when every
   loosening or tightening of enforcement is named with its consumer impact.
4. Map evidence to risk: unit tests for pure logic; denial tests that spawn a
   child and assert the forbidden action fails; explicit skips for missing
   kernel features; ported tests for moved behavior. Complete when
   every material risk has a proposed check or an explicit residual uncertainty.
5. Determine durable artifacts that must change: README, docs, examples, an
   ADR, upstream Issues in the owning repository, or a repository Skill.
   Complete when no artifact is proposed merely to record temporary planning.

## Output

Return a compact matrix with columns:

| Surface | Evidence found | Required change/check | Risk if missed |
| --- | --- | --- | --- |

Then list scope boundaries, blocking questions, and the smallest safe PR split.
Do not approve an architecture, perform a full security audit, or claim
behavior parity without inspecting the implementations.
