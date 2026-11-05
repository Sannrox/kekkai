# ADR 0004: What 1.0 promises

- Status: Proposed
- Date: 2026-11-05
- Supersedes: —
- Relates: [0002](0002-reusable-process-sandbox-library.md),
  [0003](0003-guest-backend-interface.md)
- Source: [Issue #98](https://github.com/Sannrox/kekkai/issues/98)

## Context

kekkai follows semver, and a change to what the sandbox allows or denies,
which backend is selected, or how `health` is reported is a versioned
change ([README](../../README.md#compatibility), ADR 0002). In 0.x every
such change is a minor bump, so a consumer pinning `0.2` today gets no
promise that the next minor keeps its children's rules.

Known users pin a version and upgrade on their own schedule
([README](../../README.md#non-goals)). A security library is only useful
to them if an upgrade within a major version never weakens what they
configured. This ADR states what 1.0 freezes, so that both the
maintainer and consumers can tell when kekkai is ready for it.

## Decision

### What 1.0 freezes

1. **Public API.** `Settings`, `Settings::builder`, `Sandbox`
   (`prepare`, `prepare_with_host`, `apply`, the spawn helpers, `usage`,
   `finish`, `report`), `Host`, `health`, `capabilities`, and the public
   error, enum, and report types. Public enums and `Settings` stay
   `#[non_exhaustive]`, and `Settings::builder` stays the supported way
   to construct settings.
2. **Enforcement contract per backend.** What each backend allows and
   denies for a given `Settings` value, as written in the consumer guide
   under [What is enforced](../consumer-guide.md#what-is-enforced) and
   proven by the denial and escape tests.
3. **Fail-closed behavior.** A backend the host cannot provide, or a
   rule that cannot be installed, is an error (`Error::Unavailable`,
   `Error::Unsupported`, or a failed spawn), never a silent downgrade
   (ADR 0002, decision 3).
4. **Run report.** `RunReport` keeps `schema_version` 1 and its existing
   fields and meanings.

### What is a major change after 1.0

- A rule that allows something it denied before for the same `Settings`
  value.
- A backend that, for the same `Settings` value, runs with weaker
  isolation instead of failing, or a change in which backend a setting
  selects.
- A removal or incompatible change in the public API, as reported by the
  CI `Semver` job.
- A default that denies something it allowed before, because it breaks
  children that worked under the same settings. A fix for a reported
  escape is the exception: it ships in a patch or minor release with an
  advisory, because the old behavior was never part of the contract.
- A change to the meaning of an existing `health` result or report field.

### What a minor release may add

- New deny rules behind an opt-in setting, with the default unchanged.
- New backends, selected explicitly.
- New `Settings` fields, enum variants, and report fields, on the
  `#[non_exhaustive]` and `Settings::builder` path.
- New optional cargo features.

### The bar for cutting 1.0

- The package is published on crates.io.
- The public API has gone through at least one minor release with no
  API break reported by the `Semver` job.
- Every known user runs a 0.x release that is API-compatible with the
  1.0 candidate.
- No open Issue reports an enforcement bug: an allowed action that
  should be denied, or a silent downgrade.
- Escape reports received through the private advisory process in
  [SECURITY.md](../../SECURITY.md) have a fix and a published advisory.

## Consequences

- Consumers can depend on `kekkai-sandbox = "1"` and take every 1.x
  upgrade without rechecking what their children may do.
- Tightening a default needs a 2.0, so defaults chosen before 1.0 should
  already be the strict ones the project wants to keep.
- Until 1.0, a minor bump may still change enforcement. The CHANGELOG
  calls that out on every release, as it does today.

## Alternatives considered

- **Stay on 0.x indefinitely.** Rejected: consumers get no promise that
  a minor upgrade keeps their rules, which is the property a security
  library exists to give.
- **Treat any enforcement change as major, including escape fixes.**
  Rejected: a fix for an escape must reach pinned consumers without a
  major upgrade.
- **Freeze the API only, not enforcement.** Rejected: an upgrade that
  silently allows more is worse for a sandbox than an API break, which
  at least fails to compile.
