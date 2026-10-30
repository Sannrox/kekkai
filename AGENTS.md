# Repository Guidelines

<!-- Structure and shared policy ported from Sannrox/shikigami@331897846885e4a55697b0f1006d03b4f2a7495e AGENTS.md (adapted for kekkai). Compare against the source to detect drift. -->

## Project Structure & Module Organization

`kekkai` is a Rust 2024 workspace for a general-purpose Linux process
sandbox library: Landlock filesystem rules, a seccomp gate, and resource limits
applied to a child process before it spawns. The workspace has one library
crate today, `crates/kekkai`. The design is in
[ADR 0002](docs/decisions/0002-reusable-process-sandbox-library.md).

Keep the public API small: settings in, a prepared sandbox out, applied to a
`Command` before spawn. Do not commit local state (`.state/`,
`.kekkai-state/`), test scratch trees, or generated runtime artifacts.

Human documentation: [README.md](README.md) and the
[consumer guide](docs/consumer-guide.md). Architecture decisions:
[docs/decisions/](docs/decisions/README.md). `CLAUDE.md` only points here;
this file is canonical.

## Dependencies and Ownership

- **No application dependencies.** kekkai does not depend on any control
  plane, scheduler, or application that uses it (ADR 0002). Its input is a
  settings value and a workspace root; its output is a sandbox applied to a
  `Command`. Do not add such dependencies.
- **Users pin versions.** The API follows semver, and any change to
  enforcement (what is allowed or denied, which backend is selected, how
  health is reported) is a versioned change recorded in `CHANGELOG.md`,
  never a patch-level surprise.
- **Port first, then improve.** The first implementation is ported from
  [Sannrox/shikigami](https://github.com/Sannrox/shikigami) with its tests
  (Sannrox/kekkai#1); redesigns come after.

Record cross-repository predecessors in the Issue's `## GitHub dependencies`
section as full `<owner>/<repo>#<n>` references.

## Build, Test, and Development Commands

The compiler is pinned in `rust-toolchain.toml`. Local gates match CI
(`.github/workflows/ci.yml`):

```sh
cargo fmt --all -- --check
cargo build --locked --workspace --all-targets
cargo build --locked --workspace --examples
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo test --locked --workspace --features tokio
cargo test --locked --workspace --features tracing
cargo test --locked --workspace --features guest
bash scripts/validate-workflow-skills.sh
bash scripts/validate-release.sh
```

- `cargo fmt --all` formats before review.
- `cargo clippy ... -D warnings` is required for ship-level local gates.
- `scripts/validate-workflow-skills.sh` clones or updates agent-kit and checks
  that the skill stubs, vendored scripts and this file (including
  `## Agent skill profile`)
  match it.
- `scripts/validate-release.sh` checks the tag-triggered release path: signed
  annotated tags, CHANGELOG notes, SBOM, and the family release manifest.
  Pull requests and dry runs must not publish or attest.

There is no Makefile yet. When one is added, its targets become the source of
truth for these commands and this section must point to them.

GitHub Issues are the planning source of truth. Skills live under `.agents/skills/`
(see Shared agent skills below). Read `README.md` and accepted ADRs under
`docs/decisions/` before changing system boundaries; record new boundaries,
trust-model changes, and public contracts as ADRs with the
`capture-project-decision` Skill.

## Shared agent skills

The workflow Skills (`advance-issue-frontier`, `assess-change-impact`,
`capture-project-decision`, `deliver-ready-issue`, `prepare-release`,
`refactor-docs`, `shape-work-item`, `technical-documentation`, `verify-change`)
are canonical in [Sannrox/agent-kit](https://github.com/Sannrox/agent-kit).
There is no pin: this repository always uses the latest `main`.
`.agents/skills/<name>/` holds only a generated stub that points to the shared
skill; read the installed skill under `~/.agents/agent-kit/` (or
`$AGENT_KIT_HOME`). Run `bash scripts/validate-workflow-skills.sh` to clone or
update it.

- Repository-specific facts the shared Skills need come from this file: the
  ownership, structure, parallel-lane and testing sections, plus
  `## Agent skill profile` below for anything they do not already say. Edit
  this file, not the stubs.
- Never edit stubs or the vendored `scripts/validate-workflow-skills.sh` here;
  change them upstream in agent-kit, then run
  `bash scripts/validate-workflow-skills.sh --render` here when CI reports
  drift.
- Repository-only Skills live next to the stubs as full folders and stay local.

## Agent skill profile

Facts the shared agent-kit skills read that the sections above do not already
state.

Feature: a new observable operator or integration outcome.

### Compatibility and failure obligations

The SemVer class of every change, consumers that must bump their pin, hosts
whose kernel lacks a feature, and behavior parity with code ported from
another project.

### Additional impact boundaries

- backend selection and host detection: an unavailable backend is an error,
  never a silent downgrade;
- `pre_exec` safety between fork and exec;
- public API and SemVer: settings types, prepare/apply, health report;
- known users pinning a version must be able to upgrade.

### Verification matrix

Rows beyond `## Testing Guidelines`:

| Surface | Required evidence |
| --- | --- |
| `pre_exec` code | review for async-signal safety (no allocation, locks, logging); `// SAFETY:` on every `unsafe` |
| backend selection / host detection | unsupported backend is an error, not a downgrade; health output covered by tests |
| public API | SemVer impact stated; docs updated; impact on known users named |

### Release audit

- workspace version, lockfile, and the git tag consumers pin;
- SemVer class: any change to what is allowed or denied, backend selection, or
  health reporting is at least a minor change before `1.0` and is called out;
- impact on known users and the upgrade each needs;
- supported kernels and behavior when a feature is missing;
- security notes for any enforcement fix.

## Agent delivery closeout (required)

`cargo test` / Clippy / green CI are **not** a substitute for structured code
review. For non-trivial implementation work (any behavior, security, settings,
or public-API change) that will be **committed, pushed, or opened as a PR**:

1. Run the local gates above via the `verify-change` Skill.
2. Run **`autoreview`** before the ship commit (or before push if the commit
   already exists). **Do not vendor** the autoreview skill into this repo;
   resolve the helper from the shared skill install (first match wins):

   ```bash
   # Preferred: shared agent-skills checkout or global skills home
   if [ -x "${AUTOREVIEW:-}" ]; then :; \
   elif [ -x "$HOME/Projects/agent-skills/skills/autoreview/scripts/autoreview" ]; then
     export AUTOREVIEW="$HOME/Projects/agent-skills/skills/autoreview/scripts/autoreview"
   elif [ -x "${AGENTS_HOME:-$HOME/.agents}/skills/autoreview/scripts/autoreview" ]; then
     export AUTOREVIEW="${AGENTS_HOME:-$HOME/.agents}/skills/autoreview/scripts/autoreview"
   else
     echo "autoreview helper not found; install shared agent-skills or set AUTOREVIEW" >&2
     exit 1
   fi
   # Dirty uncommitted work:
   "$AUTOREVIEW" --mode local
   # Topic branch / open PR (preferred after commit):
   "$AUTOREVIEW" --mode branch --base origin/main
   # Already committed on a clean tree:
   "$AUTOREVIEW" --mode commit --commit HEAD
   ```

3. Treat helper output as advisory: verify each accepted finding in the real
   code, fix actionable ones, rerun tests and autoreview until the helper exits
   0 with no accepted/actionable findings (or document a maintainer judgment
   blocker in the PR).
4. Report in the PR or handoff: commands run, tests, autoreview result
   (clean / findings fixed / consciously rejected).

**Do not skip autoreview** because CI is green, the change is “small,” or the
session is optimizing for throughput unless the user explicitly waived it.
Docs-only typo fixes and pure formatting may skip structured review; state the
waiver. The `deliver-ready-issue` Skill requires this same closeout before
publish/land. Read the shared `autoreview` skill’s `SKILL.md` next to the
resolved helper for engines and findings policy.

## Parallel delivery lanes

A delivery lane is one Issue, one branch, one isolated checkout, one Pull
Request, and one owner. Several agents may deliver several Issues at the same
time, on one machine or on many, only as separate lanes. One Issue is never
split across lanes, and one lane never carries a second Issue.

### Claims live on GitHub

Machines cannot see each other's worktrees, so a claim is only what GitHub
shows. An Issue is claimed, and therefore active, when any of the following
exists:

1. an open Pull Request, draft or ready, that references the Issue;
2. a branch `<type>/<issue>`, or any branch matching `*/<issue>-*`;
3. the authenticated login assigned to the Issue less than six hours ago.

An assignment older than six hours with neither branch nor Pull Request is an
ownership hint, not a veto: report it and ask the maintainer before claiming.
A claim is stale once its Issue is closed or its Pull Request has merged; its
owner or the maintainer removes it. Any other takeover first preserves the
existing branch, Pull Request, and evidence and requires the maintainer's
confirmation, unless the lead of the same parallel run owns the stalled lane.

A lane claims before it implements, under Publish or Land authority or with an
explicit claim authorization under Implement, using
`bash "${AGENT_KIT_HOME:-$HOME/.agents/agent-kit}"/skills/deliver-ready-issue/scripts/issue-lane.sh claim <issue>`:

- the branch `<type>/<issue>` is created on GitHub from the default branch by
  an atomic ref creation, so when two machines race exactly one claim
  succeeds and the other sees `claimed`;
- the authenticated login is assigned to the Issue, which shows the claim in
  the Issue list and timestamps it in the Issue timeline.

`<type>` is derived deterministically so that every machine computes the same
branch: the Conventional Commit type in the Issue title, with `bug` mapped to
`fix`; otherwise the type label (`bug` → `fix`, `enhancement` → `feat`,
`documentation` → `docs`); otherwise `chore`. Lane branches carry no slug
because the name is the claim; the Pull Request title carries the description.
Human topic branches may keep `<type>/<issue>-<slug>` and are detected as
claims by the same rule.

An Implement-only lane cannot claim and is invisible to other machines. Say so
in the report, or ask for claim authority before starting.

### Isolation on each machine

Local isolation protects lanes that share a machine; it is not a claim.

- Each lane checks out its claim branch in `.worktrees/issue-<issue>` inside
  the repository, ignored by Git. A fresh clone dedicated to the lane, as on a
  cloud agent, is equivalent. The base SHA is recorded in the lane report.
- The primary checkout belongs to the maintainer. Agents never switch its
  branch, reset it, stash it, or run long jobs in it while another lane is
  active.
- A worktree serves exactly one Issue. Finished lanes are removed; a worktree is
  never reused for a different Issue or renamed to hide its origin.
- Shared Git state is mutated in short, serialized slots: `git fetch --prune`,
  worktree creation and removal, local branch deletion, and merging belong to
  the lead of a parallel run or happen one lane at a time on a shared machine.
  A lane commits and publishes its own branch from its own worktree; that is
  not a shared mutation. Nobody holds a slot across implementation, test runs,
  or a remote wait.

### Limits, collisions, and landing

The three-lane limit counts claims visible on GitHub per repository: open
implementation Pull Requests plus claim branches without one. Assigned or
planned work with neither is not a running lane.

Parallel lanes must not collide. Collision surfaces in this repository are the
public API and its semver surface (settings types, prepare/apply, the health
report), the Landlock ruleset, the seccomp filter, and resource-limit
enforcement (rlimit and cgroup). Lanes that would both change one of these
surfaces run in sequence, not in parallel.

A lane publishes its first Verified commit to the claim branch as a draft Pull
Request that closes the Issue. Public GitHub lane fields may list only: claim
branch, repo-relative worktree (for example `.worktrees/issue-N` — never an
absolute path), base SHA, and published SHA. Keep absolute paths and
machine/host names in the private agent session only. It marks the Pull
Request ready when verification and review are complete. Immediately before
publishing, the lane fetches and confirms that the default branch is an
ancestor of its head; it refreshes onto `main` only for a conflict, a failing
gate, an explicit request, or a sibling landing on a shared surface, not
merely because `main` advanced.

Lanes publish with `issue-lane.sh push <issue>` and land with
`issue-lane.sh land <issue> --pr <pr>` (see `### Verified commits on GitHub`).
`land` merges only the reviewed head once its checks pass and reconciles an
uncertain merge response from the Pull Request state, so it is safe to rerun;
a lane that conflicts with a sibling's landing stops instead of merging. After
each merge, fetch, recompute the frontier, and let the remaining lanes recheck
`mergeable` against the new `main`.

The lead of a parallel run keeps a ledger per lane: Issue, branch, base SHA,
owner, state, Pull Request, evidence, blockers, and cleanup. Keep hostnames
and absolute checkout paths in the session with the maintainer, never on
GitHub. Report verified outcomes, not launched work. The executable lead
procedure is `skills/deliver-ready-issue/references/parallel-delivery.md` in
agent-kit.

## Coding Style & Naming Conventions

Follow standard Rust formatting with `cargo fmt` and keep modules aligned with
the domain boundaries above. Use `snake_case` for files, modules, functions, and
variables; use `PascalCase` for types and traits; use `SCREAMING_SNAKE_CASE` for
constants. Fail closed: selecting a backend the host cannot provide is an error,
never a silent downgrade, and a rule that cannot be installed aborts the spawn.
Code that runs in `pre_exec` (between fork and exec) must be async-signal-safe:
no allocation, locks, or logging. Keep `unsafe` to the `pre_exec` and syscall
boundary, each block with a `// SAFETY:` comment.

## Testing Guidelines

Enforcement tests must prove denial: a child that attempts a forbidden action
(write outside the allowed tree, open a socket, exceed a limit) must fail, and
the test asserts that failure. Tests that need a kernel feature (a Landlock
ABI, seccomp, cgroup v2 delegation) detect it and skip with an explicit
message; they never pass vacuously. Offline `cargo test` must stay green on
hosts without those features. When porting code from another project, port its
tests with it.

## Commit & Pull Request Guidelines

Use short imperative subjects, often Conventional Commit style:
`feat(cgroup): enforce memory.max for sandboxed children`,
`fix(landlock): fail closed below the ABI floor`,
`docs: document backend selection`. Keep commits narrow and describe the affected
subsystem when useful. Pull requests should include a concise behavior
summary, **tests run**, **autoreview result** (for non-trivial code), linked
issue or context, and any configuration, compatibility, or security
implications. `.agents/skills/` is tracked; do not treat it as gitignored.
Record every user-visible and enforcement change in `CHANGELOG.md` under
`Unreleased` (ADR 0002).

### Public hygiene

This repository is public. Never put hostnames, FQDNs, IP addresses, home
directories, absolute worktree paths, LAN or employer network names, deployment
or environment state, image or artifact digests, tenant or customer names,
release-hold or rollout-hold language, or other private environment inventory on
Issues, Pull Requests, comments, commit messages, ADRs, or docs. Describe
behavior and versions instead (for example "after the sandbox release" rather
than an environment name, a digest, or a hold).

### Verified commits on GitHub

Publish and land lanes through the shared agent-kit lane tool so GitHub shows
**Verified** commits and `main` stays linear:

1. Implement and commit locally as usual. Never pass `--no-gpg-sign`; if GPG
   fails, stop and fix it.
2. Publish the claim branch from the lane worktree:
   `bash "${AGENT_KIT_HOME:-$HOME/.agents/agent-kit}"/skills/deliver-ready-issue/scripts/issue-lane.sh push <issue>`.
   It creates GitHub-signed commits and resets the worktree to the published
   commit, so local `HEAD` is the Pull Request head. Confirm it reports
   `verification.verified=true`.
3. Land with `bash "${AGENT_KIT_HOME:-$HOME/.agents/agent-kit}"/skills/deliver-ready-issue/scripts/issue-lane.sh land <issue> --pr <pr>`.
   It squash-merges the reviewed head once the required checks pass, and
   deletes the claim branch only after the merge and the closed Issue are
   confirmed.

Do not queue GitHub auto-merge, and do not use GitHub **rebase** merges:
rebase-merge rewrites commits and drops signatures. Do not rewrite protected
`main` after merging unless the user explicitly approves; if protection is
temporarily relaxed, restore force-push and status-check settings immediately
after the correction.

## Security & Configuration Tips

Never commit secrets, tokens, credentials, logs, or local state. Report
suspected sandbox escapes or bypasses privately (GitHub private vulnerability
reporting or the maintainer), never in a public Issue, Pull Request, or commit
message; a fix lands before the details are public. Never put hostnames, FQDNs,
IP addresses, home directories, absolute worktree paths, LAN or employer network
names, deployment or environment state, image or artifact digests, tenant or
customer names, release-hold or rollout-hold language, or other private
environment inventory on public Issues, Pull Requests, comments, or commit
messages.
