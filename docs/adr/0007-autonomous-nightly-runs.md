# ADR 0007: Nightly development runs without the owner

Status: Accepted
Date: 2026-11-14

## Context

Until sprint 7 every session followed the protocol in `CLAUDE.md`
literally: plan mode, the owner approves the plan, the owner is asked
before any deviation from a spec or an ADR, and the owner merges
(`docs/roadmap/sprints.md`, "merge by the owner"). That makes the
owner's presence the bottleneck: no story landed after sprint 7
(3 Oct 2026) although the plan had stories ready.

`.github/workflows/automerge.yml` already merges a pull request once
the required checks pass and its review threads are resolved, so the
branch rule on `main`, not a person, is what guards a merge.

## Decision

On 14 Nov 2026 the owner ordered that development continues in nightly
autonomous runs. For these runs, and only for them:

1. `CLAUDE.md` session protocol steps 2 and 7 are waived. The run
   plans and then implements without waiting for approval.
2. A deviation from a spec or an ADR is recorded as a new ADR in the
   same pull request instead of being asked about. A change that would
   weaken the security model in `docs/THREAT_MODEL.md` is not made: it
   is left for the owner as a blocked item.
3. The run merges its own pull requests through auto-merge, or directly
   once every required check is green and every review thread is
   resolved. Never with a red or pending check: that means every
   check on the pull request, not only the ones the branch rule on
   `main` requires. Auto-merge waits for the required set alone, so a
   run that sees a red or pending check outside that set turns
   auto-merge off on its pull request until the check is green.
4. One story per run, in the priority order of `TASKS.md` and then
   `docs/roadmap/sprints.md`. A story that needs something only the
   owner can give (a secret, an account, a server, a signing key, a
   product decision) gets one `Owner:` line in `TASKS.md` saying what
   is needed and why, and the run takes the next story. Where an
   earlier session left a question with a recommended answer, the
   recommendation is taken and recorded.
5. Releases stay with the owner: no tags, no run of `release.yml`,
   nothing that touches a server or an installation. A run says when a
   sprint's work is ready for a release.
6. Runs do not change rulesets, branch protection, repository
   settings, tokens or workflow permissions, and never skip, disable
   or weaken a test or a lint rule.

Interactive sessions with the owner present keep the protocol in
`CLAUDE.md` unchanged.

## Consequences

- The plan in `docs/roadmap/sprints.md` advances without the owner;
  its dates are no longer met week by week and the progress log in
  `docs/roadmap/roadmap.md` records what actually landed.
- Review shifts from before the work (plan approval) to after it: the
  pull request, its CI, the decision lines in `TASKS.md`, and ADRs for
  deviations. The owner can revert any of it.
- The manual checklists in `docs/TESTING.md` remain the owner's and
  still gate a release, never a merge.
- Owner decisions queue up as `Owner:` lines in `TASKS.md` rather than
  blocking a session.
