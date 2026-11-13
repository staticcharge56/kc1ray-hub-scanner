# Phase 1 validation and handoff (historical)

> Historical development report. Its test counts and open hardware gates describe
> that phase. See [the current public-release review](public-release-review.md)
> for 0.4.4 hardware acceptance, the 336-test LAN-first baseline and current blockers.

Current validation is recorded in [Phase 5 release readiness](release-readiness.md).

## Result

Run from the project root:

```sh
python3 -B tools/check.py
```

Phase 1 result: **22 tests passed**. All six current runtime modules and the
new Python tooling/tests parse successfully; embedded JavaScript passes Node.js
syntax validation. TOML/JSON examples parse and retain the proposed local-only,
unauthenticated-controls-disabled defaults. SHA-256 checks confirm all six runtime
files remain byte-for-byte unchanged from the beginning of Phase 1.

## Coverage and practical limits

| Area | Baseline evidence |
| --- | --- |
| Selection | FIRST order, NEXT wrap/removed selection/current-node exclusion, no eligible node preserves state |
| Commands | Dry run avoids commands/state writes; STOP targets saved selection; failed connect retains previous state |
| Freshness | Inclusive 300-second eligibility boundary; stale/future/invalid samples rejected by scanner |
| Monitor | Initial counter baseline, activity on increase, reset handling, stale keyed sample rejection and unknown cache status |
| Favorites | Add/edit/remove/reorder; invalid mutation preserves JSON; synthetic legacy import order and dedup policy; monitor reads replacement without restart |
| Schedules | Approved AllStar filtering, duplicate node handling, stale generation rejection, timezone requirement, complete/truncated weekly HTML |

Tests patch all paths they write into temporary directories. External subprocesses
and urllib HTTP calls are blocked within each test; scanner command submission is
mocked. No HTTP server, monitor loop, systemd service, or radio entry point starts.
The syntax runner invokes only Node.js syntax checking and Python unittest.

These are characterization tests, not proof that the known security or lifecycle
issues are fixed. Phase 1 does not implement or validate authentication, HTTP 429
backoff, restart persistence, authoritative-store migration, confirmed linking,
single-link behavior, proxy trust, installer lifecycle, browser/mobile behavior,
or ASL3/ARM64 compatibility. Live reload coverage checks successive reads after
replacement, not the full endless monitor scheduling loop. CLI invocation and
Asterisk reported link formats need integration fixtures.

## Deployment evidence needed before control integration

Use sanitized copies supplied for local development; no production access is
required or authorized:

- Existing dashboard/monitor/updater systemd unit and timer definitions.
- DTMF function mappings and wrapper commands that invoke scanner.py, including
  interpreter, arguments, service identity, and expected exit/output handling.
- The existing single-link hook and how it is invoked.
- Representative successful, disconnected, connecting, and failed Asterisk
  RPT_ALINKS output, with identifying details replaced consistently.
- A representative legacy favorites export with ordering, Unicode, quotes,
  backslashes, duplicates, and node-specific sections represented synthetically.

Do not supply passwords, Asterisk manager secrets, Tailscale keys, or private
addresses. These missing artifacts constrain exact compatibility verification;
they do not prevent the next configuration/data work.

## Proposed next increment for owner review

Begin Phase 2 with shared configuration loading and validation under isolated
paths, followed by one authoritative JSON favorites store and explicit backed-up
migration. Preserve root CLI compatibility while introducing modules incrementally.
Then add restart-safe activity persistence, stale/future timestamp validation,
and Retry-After/backoff tests and implementation. Keep radio controls unchanged
until the separate secure-control phase. The draft configuration is not a promise
of implemented behavior and must be reconciled with each incremental change.

Historical backups and root runtime state remain on disk. Ignore rules only
prevent new untracked additions; they do not remove previously tracked content.
A later publication audit must inspect the actual repository index/history and
confirm source ownership before publication. MIT and attribution are now owner-approved;
see the current public-release review.
