# Phase 2B implementation and review (initial handoff)

The subsequent [retry-scope reliability improvement](retry-scopes.md) replaces the
global-for-all-errors policy described in this historical handoff. See
[activity-monitoring.md](activity-monitoring.md) for current behavior.

## Outcome

The monitor now restores validated recent observations and transmission baselines,
uses atomic/throttled checkpoints, and handles statistics failures with bounded
reads and an endpoint-wide retry gate. Phase 2A configuration selection and the
authoritative JSON favorites store are preserved. Existing TOML files work without
new keys and are never rewritten. Operational details and tradeoffs are in
[activity-monitoring.md](activity-monitoring.md).

## Files changed

| Files | Change |
| --- | --- |
| monitor.py | Restore/flush history, recalculate activity, validate baseline continuity, preserve valid samples on errors, gate HTTP requests, throttle writes, add polling diagnostics and SIGTERM shutdown handling |
| activity_history.py (new) | Versioned bounded history loading, record/timestamp validation, derived classification, atomic JSON publication, history checkpoint and write-attempt throttling |
| stats_api.py (new) | Bounded HTTP reads, payload validation, Retry-After parsing, monotonic exponential retry policy and restart restoration |
| configuration.py | Backward-compatible monitor settings and validation for retention, write intervals, response size and backoff |
| config/config.example.toml | Document implemented Phase 2B settings and defaults |
| tests/test_monitor_reliability.py (new) | Fifty new offline cases for persistence, API failures/recovery, boundaries, throttling and phase scope |
| tests/test_baseline.py | Isolate retry state between existing monitor regression cases |
| tests/test_configuration_favorites.py | Isolate the existing live-loop test's startup history and write timer |
| tests/fixtures/phase-2b-protected.json (new) | SHA-256 baseline proving six out-of-scope runtime files remain unchanged |
| README.md and docs/*.md | Current reliability documentation/report; historical handoffs marked as historical |
| .gitignore | Exclude local monitor-history.json from new Git additions |

No third-party dependencies were added. `tools/check.py` remains the same check
entry point and automatically includes the new root modules and tests.

## Validation

Final executable-code validation: `python3 -B tools/check.py` passed **105 tests**,
including all **55 existing Phase 2A tests** and **50 new Phase 2B tests**. Python
syntax checks cover all ten root modules and the tests/tools. Rendered embedded
JavaScript passes Node.js syntax checking. Configuration examples pass validation.

New tests use temporary files, controlled wall/monotonic clocks, and mocked network
responses. They never sleep in real time, contact the API/Pi, or run Asterisk.
Coverage includes:

- Fresh clean restart, startup restoration and normal shutdown flush.
- Missing, damaged-shape, oversized, stale, future, wrong-source and
  partially invalid history; saved status labels never trusted.
- Retention versus freshness, inclusive timestamp boundaries, future activity
  rejection, counter/node resets, repeated/out-of-order samples, and long-outage
  baseline recovery without invented recent activity.
- Renamed/reordered/added/removed favorites, transient live read failures, and live
  favorites updates while the endpoint is rate-limited.
- HTTP 429 and 503, numeric/date Retry-After, invalid and exceptionally long delays,
  endpoint-wide pauses, monotonic waits, persisted retry restoration, bounded
  repeated failures and successful recovery.
- Invalid JSON, null/missing fields, invalid types, timeouts, truncated HTTP bodies,
  response-size limits and forwarded timeout configuration.
- Atomic replacement/fsync failures, old-state preservation, cleanup, unchanged
  checkpoint suppression, successful and failed write throttling, continued polling
  despite disk failures, and default cache/poll timing.
- Backward-compatible retained configuration, validation of new settings, and
  byte-for-byte protected-runtime checks.

SHA-256 assertions confirm dashboard.py, scanner.py, favorites_store.py,
migrate_favorites.py, update_netwatch.py and update-nets.py are unchanged throughout
Phase 2B. Thus radio command implementations, FIRST/NEXT/STOP/manual/Nets controls,
NetWatch integration, favorites management and the screen-awake UI were not edited.
The configured radio cooldown remains unchanged, with a 15-second default.

## Defaults and decisions for owner review

1. **24-hour retention, unchanged five-minute freshness/activity defaults.** Old
   baselines can be retained diagnostically but cannot infer new activity from
   cumulative increases across an expired observation gap.
2. **60-second durable checkpoints and 15-second rebuildable cache publications.**
   Favorite edits and orderly startup/shutdown are exceptions. This reduces writes
   but adds display latency and permits recent state loss on a hard stop.
3. **Endpoint-wide backoff for every failed sample.** This favors provider load
   protection over collection speed. A persistently bad/stale node can slow other
   favorites. No per-node retry policy or cross-process budget coordination is
   implemented.
4. **Provider Retry-After is a minimum.** Exponential delay caps at 900 seconds;
   valid provider delays can be longer and survive restart even when activity
   retention expires. Very long valid delays therefore intentionally pause queries.
5. **Errors display as unknown.** Last good observations remain available in JSON,
   but errors never refresh successful timestamps or become measured inactivity.
   Existing UI controls are unchanged; richer retry diagnostics are in API JSON/logs.

These choices are configurable where documented and do not require a production
change to review. No outstanding input is required for the completed local tests.

## Remaining limitations and phase boundaries

- No production Raspberry Pi access, real upstream requests, Asterisk commands,
  service/unit edits, commits, deployment, or publication occurred.
- Actual ASL3 on Debian 12/ARM64, real-world API schema variations, mobile behavior,
  and physical SD-card write endurance are not verified by mocked local tests.
- Socket timeout is per blocking operation, not a hard overall response deadline.
  Accepted response bytes are capped; redirects retain urllib's existing behavior.
- One monitor process should run per configured installation. The gate does not
  synchronize independent processes/apps sharing an upstream/public IP budget.
- Large favorite lists inevitably exceed five-minute windows at a four-second
  interval; no rate or freshness window is automatically increased to hide that.
- Orderly SIGTERM/Ctrl-C attempts a final checkpoint; power loss, SIGKILL and disk
  failures can lose recent state. The display cache is rebuildable and not fsynced.
- Local clock correctness matters for freshness and restoring wall-clock deadlines;
  monotonic gating protects only the running process from wall-clock jumps.
- This phase adds neither authorization nor confirmed radio-link transitions.
  Phase 2A's default disabled mutations remain; enabled mutations are still legacy
  unauthenticated behavior. Phase 3 and installation packaging have not begun.
