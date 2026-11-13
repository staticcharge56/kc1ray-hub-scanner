# Targeted reliability improvement: shared and per-node retries

The Phase 2B follow-up separates provider-wide throttling from individual failures.
No Phase 3 or installation work is included.

## Behavior

- HTTP 429 always uses the shared gate. HTTP 503 with a valid Retry-After is also
  treated as explicit shared provider overload, including a valid zero/past delay
  (the exponential minimum still applies).
- Invalid/missing/stale node statistics, timeouts, network errors, and other HTTP
  failures use independent per-node gates. A 503 without a valid retry directive
  remains local to the requested node.
- Each scope keeps the configured exponential sequence and honors a valid
  Retry-After minimum even above the exponential ceiling. Healthy responses never
  reset another node's backoff; success clears only the responding node's gate and
  any expired shared failure sequence.
- Round-robin slots and the normal four-second sleep remain unchanged. A backed-off
  node's slot is idle; there are no replacement requests or catch-up bursts. The
  normal aggregate ceiling stays at one request per slot (at most 15/minute with
  the default interval, before network time).
- Failed nodes remain unknown. Their valid counters, receipt/statistics timestamps,
  and activity history remain intact, subject to the existing freshness checks.
- Both gate scopes are checkpointed atomically with the existing history state.
  Per-node delays restore even without any valid saved observation for that node.
  Removed favorites' gates are filtered out and cleaned during live reload.

Details and updated diagnostics (`api.nodes[NODE]`) are documented in
[activity-monitoring.md](activity-monitoring.md). No configuration changes or
manual favorites/history migration are needed.

## Changed files

Runtime changes are confined to `monitor.py`, `stats_api.py`, and the retry-metadata
return condition in `activity_history.py`. Activity record validation and atomic
checkpoint implementation are preserved. Existing test fixtures isolate/reset the
new per-node state, and the earlier repeated-network-failure test now checks the
node gate rather than a shared gate. `tests/test_retry_scopes.py` adds 15 cases.
README and monitoring/validation documents describe the current scope policy;
`phase-2b.md` remains a marked historical handoff.

SHA-256 checks confirm dashboard.py, scanner.py, favorites_store.py,
migrate_favorites.py, update_netwatch.py, and update-nets.py remain byte-for-byte
unchanged. Shared configuration defaults, radio-control behavior and cooldown,
NetWatch, favorites management, and mobile wake lock were not changed.

## Test results

`python3 -B tools/check.py` passes **120 tests**: the previous **105 cases**, with
scope expectations adapted to the authorized change, plus **15 new regression
cases**. Python syntax checks and rendered JavaScript `node --check` pass.
Configuration examples still validate without modification.

New coverage includes mixed healthy/failing nodes, independent exponential counts,
node-local seconds/date Retry-After, global 429 precedence, explicit 503 overload,
recovery without clearing other failures, unchanged healthy-node polling cadence,
no recovery bursts, history/baseline preservation, both scopes across restart,
legacy checkpoint translation, invalid state, long provider delays, and live
removal of a backed-off favorite. All tests use temporary files, mocked HTTP, and
controlled clocks; they make no real network requests or real-time sleeps.

## Remaining limitations

- Scope uses standard HTTP signals, not provider-specific undocumented headers.
  Ambiguous transport/server failures stay per node. During a broad outage the
  monitor can still probe other nodes at the normal aggregate ceiling until their
  individual backoffs apply; it does not assume a provider-wide rate limit.
- Gates are local to this monitor, not a distributed/shared-IP budget across
  independent processes or applications. Run one monitor instance per installation.
- Legacy global-only checkpoints lack response headers and can omit failed nodes
  that never had valid observations. Legacy 429 waits remain shared; other legacy
  waits can be restored only to identifiable failed nodes. New snapshots explicitly
  record scope and do not have that ambiguity.
- Existing checkpoint intervals, hard-stop data-loss window, per-operation socket
  timeout, favorite-count/freshness tradeoff, and hardware-validation limits remain.
  Live API behavior and ASL3/ARM64 hardware were not exercised in this offline change.

All work stayed in the local development repository. No production Pi access,
service/Asterisk configuration edits, commits, deployment, or publication occurred.
