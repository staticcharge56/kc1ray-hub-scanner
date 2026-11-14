# Persistent activity and API reliability (Phase 2B)

## State and restart behavior

The monitor stores a versioned snapshot in `paths.monitor_state_dir/monitor-history.json`. When omitted, monitor_state_dir
defaults to state_dir; managed installation gives the monitor a separate directory.
This is independent of the authoritative favorites store and the display cache.
It contains the local node, statistics source, snapshot time, per-node counters,
last successful receipt/statistics timestamps, keyed/registration/link information,
recent activity detection times, error categories, and shared/per-node retry gates.
It does not store a trusted `active`/`idle` classification or favorite names/order.

Startup restores only current favorites with structurally valid observations.
A mismatched local node/source/version, future snapshot, damaged JSON, unreadable
or missing file produces a cold baseline rather than stopping the monitor.
Individual invalid records are skipped without discarding other valid nodes.
Reads are capped at 2 MiB. Invalid/future event times are dropped permanently.
Snapshots are never restored from the older dashboard activity cache.

History retention defaults to 24 hours. Retention permits useful counters to be
remembered; it does **not** extend the freshness or activity windows. Records older
than retention are dropped. Records within retention but outside the freshness
window can remain as diagnostic baselines, with status `unknown`. Their cumulative
growth is not used to infer new activity until a fresh baseline is established.
A pending valid provider retry delay can outlive activity retention and is still
restored; an expired observation never becomes active because of that retry state.

Classification is recalculated whenever the display cache is published:

- Both the last successful receipt (`checked`) and upstream statistics time
  (`stats_time`) must be positive, nonfuture, and no older than
  `max_stats_age_seconds`. The boundary is inclusive.
- Any recorded API error makes that node `unknown`, not `idle` or `active`.
- With fresh, error-free observations, a keyed sample or a nonfuture activity
  detection within `activity_window_seconds` means `active`; otherwise `idle`.

A saved label saying `active` is ignored. A fresh saved keyed observation can
restore activity only while both timestamps remain fresh. The existing browser
and scanner independently check those observation ages as time passes.

When successful counter samples advance, activity is detected only if the previous
successful baseline is also fresh and neither counter decreased. Repeated
statistics timestamps do not create new counter activity. A decrease in either
counter resets the baseline and clears prior activity; a genuinely keyed reset
sample can still indicate activity. Out-of-order timestamps are rejected.
`last_activity` remains the local detection time, not an exact RF event timestamp.

Renaming, adding, removing, and reordering favorites preserve history for retained
nodes. Removed nodes are dropped; re-adding them after removal establishes a new
baseline. Missing/malformed favorites during a live reload retain the prior list
and its history. Names/order always come from authoritative favorites JSON.

## Checkpoints and SD-card writes

History uses same-directory temporary files, file fsync, atomic replacement, and
directory fsync, with mode 0640. A failed write before replacement leaves the prior
snapshot intact; temporary files are cleaned. A directory-fsync failure after
replacement may leave a valid new file whose power-loss durability is uncertain.
Write failures are logged and do not stop live polling. Existing writable
state/cache directories and application permissions are still required.

Changed history is checkpointed at most once per 60 seconds by default. Identical
content does not produce another write. Failed attempts are also throttled.
Startup and orderly shutdown bypass the timer. SIGTERM and Ctrl-C flush through
the monitor's `finally` path; SIGKILL, power failure, or a failed disk cannot.
A hard stop can lose observations or a new retry gate since the last checkpoint,
roughly the checkpoint interval plus an in-progress request/scheduling delay.

The rebuildable activity cache is published at most once per 15 seconds during
normal polling, without explicit fsync. With four-second loops and quick responses,
that is usually every 16 seconds. Favorite edits publish promptly on the next
reload, and startup/shutdown force publication. The browser may therefore see
new statistics or an API error later than an individual request completes; its
own timestamp checks still reject stale observations between cache writes.

Default periodic upper bounds are approximately 1,440 history checkpoint attempts
and 5,760 cache publications per day, excluding startup/shutdown and favorite edits;
unchanged history results in fewer actual writes. The previous cache wrote up to
21,600 times/day. These are application-level estimates, not physical SD writes.
A configured cache directory on a volatile filesystem can reduce disk writes
further, but rebuildable schedule caches there also disappear after reboot.

## Statistics request reliability

The normal polling interval remains four seconds **after** a request completes.
Only one favorite is queried per loop; there is no parallel fan-out or immediate
retry loop. Timeout defaults to 10 seconds and response size to 262,144 bytes.
Payloads must have valid counters, timestamps, node metadata, keyed values, and
link structure. Invalid JSON, null/missing data, oversized bodies, stale/future/
out-of-order samples, HTTP errors, interrupted HTTP bodies, and timeouts become
explicit errors. Raw upstream exception bodies are not exposed as error messages.

A failed request preserves the last good counters, keyed value, statistics time,
and `checked` timestamp. `attempted` records the failed attempt separately.
An error category makes that observation unknown. Failures never refresh the
last successful timestamps or masquerade as measured inactivity. A successful
validated sample clears that node's error and retry gate; it also resets the
expired shared gate after successful provider access. Counter growth after
a long outage cannot alone claim recent activity from an expired baseline.

Retry state is separated into two scopes:

- **Shared:** HTTP 429 always pauses requests across all favorites, including when
  Retry-After is missing or invalid. HTTP 503 with a valid Retry-After also signals
  explicit provider-wide overload and uses this shared gate.
- **Per node:** malformed/missing/stale samples, timeouts, interrupted HTTP bodies,
  network failures, and other HTTP errors pause only the affected node. HTTP 503
  without a valid Retry-After is treated per node because shared scope is unknown.

Both scopes use 30, 60, 120, 240, 480, then 900 seconds by default, staying at 900
on further failures. Healthy samples do not reset another node's failure count.
Success clears only the queried node's gate and the expired shared provider gate.
A still-pending shared gate overrides every per-node gate.

The loop keeps one round-robin slot per favorite and sleeps at the existing normal
interval. A backed-off node's slot stays idle; it is not filled with another query.
Thus a bad favorite does not stop healthy favorites, accelerate their normal
cadence, or create a retry burst. The loop continues favorite reloads, cache aging,
and checkpoints during both kinds of backoff. At most one request occurs per slot.

HTTP Retry-After supports nonnegative integer seconds and timezone-aware HTTP
dates. The larger of exponential delay and provider minimum is used, for the scope
of that failure. Past, malformed, negative, or nonfinite values do not shorten the
exponential delay. A valid provider minimum may exceed 900 seconds; it is not
shortened to the local ceiling. For example, a 404 with Retry-After affects only
that node, while a 429 or a 503 with a valid retry directive affects all nodes.
There is no jitter or retry burst after recovery. In-process waits use a monotonic
clock, preventing a forward wall-clock jump from bypassing either gate. Checkpoints
convert remaining waits to wall-clock deadlines for restoration after restarts.

Retry snapshots include a scope version and per-node map. Per-node gates survive
normal restarts even when a failed node has no valid sample to save. Only current
favorites' gates are restored; removing a favorite also removes its in-memory gate.
Old Phase 2B global-only checkpoints remain readable: recorded 429 waits stay
shared, and other waits move to failed nodes identified by their saved error
categories. Older checkpoints did not preserve response headers or identify
failed nodes with no valid observations; ambiguous legacy waits cannot be
reconstructed exactly. This affects retry metadata, not valid activity baselines.
No history file or favorites migration command is required for this change.

Independent processes and other applications behind the same public IP still do
not share a request budget. Run one monitor per installation and budget other
statistics clients separately. During widespread network failures, each node
backs off independently; the normal aggregate ceiling remains unchanged rather
than imposing an inferred provider-wide pause. No current provider allowance or
provider-specific nonstandard rate-limit signals are assumed here.

## Favorite count, freshness, and accuracy

For N favorites and polling interval P, the **minimum** revisit time is `N * P`.
Actual cycles add every request's duration and any retry delays. This is a lower
bound, not an adaptive freshness setting or a promise about API update frequency.
The monitor logs a warning when this minimum reaches either the statistics-age or
activity-window limit; it never silently increases polling frequency or freshness.

| Favorites | Minimum cycle at 4 seconds | Implication with 300-second windows |
| --- | --- | --- |
| 10 | 40 seconds | Usually room for latency; short RF activity can still be missed |
| 50 | 200 seconds | Limited headroom for slow responses and backoff |
| 75 | 300 seconds | No headroom; real revisit times exceed the freshness window |
| 250 | 1,000 seconds | Some observations inevitably become unknown between polls |

Reducing favorites improves revisit time without increasing upstream request rate.
Increasing freshness/activity windows trades stronger recency guarantees for more
retained indications; it cannot recover transmissions missed between observations.
Making the interval shorter increases API traffic and shared-IP rate-limit risk;
this increment does not do so automatically. At the default interval the theoretical
maximum normal request rate is 15/minute before network time and pauses. For a
single favorite it is still one request per loop, not a new per-cycle burst.

## Configuration additions

Existing Phase 2A TOML remains valid and untouched; missing keys inherit defaults.
All of the following belong under `[monitor]`:

| Key | Default | Meaning |
| --- | --- | --- |
| history_retention_seconds | 86400 | Maximum age of retained observations/baselines |
| history_write_interval_seconds | 60 | Minimum interval between routine history write attempts |
| cache_write_interval_seconds | 15 | Minimum interval between routine display-cache writes |
| response_max_bytes | 262144 | Statistics response limit; accepted configuration range 1024–16777216 |
| backoff_initial_seconds | 30 | First failed-request delay |
| backoff_max_seconds | 900 | Exponential ceiling; must be at least the initial delay |

Intervals are positive integers. Existing polling/freshness/activity/timeout keys
are unchanged. Configuration updates require a monitor restart. No favorites
migration or rewrite is needed for this increment.

## API diagnostics and troubleshooting

`GET /api/activity` retains its existing shape and gains monitor-provided fields:

- `api.failures`, `api.retry_at` (Unix epoch or zero), and `api.error_kind` describe
  the shared gate. Zero retry_at means no remaining wait, even if the prior failure
  category remains until the next successful request.
- `api.nodes[NODE]` contains that favorite's independent `failures`, `retry_at`,
  and `error_kind`. `api.scope_version=2` identifies the separated retry format.
- `polling.favorite_count`, `minimum_cycle_seconds`, `max_stats_age_seconds`,
  `activity_window_seconds`, and `freshness_warning` describe cycle headroom.
- Per-favorite `attempted`, `error`, and `error_kind` distinguish failed requests
  from the preserved successful `checked` and `stats_time` values.

Categories are `rate_limit`, `http`, `network`, `timeout`, `invalid_response`, and
`stale_response`. The existing UI is unchanged; errors/staleness show as unknown.
Gate diagnostics are available through cached JSON and monitor logs rather than
new UI controls. Radio command flow/cooldown are unchanged; API access now follows
[Phase 3 authorization](security.md).

For missing history, expect cold baselines until valid samples arrive. For damaged
history, inspect the logged warning and retain a copy if needed; the next writable
checkpoint replaces it with valid state. Repeated checkpoint failures require
checking the configured directory, free space, and permissions. A long wait after
429 may be an intentional Retry-After minimum; inspect api.retry_at (shared) or
api.nodes[NODE].retry_at (individual) rather than
restarting repeatedly. Check clock accuracy if samples/history are rejected as
future. HTTP socket timeouts apply to blocking operations, not a hard total
wall-clock deadline against an indefinitely trickling response. Size limits bound
accepted response bytes. Actual ASL3/ARM64, mobile, and SD-card endurance acceptance
still require later development-environment integration tests.

## Node directory descriptions

The existing per-favorite statistics request also supplies the AllStarLink node
metadata. `node.node_frequency` is the public directory's description/frequency
text (for example, node 29332 is "Alaska AllStar Hub" in the
[AllStarLink directory](https://allmondb.allstarlink.org/allmondb.php)). `node.name`
is the numeric node identifier; server names, locations and NetWatch descriptions
are not substituted for the directory description.

The monitor keeps a separate `node_description` string in activity.json. Text is
whitespace-normalized, control characters removed and limited to 256 characters.
No favorites.json data is changed: the operator's custom name remains the card
title and favorites order is unaffected. Active/All append the directory text
between node number and activity status. Nets retain their net title, membership
and schedule information while adding cached node descriptions; Favorites retain
their custom title and priority index. Text is inserted using textContent, never
interpreted as HTML. Missing descriptions create no blank separator or placeholder.

There are no additional upstream calls, browser directory lookups or changes to
polling/backoff. Description data is harvested even when the same response's
activity statistics are unusable, but it never supplies a counter, timestamp or
active classification. HTTP/network failures or malformed/missing description
fields retain the last known description; a valid, explicit empty description
clears it. Activity still becomes unknown whenever statistics are failed/stale.

The existing atomic, throttled history checkpoint includes an optional
node_descriptions map for current favorites. This is an additive schema-1 field;
older state files still load, and older readers can ignore it. Descriptions may
survive beyond activity-retention limits as metadata-only records; rejected old
counters and RF activity are not revived. Existing cache/checkpoint write intervals
are unchanged, so an abrupt failure can lose changes not yet checkpointed.

Nets nodes not monitored as favorites have no description unless one is already
available in the activity data. Their original membership/node information remains
visible without an invented directory description or inferred RF activity. Adding
one to Favorites lets normal polling populate metadata; no NetWatch schedule text
is used as a substitute and no NetLogger/AllScan dependency is introduced.
