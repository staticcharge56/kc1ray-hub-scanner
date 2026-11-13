# Current behavior baseline

Historical Phase 1 record: this describes the originally supplied implementation.
See configuration.md and phase-2a.md for the current increment.
Phase 1 leaves all six runtime modules unchanged. File hashes in
`tests/fixtures/runtime-baseline.json` identify that baseline; intentionally update
or retire this guard when approved runtime development begins.

## Components and data

| Component | Current responsibility |
| --- | --- |
| dashboard.py | Standard-library threaded HTTP server; inline HTML/CSS/JS; all four tabs; radio commands and scanner subprocess |
| monitor.py | Sequential statistics polling; live INI reload; activity cache |
| scanner.py | CLI FIRST/NEXT/STOP; selection state and Asterisk commands |
| favorites_store.py | JSON favorites manager plus generated compatibility INI |
| update_netwatch.py | Optional-in-design NetWatch cache producer; no NetLogger calls |
| update-nets.py | AllStar Nets weekly HTML schedule cache |

Favorites JSON and generated INI live under `/var/lib/allstar-mobile-scanner`.
The monitor reads INI, while the dashboard manager reads JSON. Both files are
individually atomically replaced, but are not one transaction. Order is scanner
priority. Names are stored without an appended node in JSON; INI labels append
the node. The INI monitor parser does not unescape labels like the writer does.

Activity and legacy schedule caches live under
an operator-specific home directory (redacted for publication); NetWatch and scanner state live under
`/var/lib/allstar-mobile-scanner`. The configured local node is repeated in
Python and UI strings. No installation units, timers, Asterisk hooks, actual
favorites, or production Asterisk configuration were supplied.

## Activity and history

One favorite is polled, followed by a four-second sleep. Requests time out after
10 seconds. Each iteration reloads favorites; transient read/encoding failures
retain the previous list. Renaming/reordering retains existing records; removing
a favorite drops its record. Startup requires a readable favorites file.

A node becomes active on a fresh keyed sample or an increase in total keyups or
transmit time with an advancing statistics timestamp. The first unkeyed sample
establishes baselines without declaring activity. Decreasing counters do not
indicate activity. Activity remains active for 300 seconds after detection if
statistics remain fresh; otherwise status is idle or unknown.

Records and counter baselines exist only in memory. The monitor writes a display
cache, but never restores its history from that cache on startup. HTTP errors,
including 429, are recorded as errors; Retry-After is not honored. There is no
adaptive backoff or statistics response size limit.

The monitor checks statistics time against future timestamps, but does not
consistently reject future checked/last-activity values. The browser and scanner
have additional freshness checks; future-time validation needs consolidation.
The scanner requires active status, registered=True, no error, and both checked
and statistics times within the preceding 300 seconds, inclusive.

With N favorites, revisit time is at least 4*N seconds plus network time. At 75
favorites this reaches the freshness window; the permitted 250 favorites cannot
all remain fresh. No verified current external API allowance is encoded here.
Other applications behind the same public IP may consume the same provider budget.

## Radio controls and DTMF compatibility boundary

CLI contract: `scanner.py {first,next,stop} [--apply]`. Without --apply it does not
submit radio commands, but `main()` still opens the configured lock file. Preserve
these action names, argument ordering, dry-run default, and meaningful exit codes
for existing external wrappers. The supplied scanner has a leading blank line
before its shebang; direct executable invocation needs explicit verification.

No DTMF mapping or wrapper is included. Exact DTMF digits and invocation method
cannot be established from this copy; do not invent or replace those mappings.

| Action | Current behavior |
| --- | --- |
| FIRST | Select first eligible favorite in stored order; same saved selection suppresses a new command without checking actual link state |
| NEXT | Start after saved selection, wrap once, skip that selection; missing saved favorite starts at the beginning |
| STOP | Disconnect only the saved scanner-selected node and clear state after command submission; other links are left alone |
| No eligible favorite | Report no selection and leave connection/state unchanged |
| Individual Connect/Disconnect | Validate favorite against activity cache; read direct links before command; skip already-satisfied request |
| Nets Connect | Allow numeric node from fresh cached directory, even outside the current displayed schedule window |
| Nets Disconnect | Allow any directly connected numeric node; directory membership is not required |

Commands use `asterisk -rx 'rpt cmd LOCAL ilink 3 TARGET'` for connect and ilink 1
for disconnect, with argument arrays and numeric validation. Direct links come
from `rpt show variables LOCAL`, parsing RPT_ALINKS entries with two-letter
suffixes. Scanner and manual paths share a file lock. The CLI does not query
actual links. Manual controls query before submission, but neither path verifies
the resulting state afterward. Saved selection means requested, not confirmed.

Connecting does not explicitly disconnect the previous link. Scanner output
assumes an external single-link hook will do so; that hook is absent. The approved
replacement must disconnect-before-connect by default and confirm Asterisk state.

## Web/API baseline

The server binds `0.0.0.0:8085`, with no authentication or TLS.

| Method/path | Request/response |
| --- | --- |
| GET / | Inline dashboard with Active, All, Nets, Favorites and wake-lock control |
| GET /api/activity | Cached statistics plus best available schedule; missing activity yields empty favorites; invalid cache may pass through |
| GET /api/links | Runs Asterisk for each request; returns links array or 503 |
| GET /api/favorites | Returns favorites array or 503 |
| POST /api/control | JSON action and optional node; message response |
| POST /api/favorites | JSON action, node, optional name; updated favorites response |

Control actions: first, next, stop, connect-node, disconnect-node, connect-net,
disconnect-net. Favorites actions: add, edit, remove, up, down. Favorites require
4–7 ASCII digits, unique nodes, names up to 160 characters without C0 controls,
and at most 250 entries. Nets controls accept 3–7 digits. Consistent node policy
must be settled during configuration work.

POSTs require JSON and `X-Scanner-Control: 1`. Optional Origin is compared with
supplied Host; this is not authentication. Favorites requests are limited to
2048 bytes, control requests to 1024. Invalid JSON container shapes are not all
handled. Radio web actions have a nonblocking command lock and 15-second cooldown
recorded after success; failures and favorites writes have no equivalent limiter.
429 responses omit Retry-After. CLI controls bypass the web cooldown.

Dashboard refresh is every 10 seconds and includes a live links request. Nets
adds cached activity fetches while visible. Upstream statistics traffic does not
increase per viewer, but Asterisk queries do. Arbitrary reachable API clients can
control radio and favorites. Raw command/error output may reach clients.

## Schedules and mobile UI

NetWatch import accepts approved published AllStar occurrences, validates aware
start/end timestamps and generatedAt, deduplicates occurrences, bounds downloads,
and preserves the previous cache on failure. Dashboard freshness is 90 minutes;
weekly fallback is considered usable for controls for 72 hours. Updater scheduling
is external and unknown. There is no NetLogger polling.

The Nets view displays current scheduled windows and starts within 24 hours in
the browser's local time. A schedule is not proof of RF activity. Favorite rows
combine schedule with statistics activity; weekly fallback assumes 60 minutes.
Nets supports Connect/Disconnect and Add to Favorites. Cached schedules keep the
scanner usable when remote sources fail; no schedule is required for ordinary
favorite selection. Stale fallback display handling differs between views.

Keep Screen Awake uses browser Screen Wake Lock in a secure context, requests
only while visible, and attempts reacquisition when the tab returns. Browser
support and HTTPS must be tested on devices. No mobile browser test was performed
in Phase 1. Tab switching currently uses layered replacements of setFilter.
