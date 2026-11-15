# Advanced administration — 0.7.0-beta

Phase 1 Admin was reported hardware-tested by the owner on a spare Debian 12
ARM64 ASL3 system with Apache and Cockpit. Phase 2 extends that same tab and
restricted helper. It needs new installed acceptance; local tests are not hardware
certification. No Pi or installed service was changed during development.

## Local node and cooldown

Sign in, open Admin and select a locally discovered node. Discovery reuses the
installer's bounded, read-only `rpt.conf`/include parser. It never executes #exec,
writes Asterisk files, changes registration or issues a radio command. Dynamic-only
nodes and unavailable discovery cannot authorize a selection. Read permissions or
unsupported includes can make discovery unavailable; Phase 1 settings remain usable.
The current node is retained even if it is not discoverable.

Clear any scanner selection with **STOP**, then confirm a node change. The helper
refuses a nonempty or damaged scanner selection. Existing manual Asterisk links
are left untouched: inspect them and end them separately if appropriate before
switching. The broker restarts with the new node, the monitor restarts with its
history handoff, and the web process applies the node on subsequent requests.
No administrator sessions, favorites, credentials or unrelated settings are reset.
An active radio or CLI operation makes Save return busy; retry after it completes.

Cooldown is **15–300 seconds**, default **15**. A change restarts an active broker;
the web process reads the same value. The trusted scanner CLI also reads current
policy under the shared lock. The existing last-command record is retained.
Neither link-state verification, disconnect-before-connect nor the 18-second
transition deadline can be altered in Admin. The current selection and cooldown
are independent of Asterisk DTMF mappings; none are edited.

## Backend monitoring versus dashboard refresh

| Setting | Admin range | Existing default |
| --- | --- | --- |
| Dashboard refresh | 5, 10, 15, 30, 60 seconds | 10 seconds |
| Poll interval per favorite slot | 4–300 seconds | 4 seconds |
| Statistics freshness | 60–3600 seconds | 300 seconds |
| Recent activity window | 60–3600 seconds | 300 seconds |
| NetWatch recurrence | 30–1440 minutes | 30 minutes |
| AllStar Nets calendar | Daily or Sunday at 03:00 UTC | Daily at 03:00 UTC |

Only changed values are submitted by the UI. Existing manually configured values
outside Admin's range may be retained unchanged; new values must meet the limits.
The monitor restarts only for a changed monitor setting or local node. It retains
history, counters, cached descriptions and global/per-node retry state. A root-owned
`node-handoff.json` beside `config.toml` authorizes same-source history restoration
across an approved node change or its recovery. Normal source, retention and
freshness checks still apply; a handoff never asserts that a node is active.
Damaged/untrusted handoffs are ignored. The monitor republishes the checkpoint
under the new local identity. No baseline is fabricated and no retry delay is reset.

A cycle takes **at least favorite count × poll interval**, plus network time and
backoff. For example, 80 favorites at 4 seconds require at least 320 seconds, which
already exceeds a 300-second freshness window. Raising frequency cannot bypass
provider-wide HTTP 429 or per-node failure gates. Longer freshness windows tolerate
longer cycles but retain older observations; shorter windows produce more unknown
nodes. Dashboard refresh only rereads local caches and does not change API polling.

## Schedule timers

Frequency changes create only `50-hubscanner-admin.conf` in the existing fixed
NetWatch/AllStar Nets timer drop-in directories. They do not create duplicate
timers, run import commands directly or delete cached schedules. A disabled timer
stays disabled when only its frequency changes. An enabled timer is restarted to
apply its new schedule. An already-running import can finish after its timer is
disabled; its service is not killed.

NetWatch retains its two-minute boot activation and 60-second random delay.
AllStar Nets retains UTC scheduling, persistent missed-run catch-up and 15-minute
random delay. Restarting an enabled timer may trigger its existing due/boot/catch-up
activation; this is not a new parallel poller. The reset directive replaces prior
trigger lists, explicitly restoring NetWatch's boot trigger. This follows
[systemd 252 timer semantics](https://www.freedesktop.org/software/systemd/man/252/systemd.timer.html).

Existing source cache expiry thresholds are **not** stretched automatically when
frequency is reduced. For example, the default NetWatch cache expires after 90
minutes, so a multi-hour recurrence can intentionally leave stale/unavailable nets
between imports. Review Diagnostics for source health. Source URLs, cache expiry,
jitter and arbitrary calendar expressions remain outside Admin.

Custom timer unit text, non-owned drop-ins or unsupported owned content make
frequency editing unavailable. Their contents are preserved. Source enable/disable
and other Phase 1 settings remain available. Review custom systemd configuration
outside the dashboard; do not delete operator overrides merely to enable editing.

## Diagnostics and recovery

Refresh Diagnostics reads caches, the installed package identifier, fixed service
states, and up to 100 recent journal entries from the six application services
within the last day. Journal reads have a five-second deadline and 64 KiB output
cap. Only known warning/error prefixes become fixed summaries; raw journal messages,
tracebacks, upstream errors, URLs, passwords, cookies and headers are never returned.
At most 25 recognized events are displayed. An empty event list does not prove
there were no errors; unknown message formats are deliberately omitted.

Activity diagnosis reports freshness, last successful sample, global provider
backoff and per-node retry information. It displays at most 100 nodes/retry entries;
large favorite lists are explicitly marked as truncated. Cache, sample and source
health are distinguished from service health. Failed requests remain unknown even
when a previous sample is still fresh. Missing or damaged data is unavailable,
not an idle node. Connection state comes from the existing restricted radio broker
and its five-second link cache; no privileged Asterisk access is added to Admin.

Save serializes against other Admin, installer and radio operations, checks a
revision covering configuration and owned timer overrides, then journals previous
configuration, timer files and service state. Failure restores old configuration
and overrides, reloads systemd and restarts only previously active affected
application services. Unresolved recovery leaves a private journal and fail-closed
controls. Use the existing [Admin recovery procedure](installation.md#admin-helper-recovery).
If an HTTP request times out, reload status before retrying; the helper may still
be completing its transaction. Do not discard a pending journal.

Upgrades preserve configuration/credentials and existing owned schedules. The new
installer backs up both timer drop-in directories and understands old 0.6.0
snapshots. Rollback restores schedule files and service state. Normal uninstall
removes only Admin-owned frequency overrides, retaining their data in private
configuration for reinstall; operator overrides remain. Purge retains its existing
explicit-confirmation requirements. Use the new installer for lifecycle operations
on a Phase 2 installation; an old installer cannot back up new timer areas.

## Spare-Pi acceptance still required

With RF disabled and no production access, verify node discovery under the actual
root-helper sandbox, multiple-node selection, STOP prerequisite, read-only link
queries, broker/monitor startup and history/backoff preservation. Test timer changes
with `systemctl cat` and `list-timers`, disabled timers, jitter/catch-up, failure
recovery and reboot. Verify owner/mode preservation and rollback from 0.7.0 to
0.6.0 using the new installer. Exercise desktop/mobile Admin, session expiry,
password reauthentication, diagnostics redaction and `/hubscanner/` over HTTP/HTTPS.
Asterisk-owned private configuration may make read-only discovery unavailable;
no Asterisk group membership or filesystem permissions are silently changed.
