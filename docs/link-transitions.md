# Application-owned disconnect-before-connect

See the current [connection-state safety correction](connection-state-safety.md):
C is connecting, not established; only verified T/R can confirm success.

This policy is for personal AllStarLink nodes. It runs entirely in Hub Scanner's
restricted radio-control broker and shared scanner code. It does not edit rpt.conf,
DTMF mappings, Asterisk hooks or single-link.sh. No Pi changes or deployment were
performed. Existing high-powered/public-node connection policy is outside scope.

## Connect, FIRST and NEXT

Manual Favorites Connect, Nets Connect and the existing FIRST/NEXT selection rules
all use radio_control.py. Selection still uses authoritative favorites order and
fresh activity; no eligible node means the existing connection is left unchanged.
Before a connection can be reported successful:

1. Read fresh Asterisk RPT_ALINKS through the local CLI. Never use a saved selected
   node or cached browser status as proof of current connections.
2. If the destination is already the only reported direct link, submit no radio
   commands. Wait if it is C; confirm the scanner position only after established T/R.
3. Otherwise request disconnect of every currently reported direct link, including
   the requested destination if it is among multiple links.
4. Poll until those links have cleared. A disconnect error, unavailable/ambiguous
   status, timeout or unexpected new connection aborts the new connect.
5. Check again immediately before connect that the link set is empty. Record the
   requested destination as pending, submit connect, then confirm it is the sole
   reported link in a verified established state. A successful CLI command acknowledgment alone is insufficient.

ASL3 may report exactly one literal empty `RPT_ALINKS=` field when there are no
links. That is accepted alongside numeric zero; missing, duplicate or malformed
fields still fail closed. See the [empty-status correction review](link-status-compatibility.md).

This deliberately replaces all reported direct connections; there are no permanent,
inbound or public-node topology exceptions. Indirect network participants are not
individual local direct links. The recognized RPT_ALINKS format is a count followed
by numeric node IDs with two-letter suffixes. Count mismatches, duplicate IDs,
missing fields, nonnumeric/unsupported links or multiple status fields fail closed
instead of being silently dropped and mistaken for an empty node. Real ASL format
coverage remains a spare-system acceptance check, not a claim based on mocks.

## STOP and individual Disconnect

STOP reads actual links and disconnects only the scanner's applicable selected
connection, favoring a pending requested destination if it has become active.
Other connections are not dropped by STOP. A stale selection with no applicable
active link is cleared without a disconnect command. Individual Disconnect checks
and confirms only the authorized requested node; it leaves unrelated links alone.

A failed/timed-out connection is not marked confirmed. scanner-state.json retains
an additive pending_node field before connect submission, so STOP can recognize
a late-arriving requested connection. Legacy states with only node still work.
confirmed=true and the final node are stored only after an actual status query
confirms an established T/R result. Pending requests explicitly store confirmed=false. An unavailable status or failed STOP does not discard the
selection needed for retry. State changes use atomic JSON replacement.

## Locks, cooldown, timeouts and security

The radio broker executes FIRST/NEXT/STOP selection in-process using the bundled
scanner module, avoiding orphan scanner subprocesses when an RPC times out. The
trusted local CLI interface remains first|next|stop [--apply]; no DTMF digits,
mappings, wrappers or Asterisk commands are added/changed. The configured CLI
script path remains validated at startup, but the web broker now runs bundled
scanner logic rather than spawning custom scanner_script overrides. Custom
selector implementations need separate review before migration.

Both broker radio operations and trusted local CLI --apply requests reserve the
same web-control.lock and persistent web-last-command.json cooldown. The existing
15-second default starts again after completion, including failed attempts and
no-ops. A second request is rejected as busy/cooldown, not queued to execute later.
CLI --apply now also participates in that shared cooldown. The common scanner.lock
covers selection, state, query, disconnect, polling, connect and confirmation for
both manual and automatic actions. Local CLI dry runs take the nonblocking scanner
lock but never query Asterisk, submit commands or reserve the cooldown.

Each transition has an 18-second monotonic budget; each Asterisk process is limited
to the lesser of three seconds and the remaining budget. Status polls wait up to
0.5 seconds between observations, with no repeated disconnect/connect submissions.
The broker's existing default 30-second RPC timeout remains. Keep it longer than
the transition budget; a client timeout cannot prove what Asterisk ultimately did.
Malformed/failed status never becomes "no connections". Failure invalidates the
broker's display-link cache because old links may already have been disconnected.
No automatic reconnect, background retry or hook-based recovery is introduced.

Authentication, administrator authorization, CSRF, destination allowlists, Unix
socket peer-UID checks, role separation and local-only defaults remain. All radio
subprocess arguments are fixed argv with validated ASCII node IDs; there is no
shell interpolation. Existing ilink disconnect(1)/connect(3) CLI commands are used.
NetWatch, optional AllStar Nets, favorites management, activity/history/API polling,
and mobile wake-lock behavior are unchanged. Dashboard HTML/JavaScript and HTTP
handlers are checked separately against the prior source to protect those paths.

## Limits and acceptance

Application requests are serialized, including trusted local scanner callers.
Asterisk cannot atomically lock out incoming links, external CLI users or existing
operator scripts. An external connection seen during clear/preconnect aborts the
new request; a different link appearing after submission causes an error rather
than success. A connection can arrive after the last observation or a timeout.
Inspect reported links before retrying; STOP's pending selection helps handle late
application requests. These checks are not a permanent network-wide single-link
policy and must not replace a public-node policy.

Tests use mocked Asterisk responses and temporary files; they do not operate a
transmitter. On a separately approved spare acceptance system, retain physical RF
inhibition, use cooperating RF-inhibited destinations, and compare actual links
before/after each operation. Verify old links clear before new connect, failure
aborts, only-destination no-op, FIRST/NEXT ordering, STOP scope, 15-second cooldown
and overlapping-request rejection. Do not install hooks or change Asterisk config.
The old acceptance archives and metadata-only lifecycle candidate do not contain
this new behavior; a fresh reviewed package is required before hardware testing.

## Development validation

`python3 -B tools/check.py`: **287 tests passed in 58.725 seconds**, including
34 new transition/integration tests in tests/test_link_transitions.py. Python,
embedded JavaScript, shell and rendered systemd syntax checks passed. Local test
sockets were explicitly enabled; upstream, Asterisk, account and systemd mutations
are mocked. Real-driver integration covers broker/manual/FIRST/NEXT/STOP/Nets,
reported-state confirmation, disconnect failure/cooldown and overlapping broker
and CLI callers. Actual ARM64/Asterisk behavior remains unverified by this run.

Changed implementation files: radio_control.py (new), scanner.py, dashboard.py
(server-side radio functions only), control_service.py; tools/installer.py adds the
new module to the installed allowlist. The example TOML changes comments only,
with no new configuration requirement. Acceptance fixture expectations now reflect
application-owned transitions. Updated baseline tests explicitly authorize the
radio-policy changes while retaining other protected runtime hashes; the new
radio-policy-protected.json guard checks unchanged UI and HTTP/auth handlers.
Documentation in README, api.md, asterisk-integration.md, hardware acceptance and
historical release-readiness links points to this current behavior. No new archive,
installation, Asterisk config, mapping, hook, commit or publication was produced.
