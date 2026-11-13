# Connection-state confirmation correction

This local development correction preserves ASL3 metadata rather than confirming a
connection from the presence of a node number alone. No target installation or
Asterisk configuration is changed; no acceptance package has been prepared.

## Verified protocol semantics

Reviewed the official app_rpt
[RPT_ALINKS producer](https://github.com/AllStarLink/app_rpt/blob/master/apps/app_rpt/rpt_link.c#L551-L579)
and [lstats state formatter](https://github.com/AllStarLink/app_rpt/blob/master/apps/app_rpt/rpt_cli.c#L376-L391).
The producer selects C when thisconnected is false, otherwise T for transceive or
R for monitor. The CLI formatter uses the same thisconnected value to distinguish
CONNECTING from ESTABLISHED. K/U separately encode keyed/unkeyed, not connection
success. This is source inspection, not a query of either Raspberry Pi or proof of
every installed app_rpt revision. Existing owner-reported empty/TU observations
remain covered by exact regressions.

| State | Evidence used by this implementation |
| --- | --- |
| connecting | C with a recognized K/U suffix, or an application connect request awaiting its first observation |
| established | Target is the sole reported adjacent link with T or R and recognized K/U metadata |
| disconnecting | Application has requested removal and is still waiting for a valid snapshot without that link |
| disconnected | Target is absent in a complete, valid snapshot; empty RPT_ALINKS or numeric zero is valid |
| unknown | Missing/malformed/ambiguous status, unknown mode/keyed code, bare legacy IDs without metadata, deadline or request failure |

There is no native D/disconnecting suffix in the inspected producer. Disconnecting
is an application transition state, not something inferred from a fabricated D
code. T/R/C are all PRESENT and therefore must clear before a replacement. DU/FU,
L, lowercase and other unverified mode combinations remain unknown; they are never
silently upgraded into established or interpreted as removal. Malformed/count/
identifier/duplicate data still fails closed. Unknown state cannot authorize
confirmed connection success. Keyed K does not make a C link established, and
unkeyed U does not make a T/R link disconnected.

## Transition behavior

Connect/FIRST/NEXT/Nets use the same server-side controller and the same single
18-second monotonic budget, including disconnection and connection waits. Each
Asterisk process retains the <=3-second/remaining-budget bound. A response arriving
after the deadline cannot extend it.

- Already-only T/R returns without radio commands, with an observed established
  state. Already-only C issues no duplicate command and waits for establishment.
- A newly requested target waits through empty/connecting observations; only sole
  established T/R can succeed. Stuck C times out. C disappearing is a failed,
  disconnected connection, not success. Unknown metadata or unrelated links abort.
- Old links in T/R OR C remain present during disconnect. New connect cannot be
  submitted until a valid full snapshot confirms absence, followed by the existing
  pre-connect recheck. A disconnect failure, ambiguity or timeout aborts replacement.
- STOP and individual Disconnect likewise wait for actual absence. A C link is
  cancellable through the existing disconnect operation; no DTMF or hook change.

Before a control observation, a previous persisted confirmation is revoked rather
than reused as truth. A pending requested destination is stored with confirmed=false
before waiting/submission. Only an observed established target writes confirmed=true.
Failures keep an unconfirmed pending target so STOP can handle a late arrival.
Existing legacy node-only selection files remain readable. No automatic retry or
reconnect is added. External Asterisk callers/incoming links still cannot be
atomically prevented by application locks; inspect fresh state after any error.

The 15-second completion-based cooldown, shared CLI/broker locks, authorization,
CSRF, destination policy, protected Unix socket and privilege separation remain.
Actual commands remain fixed argv using the existing ilink1/3 flow; no rpt.conf,
DTMF, connpgm/discpgm or single-link.sh modification is involved.

## Structured status and dashboard compatibility

parse_links and the internal Asterisk/driver status path now retain records:

```json
{"node":"1001","mode":"C","keyed":false,"state":"connecting","suffix":"CU"}
```

The HTTP API preserves its node-ID array and adds metadata, for example:

```json
{"links":["1001"],"link_states":[{"node":"1001","mode":"C","keyed":false,"state":"connecting","suffix":"CU"}]}
```

The ID array denotes PRESENT adjacency, not establishment. Empty status returns
both arrays empty. The new dashboard shows state labels and Cancel connection for
C instead of presenting it as established. Disconnecting/removal progress is
shown separately while the application request is pending; the observed link may
still be T/R until it disappears. Unknown metadata is displayed as unverified,
and server controls fail closed. Old consumers of links still receive strings.
Code importing parse_links/direct_links internally must handle records rather than
assuming strings; bare IDs cannot be used to confirm a connection.

The five-second display cache is unchanged; transitions always query fresh status.
No peer addresses, raw CLI output, passwords or configuration contents are exposed.
The HTTP/auth handlers are separately hash-checked against the prior release; the
UI guard now permits only the explicitly requested structured-state display work.

## Validation scope

Regression scenarios include C→T, keyed/unkeyed T/R/C, already-only C, stuck C,
failed commands, C disappearing, malformed/unknown states, old links that remain C
after disconnect, STOP cancellation, late responses and a shared disconnect/connect
deadline. Wire tests exercise the exact client/parser path that previously marked
CU confirmed. API tests preserve IDs while returning connecting metadata; the new
UI label helper is executed with Node.js. Existing authentication, cooldown,
concurrency, favorites, monitoring, lifecycle and syntax checks remain required.
All Asterisk operations are mocked. Neither Pi was contacted. Real revised-path
hardware acceptance remains a later separately approved step; no new package here.

## Local validation result

`python3 -B tools/check.py`: **324 tests passed in 62.205 seconds**, zero failures
or errors, with local test sockets enabled. This adds30 regression tests to the
previous294-test suite, including the actual-client CU false-confirmation
reproduction. Python, JavaScript, shell and systemd checks passed. The 29 dedicated
connection-state tests also passed separately. No hardware or deployment test is
claimed for the revised implementation.

Implementation changes: radio_control.py preserves and validates records and
waits for establishment; control_service.py returns additive metadata; dashboard.py
renders structured states. Existing tests/fixtures were adapted for explicit
metadata and false pending confirmations; tests/test_connection_states.py adds
state/deadline/API/UI coverage. The prior UI+HTTP protection fixture is retained
as history, with a separate prior-release HTTP/auth hash guarding unchanged
handlers while allowing the requested display update. No broker permission,
authentication implementation, session logic, configuration default, service unit,
Asterisk integration file or release metadata was changed.
