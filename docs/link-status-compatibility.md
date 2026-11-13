# ASL3 empty link-status correction — corrected acceptance candidate

The later [connection-state safety correction](connection-state-safety.md) now
preserves structured mode/keyed metadata and waits for established T/R. The initial
empty-parser work and validation record below are historical.

The owner reported that Debian 12 ARM64 / ASL3 Asterisk22.10.1 emits a literal
`RPT_ALINKS=` field with no value when no nodes are connected. The previous parser
rejected it, so authenticated GET /api/links returned503 despite a healthy node.

The corrected parser accepts exactly one well-formed empty field as an empty list.
LF, CRLF, a final field without a newline and existing space/tab indentation are
supported. The existing `RPT_ALINKS=0` representation remains supported. A missing
field is never treated as empty. Candidates are counted before value parsing so
an empty field plus a malformed/duplicate field cannot hide existing links.
Whitespace-only values, missing equals signs, malformed duplicates, bare commas,
embedded controls and invalid nonempty values remain errors.

Nonempty validation is unchanged: bounded numeric count matching every entry,
3–7 ASCII-digit node IDs, two-letter suffix shape, unique node IDs and the existing
count/response-size limits. Unknown records are not dropped, counts are not guessed,
nonempty node lists without counts are not accepted, and partial status is not
reinterpreted as no links. No destination or mode conversion heuristic is added.

## Connected-format review

Reviewed the official upstream
[rpt_link.c producer](https://github.com/AllStarLink/app_rpt/blob/master/apps/app_rpt/rpt_link.c#L516-L675)
and [rpt_update_links emitter](https://github.com/AllStarLink/app_rpt/blob/master/apps/app_rpt/rpt_link.c#L699-L738).
The producer forms adjacent-link entries from node name, link mode and keyed state;
the emitter prefixes the count only when links exist. This supports the empty-field
correction and existing populated shape. Synthetic regression entries cover
transceive, receive and connecting mode letters with keyed/unkeyed suffixes.
They are not hardware captures and suffixes are not a new authorization mechanism.

This was an upstream master-source review, not verification of the spare's exact
installed app_rpt revision. Asterisk22.10.1 alone does not establish that revision.
The owner subsequently supplied the exact populated field
`RPT_ALINKS=1,638901TU` and confirmed ESTABLISHED using `rpt lstats LOCAL_NODE`,
followed by a successful disconnect. Regression tests now cover that exact field
and the exact empty `RPT_ALINKS=` response, including LF/CRLF variants. This is
owner-reported hardware evidence, not a live query performed by development. No support for other link
protocols, nonnumeric identifiers or undocumented formats is inferred from the
empty-field report. The parser's existing two-letter suffix validation is retained;
the initial empty-field correction did not add mode-based interpretation; the
subsequent safety correction does so without changing empty/count/ID validation.

## Regression coverage and scope

Tests cover a literal empty field with LF/CRLF/no terminal newline, a populated
list, missing/duplicate/malformed status, duplicate and invalid node IDs, incorrect
counts and partial records. An authenticated HTTP handler -> broker router -> real
parser test verifies empty status returns200 with `{"links":[]}`; a malformed
duplicate returns503. Only the Asterisk response is mocked along that status path.

The broker/manual/FIRST/NEXT/STOP/Nets integration fixture and disposable mock now
emit the reported empty representation. Existing transition tests therefore
exercise clearing old links and connecting from that state, rather than relying
only on a synthetic numeric zero. Locks, 15-second cooldown, authentication,
CSRF, timeouts and application-owned disconnect-before-connect are unchanged.
No Asterisk configuration, DTMF mapping, hook or single-link.sh change is involved.
Neither Pi was contacted. The initial correction was prepared without an archive;
the owner has now requested a corrected acceptance package newer than0.4.2.
Release metadata is updated for that package; application transition behavior
remains unchanged.

## Initial correction validation (historical)

`python3 -B tools/check.py`: **293 tests passed in 63.174 seconds** with local test
sockets enabled. Python, embedded JavaScript, shell and systemd syntax checks
passed. The targeted link suite passed40 tests, including six additional parser/
HTTP regression methods. Comparing runtime files against the prior0.4.2 archive
confirmed that only parse_links changed; the rest of the transition engine and
all scanner/broker/security modules are unchanged. No archive was prepared.
