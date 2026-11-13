# Phase 5 release-readiness review

> Historical development report. Its test counts and open hardware gates describe
> that phase. See [the current public-release review](public-release-review.md)
> for 0.4.4 hardware acceptance, the 336-test LAN-first baseline and current blockers.

**Status: NOT ready for production or a public release.** Local validation passes,
but installed Debian 12 acceptance and real ASL3/ARM64 compatibility remain blocked.
No production Pi was contacted; no host accounts, Asterisk files, systemd services,
firewall/Tailscale settings, commits or releases were changed.

Current development subsequently implements [application-owned link transitions](link-transitions.md).
The original Phase 5 findings below are historical; new local tests do not close
the installed/hardware acceptance gates. No Asterisk hook or DTMF change is required.

## Changed files

| Files | Change |
| --- | --- |
| acceptance/Containerfile, acceptance/prepare.py | Disposable Debian image definition and allowlisted context generator |
| acceptance/installed.py, acceptance/mock_asterisk.py | Guarded installed-service smoke runner and non-radio Asterisk fixture |
| acceptance/README.md | Build/run instructions and explicit unexecuted limitations |
| tests/test_acceptance.py | Eleven additional local HTTP, backup-capacity and harness-safety tests |
| tools/installer.py | Shared snapshot free-space precheck for every lifecycle caller |
| tools/check.py | Include acceptance Python syntax |
| README.md, docs/validation.md | Link current release status and accurate test behavior |
| docs/current-behavior.md | Redact historical machine-specific home path |
| docs/installation.md, docs/release-readiness.md | Acceptance gate, retention proposal and complete findings |

## Evidence and results

Run `python3 -B tools/check.py` for the complete offline/local suite. Phase 5
adds `tests/test_acceptance.py`. Python syntax includes the acceptance scripts;
JavaScript syntax covers dashboard and login code. Shell syntax, rendered systemd
unit verification and recovery CLI bootstrap remain mandatory.

| Validation | Evidence | Result |
| --- | --- | --- |
| Existing regression coverage | All original 226 tests retained | Passed |
| New local integration and packaging tests | Real HTTP server on ephemeral loopback port; real scrypt credentials, actual request parsing, temp JSON files; no radio/external API calls | Passed; final count below |
| Authentication/session protection | Login/logout, private favorites read, idle expiry, CSRF rejection, login rate limit, untrusted forwarded headers and explicitly trusted HTTPS proxy cookie | Passed locally |
| Unix socket protocol | Existing real Unix socket-pair/peer credential tests | Passed; not evidence of installed cross-UID DAC |
| Backup space preflight | Added shared snapshot capacity check; low-space snapshot, rollback and uninstall preserve data/services in modeled target | Passed |
| Fresh install/node selection/accounts/upgrade/rollback/uninstall | Existing temporary-root FakeHost tests intercept every account/systemd/Asterisk command; real filesystem snapshots and checksums | Passed as modeled tests |
| History/favorites/API/schedules | Existing offline loop, restart, atomic write, live reload, stale/error/reset and 429 tests; parser fixtures | Passed as offline tests |
| Debian 12 installed lifecycle and actual separate UIDs | Prepared guarded systemd acceptance image and runner | BLOCKED: not executed here |
| Actual service startup ordering, sandbox permissions and separate-UID web/broker communication | Unit syntax and modeled ordering pass; installed assertions prepared | BLOCKED: needs booted disposable systemd target |
| Real ASL3, ARM64, Raspberry Pi performance and socket group compatibility | No nonproduction hardware available | BLOCKED |
| Browser/mobile wake lock and actual Tailscale Serve/HTTPS termination | JavaScript syntax/proxy protocol tests only | UNVERIFIED |

Final local run: **237 tests passed in 56.332 seconds, zero failures/errors**,
using `python3 -B tools/check.py` with approved local socket access. The initial restricted-sandbox run had 31 socket
permission errors, including existing tests; rerunning with approved local socket
access passed. Those sandbox errors are not counted as application failures.
Installed/hardware checks are not included in the passing count.

## Disposable acceptance environment

See [acceptance instructions](../acceptance/README.md). `acceptance/prepare.py`
creates an allowlisted, checksum-manifested build context in a new external
folder. It excludes private config/accounts, favorites/history/state, historical
source snapshots, `.git` and environment metadata. Existing destinations and
symlink sources are refused. A context was successfully generated locally.

`acceptance/Containerfile` specifies Debian 12, Python 3.11, systemd, CA roots and
development syntax tools. `acceptance/installed.py` refuses an ordinary host and
requires the image marker, detected virtualization, Debian 12, root, systemd PID 1
and empty managed/Asterisk destinations. These are accident guards, not isolation.
Run only inside the described disposable container/VM without host mounts/devices.
The Containerfile build itself has NOT been run here; the Debian tag/package
versions are not pinned and must be captured in the first successful report.

The runner installs a clearly fake `asl3-asterisk` package and synthetic node.
The mock only implements fixed version/status/ilink commands against local JSON;
it never invokes a real Asterisk binary or opens a radio device. Runtime external
networking is disabled. It starts actual installed web/broker/monitor units under
three identities, checks effective filesystem permissions, HTTP authentication,
CSRF, expiry, live favorites reload, imported NetWatch fixtures, history restart,
all seven controls and cooldown, upgrade/rollback/uninstall and retained identities.
Report assertions contain no passwords, hashes or session cookies.

The installed harness is unexecuted and may reveal additional defects. Its smoke
coverage is not complete: installed login throttling, trusted HTTPS deployment,
account-collision/partial-install/damaged-file injection and exhaustive service
restarts still need installed acceptance scenarios beyond existing offline tests.
A successful smoke run alone will not close those review items.

### Why it could not run on this host

The Mint host has no Docker, Podman, systemd-nspawn, debootstrap, QEMU or KVM device.
A namespace probe succeeded, but `/proc/self/uid_map` contained only `0 1000 1`;
`setuid(1001)` failed with EINVAL. Subordinate ID ranges exist, but `newuidmap` is
absent. This cannot faithfully test three service identities. No host package or
hypervisor installation was performed. A downloadable single-UID rootfs would not
resolve the permissions/systemd validation gap.

## Hardware and ASL3 assumptions

The [official ASL3 Debian guide](https://allstarlink.github.io/install/debian/install/)
includes Debian 12 Bookworm and the `asl3-asterisk` package. The installer deliberately
accepts only Debian 12, checks package/Python/architecture, Asterisk version and
active service, parses bounded `rpt.conf` includes/templates, and performs a read-only
selected-node query as the radio UID. Supported architecture names are a detection
policy, not proof that every architecture works.

| Assumption | Required nonproduction verification |
| --- | --- |
| `/usr/sbin/asterisk` (configurable binary), `/etc/asterisk/rpt.conf` | Verify actual package layout, includes and node discovery without changing configuration |
| `/run/asterisk/asterisk.ctl`, safe nonroot group with group write | Record actual ownership/mode; test radio UID access and web UID denial; custom socket paths currently unsupported |
| `rpt show variables NODE` contains `RPT_ALINKS` and expected suffixes | Capture sanitized real outputs for disconnected/connecting/failed/successful links; mocks cannot establish format compatibility |
| Broker requires/starts after Asterisk; web after broker; monitor after network-online; timers optional | Boot/reboot and stop/restart dependency tests with actual systemd, including RuntimeDirectory cleanup |
| No bundled architecture-specific extension | Execute on Debian 12 ARM64 Python/OpenSSL; validate real memory/latency/load and permissions |
| Existing single-link hook and DTMF integration | Review original hook/mappings separately; test safely on nonproduction ASL with RF disabled |

The [Pi 3B+ specification](https://www.raspberrypi.com/products/raspberry-pi-3-model-b-plus/)
lists a 1.4 GHz quad-core 64-bit processor and 1 GB RAM. That is hardware capacity,
not a measured application requirement. Scrypt N=131072,r=8 uses approximately
128 MiB for its main memory array; login hashing is serialized. One local x86
hash took 0.437 seconds with 149,324 KiB whole-process peak RSS. Neither timing nor
that process RSS predicts Pi latency or combined Asterisk/web/broker/monitor RAM.
Do not lower hashing strength without separate security review. Measure all services,
peak login load, swapping and radio latency on a spare Pi before recommending
minimum free RAM/CPU headroom. No verified minimum or capacity claim is made.

Default application write bounds are approximately 1,440 history checkpoints and
5,760 cache publications per day, plus startup/shutdown/favorites changes and
command state. These count logical publications, not journal/fsync/SD physical
writes. See [activity monitoring](activity-monitoring.md) for throttling and the
4*N-seconds-plus-network polling/freshness tradeoff. Disk must accommodate full
snapshots and staged code; no fixed SD-card size/endurance recommendation is
validated. Low-space prechecks cannot eliminate ENOSPC races, quotas or inode
exhaustion; failure recovery tests remain important.

## Security and publication audit

All runtime modules except the installer are unchanged in this phase; protected
hash tests still pass. Radio authorization/commands, dashboard features, favorites
management, NetWatch and monitor logic were not rewritten.

Review covered runtime sources, example config, installer, service templates and
public documentation. No embedded default password, session secret or private key
was found in the allowlisted installed payload. Added regression checks reject
private-key PEM headers and the original operator home path. These narrow checks
are not a comprehensive secret scanner or proof of absence. One historical home
path in `docs/current-behavior.md` was redacted. Public project/callsign branding and
external provider URLs remain intentional. Synthetic credential fixtures are test
values, never working operator accounts.

Eleven ignored historical/runtime copies remain locally; they must not be included
in a public source archive. The sanitized test context excludes them, but `.gitignore`
does not remove already tracked objects. This workspace has an empty `.git` placeholder,
so an actual Git index/history audit was unavailable. Audit the final proposed Git
index/archive and all history on the publishing checkout, including documentation,
fixture provenance and ownership. The test context is not a publication approval.

Remaining security/behavior risks:

- Effective installed DAC, systemd sandboxing and real peer UID checks must be
  exercised together; socket-pair and FakeHost tests cannot establish that boundary.
- Radio account necessarily has Asterisk socket access. Its server-side allowlist,
  immutable code/config and absence of web membership require deployed verification.
- Existing command flow reports requests and separately reads links; bounded,
  confirmed disconnect-before-connect and configurable single-link enforcement are
  still a separately reviewed control migration. No hook was supplied. Earlier
  acceptance requirements for those guarantees are **not satisfied** by mocks.
- Sessions/rate-limit counters are process-local and reset on web restart. Sessions
  are revoked by restart; persistent cross-restart attack throttling is not provided.
- Real trusted proxy configuration, origin restrictions, Secure cookies and direct
  access denial must be tested with the selected HTTPS proxy. Identity headers do
  not authenticate an administrator.

## Lifecycle retention proposal — approval requested for future implementation

Retain the current release plus **three previous successful releases**, each with
its corresponding complete pre-upgrade backup set (including config, favorites,
history, credentials and service metadata). Also retain the newest safety backup
and every backup referenced by a pending transaction/rollback, regardless of age.
Do not treat failed/staged attempts as successful retention slots. Never prune the
only recoverable backup, current symlink target, incomplete transaction evidence,
or operator-requested archival backups.

Proposed pruning should run only after readiness checks succeed, integrity and
reference checks pass and a dry-run retention report is reviewed. Prune a release
and its associated obsolete backup set together; root-only backup access must
remain. Current snapshots include all retained releases, so nesting/duplication
can substantially increase space needs. Review a snapshot-layout change before
claiming bounded storage with this policy. **No automatic pruning is implemented
or authorized by this proposal.** Existing retention is unbounded and disk use
must be monitored until a reviewed retention implementation exists.

Locked identities/group IDs remain after uninstall/purge to avoid UID reuse and
ownership confusion. There is no automatic identity deletion. Any later manual
cleanup requires separate approval after checking retained backups, all owned
files, callbacks and external references; do not blindly run userdel/groupdel.

## Required final review

1. Run and repair the disposable Debian 12 installed harness; retain image/package
   versions and per-assertion report. Extend it for installed negative/failure cases.
2. Test actual ASL3 ARM64 on spare hardware with RF disabled and sanitized outputs;
   establish memory/CPU/storage headroom and validate service lifecycle/proxy behavior.
3. Review the unresolved single-link/confirmed-transition requirements separately.
4. Approve retention design and final MIT licensing/source provenance; inspect actual
   proposed public Git contents/history. MIT and attribution are now owner-approved; original-code provenance remains
   independently unverified. See the current public-release review.
5. Re-run complete checks on the exact proposed release tree and review every
   remaining blocker before any production installation or publication.
