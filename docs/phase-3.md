# Phase 3 security implementation and review (historical handoff)

Phase 4 subsequently adds [local packaging](phase-4.md). Deployment limitations
below describe the Phase 3 handoff; production installation remains unperformed.

## Outcome and architecture

The web interface now has built-in administrator authentication, bounded opaque
sessions, CSRF protection, optional read-only anonymous viewing and explicit HTTPS
proxy trust. Every browser radio/favorites mutation uses one administrator guard.
A separate UID-restricted Unix-socket service applies a shared radio destination
policy and wraps the existing Asterisk/scanner flow. The web process receives no
Asterisk identity/group access and has no privileged execution fallback.

This is reviewable local implementation, not a deployment. OS identity/group/path
provisioning and production integration remain deliberately unperformed. Details
are in [security.md](security.md), [api.md](api.md) and the updated configuration
example. Nothing starts automatically or modifies systemd/Asterisk configuration.

## Changed files

| File | Change |
| --- | --- |
| security.py (new) | Fixed-profile scrypt credential creation/verification; private-file validation; opaque sessions/rotation/expiry; explicit host/proxy context; shared admin/CSRF policy and bounded rate limits |
| manage_admin.py (new) | Interactive hidden passphrase setup/reset, no password argument/default, atomic private credential file |
| control_service.py (new) | Shared action/destination validation; retained cooldown with failed-attempt charging; nonblocking command concurrency; existing scanner subprocess/driver calls; sanitized messages and cached link status |
| broker.py (new) | Bounded Unix-socket service and client; bidirectional peer-UID checks; allowlisted operations; identity and filesystem permission checks; no automatic stale-socket replacement |
| web_auth.py (new) | Sign-in page and session/CSRF-aware UI helpers, sign-out and explicit user activity touches |
| dashboard.py | Private/read-only/admin route policies; shared mutation guard and broker calls; bounded HTTP parsing/workers/timeouts; safe headers/nonced scripts; UI access state; legacy manual driver now validates actions and rejects scanner-lock contention promptly |
| configuration.py, config/config.example.toml | Auth/session/limit/proxy/broker settings and validation; default loopback, disabled anonymous access and disabled mutations retained |
| tools/check.py | Syntax-check both independently rendered application/login scripts |
| tests/test_security.py (new) | Password, session, proxy, HTTP authorization/CSRF, limits, validation and UI regression tests |
| tests/test_control_security.py (new) | Radio policy, command contract, cooldown, concurrent commands, bounded status reads, Unix peer identity and startup safety checks |
| tests/fixtures/phase-3-protected.json (new) | Hash baseline for unchanged scanner, monitoring/retry/history, favorites/migration and schedule modules |
| Existing configuration/phase-boundary tests | Recognize implemented anonymous-view option and authorized dashboard edits; preserve earlier behavior cases |
| README, documentation, .gitignore | Current usage/security/review guidance and local credential exclusion |

No third-party dependencies, account creation or system permission changes were
introduced. Hashing and peer credentials use Debian 12/Python 3.11 standard-library
facilities. The actual Raspberry Pi hashing latency still needs measurement.

## Validation

Final validation: `python3 -B tools/check.py` passed **183 tests**, including
the previous **120 cases** (with authorized Phase 3 schema/edit expectations) and
**63 new security cases**. All executable-code changes passed the complete suite. Python syntax checks include all 15 root modules and test/tool code;
application and login JavaScript are checked separately with Node.js.

HTTP tests exercise BaseHTTPRequestHandler parsing with synthetic messages over
local Unix socket pairs, with no listening TCP port or external network request.
This environment blocks even socket-pair traffic in its default sandbox, so these
offline tests were rerun with approved execution outside that restriction. Radio
subprocesses remain mocked. No production connection, service or Asterisk command
was invoked by the tests.

Coverage includes real scrypt verification and salts, no-clobber setup, credential
permissions; cookie flags/rotation/revocation/idle and absolute expiry; bootstrap
and login/account/request limits; CSRF on login and every mutation; private versus
anonymous viewing; untrusted/ambiguous proxy headers; Secure cookies behind a
configured HTTPS proxy; malformed HTTP/JSON and oversized bodies; every radio and
favorites action; unauthorized destinations; command cooldown and timeout/error
handling; real file-lock contention; Unix peer UIDs; worker bounds; and protected
runtime hashes. The startup path test models trusted Debian-style Python symlinks
and rejects a web-writable target without changing real system ownership.

## Decisions requiring review before packaging

- Select the dedicated non-login web account, separate non-root broker/monitor
  identity with required existing Asterisk access, private socket group and read
  group. Placeholder numeric IDs deliberately remain -1; actual startup fails
  closed until configured. Source/interpreter/config/data permissions must pass
  the checks described in security.md. No accounts/permissions were provisioned.
- Approve the privilege wrapper boundary. It changes transport/OS identity, not
  the Asterisk command sequence, DTMF CLI or single-link hook behavior. Legacy
  driver helpers remain in dashboard.py for this increment; a future extraction
  can improve layout without combining it with command-behavior migration.
- Choose actual HTTPS origin and exact proxy peer. Built-in login remains required;
  Tailscale/forwarded identity never grants admin. Review whether exposing favorite
  names, activity and direct links through optional anonymous viewing is appropriate.
- Review 30-minute idle / eight-hour maximum sessions, fixed scrypt work factor,
  5/client and 20/global login attempts per five minutes, and other bounded limits.
- Approve tightened Nets-disconnect destinations and failed-attempt cooldown.
  Existing scanner/radio command requests remain asynchronous and unconfirmed.
- Approve password-reset procedure: explicit reset followed by web restart, which
  loads the new hash and revokes all memory-only sessions.

## Remaining risks and limits

This is not an independent security audit or real ASL3 ARM64/TLS/proxy acceptance.
Service-account isolation has unit/model checks but needs disposable-host testing
under the actual provisioned users/groups. The broker retains required Asterisk
privileges; a compromised web UID retains its allowlisted IPC capabilities. Same-UID
local processes and root are trusted. Memory-only sessions and rate counters are
not coordinated across multiple web processes. Distributed availability attacks
are not eliminated by the bounded limits. Password reset requires web restart.
The existing asynchronous control and single-link behavior is unchanged, as
requested; confirmed transitions need their separately reviewed migration.

Installation packaging, deployment, production access, commits, pushes and
publication have not begun. Final MIT approval remains with the project owner.
