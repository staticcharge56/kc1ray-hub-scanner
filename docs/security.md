# Security and authorization (Phase 3)

Phase 3 implemented security in the local development copy; Phase 4 adds
[explicit lifecycle packaging](installation.md) while preserving these policies. It does not
install services, create OS users/groups, configure Tailscale, modify Asterisk,
or authorize deployment. The packaging implementation chooses separate web, radio and monitor roles;
review those names/permissions before any target installation. Previous TOML files still parse, but web startup now
requires administrator credentials and a separate configured web identity.

## Architecture and privilege boundary

```text
Browser → built-in login/session/CSRF gate → Unix-socket RPC → existing radio driver
                     │                            │
              unprivileged web UID        separate non-root service UID
                                                  │
                                    favorites store / Asterisk / scanner CLI
```

The HTTP server reads activity/schedules and favorites. All browser radio and
favorites mutations pass the same administrator + CSRF authorization gate. Radio
requests then pass one command/destination policy in `control_service.py`.
The HTTP request path never calls Asterisk, the scanner subprocess, or the
favorites writer directly. There is no in-process privileged fallback.

`broker.py` wraps the existing Asterisk driver and scanner CLI. It exposes only
`links`, `control`, and `favorites` operations, not commands, paths, scripts, or
shell arguments supplied by a browser. UNIX SO_PEERCRED must identify the exact
configured web UID. The client verifies the server's exact service UID as well.
The socket uses mode 0660 and a configured private group. Membership alone does
not authorize a different UID. These Linux facilities are available on Debian 12.

The web process refuses root, its broker's UID, the Asterisk account, or Asterisk
group membership. The broker requires separate configured non-root identities,
and refuses paths that the web identity can replace or write: application modules,
configuration, Python/Asterisk executables, scanner script, socket directory,
existing state/cache/runtime files and their ancestors. Web-owned symlinks are rejected; administrator-owned symlinks (including the
normal Debian Python executable link) and their resolved targets/ancestors are checked. It does not automatically change ownership or permissions.

The broker still needs the existing local Asterisk access; it is not an Asterisk
sandbox. A compromised web process can invoke the allowlisted operations as its
service identity but does not receive arbitrary Asterisk CLI access or a shell.
All processes under the web UID are inside this trust boundary; use a dedicated,
non-login account. System administrators/root remain trusted.

The initial local wrapper still imports the existing driver helpers from
`dashboard.py`; importing the module does not start HTTP. A later code-only driver
extraction can improve module organization, but command sequences have not been
migrated. `scanner.py`, DTMF arguments, and the external single-link hook contract
remain unchanged. Link establishment is still asynchronous and unconfirmed by
the command path; a separately reviewed control migration is needed to change it.

## Administrator setup and passwords

There is one built-in administrator account and optional anonymous viewers.
There is no default password, web signup, forwarded-header login, or implicit
Tailscale administrator. Missing/invalid credentials prevent web startup.

Use an **explicit development path** for local credential setup:

```sh
python3 -B manage_admin.py --credentials /absolute/local/dev/credentials.json --username admin
```

The parent directory must already exist. Passwords are prompted twice with
`getpass`; they are not accepted as command-line arguments. Use a passphrase of
at least 15 characters (at most 1,024 UTF-8 bytes). Initial setup is no-clobber;
`--replace` explicitly resets a hash. After a reset, restart the web process to
invalidate its in-memory sessions and load the new credential file. Reset is not
complete until that restart; credentials are not watched dynamically.

Credentials contain a unique random 16-byte salt and a 32-byte scrypt digest,
using N=2^17, r=8, p=1. This matches an [OWASP recommended scrypt profile](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
Each verification uses roughly 128 MiB of scrypt workspace; only one hash is
allowed concurrently. Actual Raspberry Pi latency still needs measurement.
There is no additional Python dependency. Constant-time digest comparison is used;
unknown usernames still perform the password hash.

Files are created atomically with mode 0600. The web loader permits private
regular files with mode 0600/0640, refuses symlinks, group writes, execute bits,
world access, oversized files and unsupported hashing parameters. Packaging must
provision readable ownership for the web UID without making configuration or
privileged code writable. Never commit credentials, including hashes, to Git.

## Sessions, CSRF and logout

Session cookies contain random 256-bit opaque IDs. Only their SHA-256 digests
are stored in server memory. Cookies are host-only, Path=/, HttpOnly and
SameSite=Strict, with Secure on HTTPS. No ID is returned in JSON or browser
storage. Login rotates both the ID and independent CSRF token, invalidating the
pre-login cookie. Logout revokes the session and expires the cookie.

`GET /api/session` bootstraps an unprivileged session and returns its CSRF token.
This token is intentionally available to same-origin JavaScript; it is not the
HttpOnly session ID and cannot authorize actions by itself. Login, logout, user
activity refresh, radio controls, and favorites writes require a matching CSRF
header, and mutations require administrator authorization. An explicitly supplied
Origin must match the configured request origin; cross-site Fetch metadata and
duplicate security headers are rejected. Non-browser API clients may omit Origin
but must still supply the session cookie and correct CSRF token.

Idle expiry defaults to 30 minutes, with an absolute eight-hour lifetime. Both use
monotonic time in the running process. Sessions disappear on restart. Background
statistics polling does **not** refresh inactivity. The UI sends bounded explicit
activity touches after pointer/keyboard input; authenticated operations also touch
the session. Screen wake lock keeps its browser behavior but does not bypass idle
expiry. If anonymous viewing is off, expired viewers return to login.

Passwords, cookie values and session IDs are not logged or echoed in JSON. HTTP
access logging is disabled rather than recording raw request lines/query strings.
Errors are sanitized; scanner stderr and raw exception details are not returned.
CSP uses per-response script nonces; inline event attributes were replaced with
nonce-authorized event listeners. Framing, content sniffing, caching and referrer
leakage are restricted with response headers.

## Network and HTTPS proxy configuration

Default binding remains `127.0.0.1:8085`. The recommended installation workflow
explicitly selects an offered private physical LAN IPv4; localhost remains the
fallback. `web.allow_lan_http=false` is the default. An explicit installer LAN
selection enables it and the exact HTTP origin. This opt-in permits HTTP admin
access only at that numeric bind/port origin from RFC1918 clients. It does not
weaken login, CSRF, rate limits, session expiry, or broker restrictions.

**LAN HTTP does not encrypt credentials or sessions.** HttpOnly/SameSite remain,
but Secure is set only for HTTPS. Private addressing does not establish trust;
use HTTPS or localhost instead on shared/untrusted networks. Outside that narrow
opt-in, non-loopback administrator access requires HTTPS from an explicitly
trusted proxy. Changing Host alone never creates loopback access. See
[network access and troubleshooting](network-access.md).

For an optional provider-independent HTTPS proxy deployment, configure an exact origin
and only the actual proxy peer, for example:

```toml
[web]
bind = "127.0.0.1"
port = 8085
allow_lan_http = false
allowed_origins = ["https://scanner.example.org"]
trusted_proxies = ["127.0.0.1/32"]
anonymous_view = false
controls_enabled = false
```

This is illustrative configuration, not a deployment command. The proxy must
preserve the public Host and overwrite `X-Forwarded-Proto`; trusted HTTPS requests
then receive Secure cookies. If supplying `X-Forwarded-For`, it must be one valid,
overwritten address, not an untrusted chain. Ambiguous values are rejected. When
it is absent, rate limits conservatively group clients under the proxy's address.
A proxy listening from another address needs that exact address/CIDR configured.

Untrusted forwarded headers are ignored. `Forwarded`, X-Forwarded-Host,
X-Forwarded-User, and Tailscale identity headers never grant a role. Built-in
administrator login is required even if a proxy authenticates tailnet users.
Tailscale Serve supports HTTPS reverse proxying and identity headers; see its
[official documentation](https://tailscale.com/docs/features/tailscale-serve).
The application's trust decision is based on the explicit peer list, never the
mere presence of a header. Proxy configuration must strip client-supplied forwarding
values; use a single controlled hop. Do not trust a broad network unnecessarily.
Local processes capable of using a trusted loopback hop remain local trust peers.

The application does not terminate TLS or set HSTS itself; certificate, TLS and
HSTS policy belong to the HTTPS proxy. The root path is supported; URL-prefix
mounting is not implemented. No proxy configuration was installed or tested live.

## Read access, destinations and command safety

`anonymous_view=false` is the default. Unauthenticated visitors receive the login
page and cannot read activity, direct links, or favorites. Enabling it explicitly
exposes activity/favorite names and node IDs, schedules, and direct links read-only.
The favorites management endpoint remains administrator-only even for GET.
Every POST that changes favorites or radio state always requires admin + CSRF.

The separate `controls_enabled=false` maintenance switch disables radio/favorites
writes even for administrators; login/logout remain usable. There is no longer a
configuration that restores anonymous mutation behavior.

Authorized destinations are checked immediately before radio execution:

- Individual Connect/Disconnect: current authoritative favorites.
- Nets Connect: a current node in an enabled, fresh cached schedule.
- Nets Disconnect: current favorites, fresh schedule nodes, or the saved
  scanner-selected destination, retaining the ability to stop a prior selection.
- FIRST/NEXT: existing CLI selection from current favorites and fresh eligible
  observations. STOP: the saved selected node, after syntax/state validation.

Only ASCII numeric node IDs of the existing permitted lengths are accepted.
Self-connections, unknown actions/fields and non-string destinations are rejected.
An unrelated directly connected node is not automatically authorized for a
Nets disconnect. Invalid/corrupt saved selection/cooldown state fails closed.
The browser cannot supply executable paths or raw Asterisk commands.

The existing 15-second cooldown remains configurable. A shared file lock rejects
concurrent web commands; manual control also takes the scanner/DTMF lock without
waiting indefinitely. Scanner subprocess timeout remains 20 seconds; direct
Asterisk command timeout remains 15 seconds and status query timeout eight seconds.
No shell is used. Failed valid command attempts also consume the cooldown, closing
the former error-bypass path. A timeout does not prove that a requested asynchronous
link operation was undone; inspect reported link status before retrying.

Link status is cached in the broker for five seconds across viewers, including
failed attempts, to limit Asterisk subprocess creation. This can delay button-state
updates; control execution still reads direct link state itself. No added AllStarLink
or NetLogger requests are introduced by security.

## Limits and configuration

| Setting | Default |
| --- | --- |
| web.allow_lan_http | false; explicit LAN installation selection opts in |
| web.anonymous_view | false |
| web.allowed_origins | empty: only localhost/127.0.0.1 at configured port |
| web.trusted_proxies | empty |
| web.request_timeout_seconds / max_workers | 5 / 16 |
| auth.credentials_file | /etc/kc1ray-hub-scanner/credentials.json |
| auth.session_idle_seconds / session_max_seconds | 1800 / 28800 |
| auth.max_sessions | 128, including pre-login sessions |
| auth.login_attempts / login_global_attempts | 5 per client / 20 total |
| auth.login_window_seconds | 300 |
| auth.sensitive_attempts / sensitive_window_seconds | 30 per administrator / 60 |
| auth.read_attempts / read_window_seconds | 180 per client / 60 |
| broker.socket_path | /run/kc1ray-hub-scanner/control.sock |
| broker.web_uid / service_uid / socket_gid | -1 (unconfigured; startup fails closed) |
| broker.timeout_seconds / max_workers | 30 / 8 |

Session bootstrap is limited to twice the login-attempt allowance per client and
login window. Sensitive limits share an account bucket across sessions and radio/
favorites endpoints; cookie rotation does not reset them. Logout bypasses this
sensitive bucket so a busy admin can still sign out, while retaining general
request limits and CSRF. Denials carry Retry-After where appropriate. Limit tables
are bounded and do not evict live buckets to create bypasses. Rate counters are
in-memory; restarting the web process resets them and invalidates sessions.
HTTP bodies are limited to 4 KiB and must be JSON objects with unambiguous lengths,
no transfer encoding, and no duplicate JSON keys. Worker pools, socket timeouts,
RPC frames and response sizes are bounded. These controls do not guarantee
availability against a distributed denial-of-service attack.

## Packaging decisions requiring owner review

Before installation work, approve/select the dedicated web UID, non-root broker/
monitor identity with the existing required Asterisk access, private socket group,
and read-only data group. Directories should allow the service to create atomic
state/cache files while allowing the web UID only read/traverse; setgid directories
can preserve the read group on replacements. The web UID must not write source,
configuration, state, cache, or runtime directories/files. Socket group access is
needed only to connect, not to replace the socket directory entry.

Review the actual HTTPS origin/proxy address, whether anonymous favorites/activity
are appropriate, session limits, the tightened disconnect destination policy,
failed-attempt cooldown, and password-reset restart procedure. The new broker is
an undeployed local wrapper for review, not a change to production Asterisk flow.
There is deliberately no automatic legacy in-process fallback.

## Remaining risks and verification limits

Offline tests cover HTTP parsing over local Unix socket pairs, authentication,
sessions, CSRF, proxy spoofing, role/destination policy, concurrent commands,
timeouts and peer credentials. They do not constitute an independent security
audit, real TLS/proxy integration, ASL3 ARM64 acceptance, or a privilege-isolation
acceptance test under provisioned service accounts. Those checks remain required
in a disposable environment before release. No production services were accessed.

A compromised/root-owned local broker or Asterisk remains privileged; a compromised
web process retains its allowlisted IPC capabilities. Plain loopback HTTP is for
local use and remains cleartext. Secrets in memory cannot be protected against
OS-level compromise. Memory-only sessions/rate limits are not shared across multiple
web workers/processes; run one bounded threaded web process. Credentials reset
requires restart to revoke all sessions. Existing asynchronous radio commands and
single-link behavior remain unchanged pending separate control migration review.
