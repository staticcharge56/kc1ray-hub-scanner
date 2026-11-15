# KC1RAY Hub Scanner — 0.7.0-beta

An activity dashboard and favorites scanner for personal AllStarLink nodes on
ASL3 / Debian 12. Includes live favorites, activity history, scheduled nets and
authenticated FIRST, NEXT, STOP and direct connection controls.

Hardware acceptance of 0.4.4 passed on a spare Debian 12 ARM64 Raspberry Pi
running ASL3 Asterisk 22.10.1. Later beta increments require installed-hardware
acceptance; other ASL3 versions and 32-bit hardware remain unverified.
See the [release review](docs/public-release-review.md).

Version **0.7.0-beta** extends the administrator-only **Admin** tab with local
node selection, cooldown, backend monitoring settings, schedule frequency and
sanitized diagnostics. See [Advanced administration](docs/admin-advanced.md).
It retains Phase 1 dashboard
refresh, control availability, anonymous viewing, schedule-source timers,
password changes and read-only service status. It retains Apache `/hubscanner/`,
standalone LAN access, restricted firewalld management and node descriptions.
See [Admin operation](#admin-operation) and the [network guide](docs/network-access.md).

## Install for your personal node

Start with [the installation guide](docs/installation.md). **An existing compatible
Apache server is the preferred access method**, serving `/hubscanner/` beside
AllScan's `/allscan/`. The Python backend remains `127.0.0.1:8085`; the installer does not open port 8085. No virtual-host file or certificate is replaced.

Inspect first on your authorized Debian 12 ASL3 target:

```sh
sudo sh ./install.sh inspect
```

Choose a reported `apache_sites` ID, then preview, for example:

```sh
sudo sh ./install.sh install --node 1000 --web-access apache \
  --apache-vhost /etc/apache2/sites-enabled/000-default.conf:1 \
  --apache-origin http://192.168.50.10
```

Replace the node, exact reported virtual-host ID and browser origin. Add a second
`--apache-vhost` and `--apache-origin https://YOUR_HOST` to include an existing HTTPS
host; no certificate is generated. Multiple hosts require explicit selection.
Only after reviewing the plan, repeat the command with `--execute`. The installer
prompts for an administrator password of at least 8 characters. Then browse the
selected origin plus `/hubscanner/`. HTTP still leaves credentials and sessions
unencrypted; HTTPS is preferred when already available.

Standalone LAN access remains available:

```sh
sudo sh ./install.sh install --node 1000 --web-access standalone \
  --port 8085 --bind 192.168.50.10
```

Use an offered private LAN address and add `--execute` only after plan review.
Then browse `http://YOUR_LAN_IP:8085`. This mode retains subnet-restricted firewalld
management. Use `--bind 127.0.0.1` for localhost-only standalone access. The installer
never changes router forwarding, generates certificates, or alters Asterisk settings.
See [Apache selection, recovery and limitations](docs/network-access.md).

Controls and favorites changes initially remain in maintenance mode. After
checking sign-in, edit `/etc/kc1ray-hub-scanner/config.toml`, set
`controls_enabled = true` inside the existing `[web]` section, then restart:

```sh
sudo systemctl restart kc1ray-hub-scanner-broker.service kc1ray-hub-scanner-web.service
```

Use `--netwatch` on the initial install commands if desired; for an existing
installation follow the [schedule/timer instructions](docs/installation.md#3-optional-schedules-and-https).
The installer requires reviewed group access to Asterisk's control socket; see
[socket setup](docs/asterisk-socket-access.md) if inspection stops.

**Trusted-LAN HTTP does not encrypt credentials or sessions.** Use it only on a LAN
you trust. Administrator login, CSRF protection, session expiry and restricted
radio-control permissions still apply. HTTPS is optional and provider-independent;
use a configured trusted HTTPS reverse proxy when encryption is needed.
[Tailscale and 44Net Connect](docs/network-access.md) are optional remote networking
choices; neither is required to run the scanner. 44Net Connect provides WireGuard
connectivity and routable addresses, not HTTPS termination.

Node cards keep your custom favorite title and add the cached AllStarLink directory
description to the node-information line, for example:
`Node 29332 - Alaska AllStar Hub - Active`. Active/All, Nets and Favorites reuse
existing cached metadata; missing descriptions leave no empty field. NetWatch net
names and schedules remain separate. See [description caching](docs/activity-monitoring.md#node-directory-descriptions).

FIRST, NEXT and Connect use application-owned disconnect-before-connect and verified
Asterisk link states. No rpt.conf, DTMF, connection hook or single-link.sh changes
are needed. See [connection-state safety](docs/connection-state-safety.md).

## Development

Use Python 3.11+, systemd-analyze and Node.js for the JavaScript syntax check. There are no pip or
npm dependencies for the baseline checks. From this directory, run:

```sh
python3 tools/check.py
```

Checks parse the application modules, check the embedded JavaScript, validate
example data, run isolated regression tests, and exercise safe favorites migration.
Tests use temporary files, mocked radio/upstream requests, local Unix socket pairs,
and real HTTP servers on ephemeral loopback ports for authentication integration. In a sandbox that blocks socket pairs,
this test command requires approved local execution outside that restriction. They do not
install/start system services, invoke real radio commands, or contact a Raspberry Pi. Node.js is a
required development check tool, not a proposed application runtime dependency.

Use isolated development paths and a synthetic configuration for manual testing.
The scanner's CLI dry run still opens its configured lock file. Automated tests
block external calls and exercise the monitor loop with mocked observations.

## Project guide

- [Final public-file review and publishing commands](docs/public-release-review.md)
- [Historical Phase 5 release-readiness report](docs/release-readiness.md)
- [Disposable Debian acceptance harness](acceptance/README.md)
- [Spare Pi ARM64 pre-installation checks and approval gates](docs/arm64-hardware-acceptance.md)
- [Step-by-step installation and lifecycle operations](docs/installation.md)
- [Phase 4 changes, tests and remaining review](docs/phase-4.md)
- [ASL3 restricted Asterisk socket setup](docs/asterisk-socket-access.md)
- [Historical optional Asterisk integration guidance](docs/asterisk-integration.md)
- [LAN access, optional HTTPS and network troubleshooting](docs/network-access.md)
- [Security, administrator setup, proxy trust and review decisions](docs/security.md)
- [Phase 3 changes and validation](docs/phase-3.md)
- [HTTP API and session usage](docs/api.md)
- [Configuration, migration, and data preservation](docs/configuration.md)
- [Persistent activity and API reliability](docs/activity-monitoring.md)
- [Retry-scope improvement and validation](docs/retry-scopes.md)
- [Phase 2B changes and validation](docs/phase-2b.md)
- [Phase 2A changes and validation](docs/phase-2a.md)
- [Historical Phase 1 behavior and APIs](docs/current-behavior.md)
- [Approved requirements and phased plan](docs/development-plan.md)
- [Test coverage and deployment evidence needed](docs/validation.md)
- [Configuration example](config/config.example.toml)
- [Empty favorites example](config/favorites.example.json)

Current runtime source remains at the repository root. Historical `.backup`,
`.before-*`, and `.dry-run-backup` files are retained locally and ignored for future
Git additions, along with runtime state. Ignore rules do not remove tracked files
or sanitize Git history; a separate publication review is still required.

The installer never modifies Asterisk configuration, DTMF mappings, existing
hooks or Tailscale. Running firewalld receives a tracked LAN-subnet-only rule;
other firewall rules remain untouched. It detects missing prerequisites rather
than installing/upgrading ASL3 or running package downloads automatically. The reported hardware acceptance applies to Debian 12 ARM64 with ASL3 Asterisk 22.10.1.

## License

MIT, copyright (c) 2026 KC1RAY Hub Scanner contributors. The owner has approved
the [license and attribution](LICENSE). Original-code provenance is not
independently verified; see [the provenance review](docs/license-and-attribution.md).

## Admin operation

Sign in as the administrator, then choose **Admin**. Save applies the five
supported settings without restarting Asterisk or disconnecting current links;
Cancel restores the displayed values. Reload settings/status reads local state
without polling external services. Refresh changes affect dashboard refresh only,
not AllStarLink polling. Disabling controls requires confirmation and preserves
the existing maintenance behavior: favorites writes are also disabled.

Anonymous viewing exposes node/activity/schedule information to anyone who can
reach the dashboard; it grants no administration or mutation rights. Source
switches enable/start or stop/disable only the existing NetWatch and AllStar Nets
timers. Cached data is retained; the timer decides when the next import runs.

Password changes require the current password, two matching new entries of at
least eight characters, and reauthentication afterward. All previous sessions
are revoked. Use HTTPS to encrypt passwords and cookies; trusted-LAN HTTP is
unencrypted. Settings Save preserves other configuration values and file
ownership/permissions, but rewrites TOML formatting and comments. See
[configuration](docs/configuration.md), [security](docs/security.md) and
[recovery](docs/installation.md#admin-helper-recovery).
