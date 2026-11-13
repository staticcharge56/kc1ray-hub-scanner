# KC1RAY Hub Scanner — 0.5.0-beta

An activity dashboard and favorites scanner for personal AllStarLink nodes on
ASL3 / Debian 12. Includes live favorites, activity history, scheduled nets and
authenticated FIRST, NEXT, STOP and direct connection controls.

Hardware acceptance of 0.4.4 passed on a spare Debian 12 ARM64 Raspberry Pi
running ASL3 Asterisk 22.10.1. Version **0.5.0-beta** is the first public-release
candidate; the later LAN-first changes passed 336 local tests and still have an
unreported installed-hardware acceptance gap. Other ASL3 versions and 32-bit
hardware are not covered by the reported acceptance. See the
[release review](docs/public-release-review.md) for remaining provenance concerns.

## Install for your personal node

Start with [the installation guide](docs/installation.md). The recommended workflow
is an **explicitly selected private LAN IPv4 address**, so your browser or phone can
reach the dashboard. The installer offers detected addresses but never selects one
for you. Enter keeps localhost-only access; unattended installs also default to
localhost. It never binds every interface automatically or changes your firewall,
router, Tailscale, or Asterisk configuration.

From a reviewed local source checkout on your Debian 12 ASL3 Pi:

```sh
sudo sh ./install.sh inspect
sudo sh ./install.sh install --node 1000 --port 8085 --bind 192.168.50.10
# After reviewing the plan:
sudo sh ./install.sh install --node 1000 --port 8085 --bind 192.168.50.10 --execute
```

Replace `1000` with your local node and `192.168.50.10` with a private LAN address
offered by `inspect`. Reserve the address in DHCP. The installer prompts for an
administrator passphrase; there is no default password. Then open
`http://192.168.50.10:8085` using your selected address and sign in.
For localhost-only access use `--bind 127.0.0.1` and browse locally or through an
SSH tunnel. Do not forward the HTTP port to the internet.

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
hooks, Tailscale or firewall settings. It detects missing prerequisites rather
than installing/upgrading ASL3 or running package downloads automatically. The reported hardware acceptance applies to Debian 12 ARM64 with ASL3 Asterisk 22.10.1.

## License

MIT, copyright (c) 2026 KC1RAY Hub Scanner contributors. The owner has approved
the [license and attribution](LICENSE). Original-code provenance is not
independently verified; see [the provenance review](docs/license-and-attribution.md).
