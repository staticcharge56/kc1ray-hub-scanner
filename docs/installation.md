# Installation, upgrade, rollback and removal

Version 0.6.0-beta is prepared for first public release. These
commands are instructions for a **separately authorized Debian 12 ASL3 target or
disposable acceptance environment**. They have not been run on the production Pi
or used to install services on the Linux Mint development host.

## Requirements and assumptions

- Debian **12**, with an installed `asl3-asterisk` package and an already-running
  `asterisk.service`. The installer does not install/upgrade ASL3, DAHDI or Asterisk.
  Follow the [official ASL3 Debian instructions](https://allstarlink.github.io/install/debian/install/)
  for the underlying system. Mint/Ubuntu/other Debian versions are intentionally rejected.
- Detected architectures: arm64, amd64, armhf. The application contains no bundled
  architecture-specific binaries. 0.4.4 hardware acceptance passed on Debian 12 ARM64 / ASL3 Asterisk 22.10.1; 32-bit hardware remains unverified.
- Python 3.11+ with tomllib, OpenSSL scrypt, SSL and a usable system CA bundle;
  systemd/systemd-analyze, shadow account tools (`groupadd`, `useradd`, `passwd`,
  `nologin`), runuser and dpkg tools. Missing prerequisites stop the operation;
  no package manager, download, pip or npm command is run automatically.
- A standard `/run/asterisk/asterisk.ctl` socket with write permission for an
  appropriate non-root group. Only the radio account is added to that existing
  group. Root/sudo/adm/disk/shadow/docker/lxd groups are refused. A custom socket
  location or unsuitable existing permissions needs explicit manual ASL review;
  the installer never changes Asterisk socket/configuration ownership or modes.
- Standard managed paths listed below, root-owned code/interpreter/Asterisk binary,
  and sufficient free disk for a full backup plus staging. Unmanaged files and
  reserved-name account/group collisions are refused, not silently adopted.

Use a trusted local checkout/archive. The installer does not fetch code or provide
a release-signature distribution system. File hashes detect changes/corruption,
not publisher authenticity. The owner has approved MIT; see
[license and provenance](license-and-attribution.md).

For LAN installations with running firewalld, review the subnet/zone rules in the
dry run. The installer updates only its tracked rich rules, without a global
reload. See [network access](network-access.md) for ownership, rollback, uninstall
and inactive-firewalld behavior.

## ASL3 owner-access socket compatibility

An `asterisk:asterisk` control socket at mode0755 is a recognized ASL3 layout,
but lacks group write for a dedicated radio UID. Inspection stops with targeted
operator guidance; it never changes Asterisk. See [restricted socket setup and
effective identity checks](asterisk-socket-access.md). Mode0660 is recommended,
world-accessible sockets are refused, and a real radio-UID connection plus read-only
node query must succeed before candidate activation. Directory `asterisk:root`
mode0755 can remain unchanged.

## 1. Inspect and review a plan

A compatible existing Apache is the preferred method. Inspect `apache_sites`, then
select `--web-access apache`, explicit `--apache-vhost` IDs and exact origins as
shown in [Apache instructions](network-access.md#preferred-existing-apache-at-hubscanner).
The example below is the standalone alternative; add `--web-access standalone`
when Apache is available and you want the direct-port workflow. Existing upgrades
retain their method unless explicitly changed.


On the intended disposable/authorized target, from the reviewed source directory:

```sh
sudo sh ./install.sh inspect
sudo sh ./install.sh install --node 1000 --web-access standalone --port 8085 --bind 192.168.50.10
```

Replace synthetic node `1000` with your node, and `192.168.50.10` with an address
actually offered by `inspect` under `lan_candidates`. The addresses are suggestions,
not automatic selections. Only up physical interfaces with RFC1918 IPv4 addresses
are offered; VPN, container, 44Net, CGNAT and public addresses are excluded. Multiple
interfaces are listed for operator review rather than guessing a preferred route.
If discovery is unavailable or returns no suitable address, use `--bind 127.0.0.1`
or omit it for the secure localhost fallback. No new dependency is required;
optional discovery uses the existing `ip` utility from iproute2. Omitting **--execute** performs
read-only inspection/planning: no accounts, directories, units or services are
changed. Root is useful for reading ASL configuration/socket metadata, but planning
has no write step. `--help` works without an installed application, including when
an existing TOML is damaged.

Inspection reports OS, architecture, Python, Asterisk/package version, control
socket group and numeric node sections. Includes are read recursively within
`/etc/asterisk`, with limits and loop detection. Numeric templates marked `!` are
excluded. `#exec` is reported but never evaluated. With dynamically generated
nodes, explicitly choose a node; the later read-only Asterisk query must confirm
that node before any application service starts. External/symlinked includes and
nonstandard layouts require review rather than guessed discovery.

Review the detected node, port, fixed paths and identity policy. Fresh ports must
be unprivileged (1024–65535) and free. UID/GID values are allocated from the host's
system account ranges and stored in the generated configuration; none are guessed.

## 2. Install with secure administrator setup

Only after separate authorization to change that target:

```sh
sudo sh ./install.sh install --node 1000 --web-access standalone --port 8085 --bind 192.168.50.10 --execute
```

Review the dry-run plan before repeating it with --execute. Selecting a LAN bind
explicitly opts into unencrypted trusted-LAN HTTP and sets its exact allowed origin.
Reserve that address in DHCP. Never forward this HTTP port from the internet.
A missing node or port is prompted on an interactive terminal. An interactive fresh
install without --bind offers LAN choices and defaults to localhost on Enter.
Noninteractive omission retains localhost; no LAN address is chosen automatically. The default port
prompt offers 8085. The passphrase is prompted twice, hidden, with at least 8
characters. There is no default password, plaintext password argument or password
environment variable. Noninteractive installation requires an existing private
scrypt file created using `manage_admin.py` and the `--admin-credentials` option.
That option accepts a hash file, never a plaintext password. `--admin-name NAME`
selects the username for newly prompted credentials; imported credentials keep
their existing username/hash.

The installer validates prerequisites, snapshots the prior managed state, creates
accounts/directories, stages allowlisted source, validates configuration/data,
checks radio-account access using **only** `rpt show variables`, verifies units,
atomically switches the release pointer, enables/starts application services and
checks readiness. It never submits connect/disconnect commands during install.
Failure triggers restoration of the prior files and service states. Allocated
non-login identities remain registered so retrying does not recycle UIDs.

Without a compatible Apache or an explicit standalone LAN selection, the
installation binds to `127.0.0.1`. With compatible Apache, fresh execution requires
a method choice; Apache mode always uses 127.0.0.1:8085. Fresh installations without configuration imports disable anonymous viewing and keep
`controls_enabled=false`. Sign-in works, but radio/favorites writes remain in
maintenance mode until the owner reviews configuration and explicitly changes
that setting. All writes still require admin + CSRF after enabling it. The
30-minute idle/eight-hour maximum session defaults remain configurable.

## Managed layout and identities

| Purpose | Location / identity |
| --- | --- |
| Versioned program and atomic current link | /opt/kc1ray-hub-scanner/releases/ and /opt/kc1ray-hub-scanner/current |
| Config and private administrator hash | /etc/kc1ray-hub-scanner/ |
| Favorites, scanner selection, cooldown | /var/lib/kc1ray-hub-scanner/, owned by kc1ray-radio |
| Persistent monitor history | /var/lib/kc1ray-hub-scanner-monitor/, owned by kc1ray-monitor |
| Activity and schedule caches | /var/cache/kc1ray-hub-scanner/, owned by kc1ray-monitor |
| Socket and command locks | /run/kc1ray-hub-scanner/, owned by kc1ray-radio |
| Root-only manifests/backups/journal | /var/lib/kc1ray-hub-scanner-package/ |
| Lifecycle command | /usr/local/sbin/kc1ray-hub-scanner |
| Units and tmpfiles definition | /etc/systemd/system/kc1ray-hub-scanner-* and /etc/tmpfiles.d/kc1ray-hub-scanner.conf |

Three locked, non-login accounts use `/nonexistent` homes. `kc1ray-web` has its
private primary group plus `kc1ray-read` and `kc1ray-control`; it has no Asterisk
membership. `kc1ray-monitor` has only `kc1ray-read`. `kc1ray-radio` has that read
group plus socket/control and the existing Asterisk socket group. Only radio
executes existing Asterisk/CLI controls. Normal runtime code/config are root-owned.

Data/cache directories use mode 2750 with the read group, ensuring atomic
replacements retain read access while the web group has no directory write.
The monitor's separate `paths.monitor_state_dir` is the only runtime-path addition;
manual layouts omitting it retain their old `state_dir` behavior. Credentials use
root:kc1ray-web mode 0640; TOML uses root:kc1ray-read 0640. Root metadata/backups
are private. The socket is radio-owned, `kc1ray-control`, mode 0660, and both sides
also verify the configured UID.

Broker runtime ownership and cleanup are managed by its RuntimeDirectory, with a
matching tmpfiles definition for boot. Its readiness check waits for exact socket
identity/mode before web startup; web readiness uses a non-mutating login probe.
A 403 is expected for a proxy-only origin policy. systemd directory behavior is
documented in [systemd.exec](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html).
All units use a read-only system view, no new privileges, bounded stops and
role-specific write paths. No privileged web fallback is installed.

## 3. Optional schedules and HTTPS

For LAN/HTTPS settings, optional remote access and connection troubleshooting, see
[network access](network-access.md). HTTP cookies retain HttpOnly/SameSite and all
session checks, but cannot carry Secure on plain HTTP. HTTPS sessions use Secure.
Keep controls disabled until authentication and the selected origin have been tested.
To enable application controls and favorites management, set
`controls_enabled = true` inside the existing `[web]` TOML section, then restart both
`kc1ray-hub-scanner-broker.service` and `kc1ray-hub-scanner-web.service`.
Do not enable anonymous viewing to resolve a sign-in problem.

Enable sources explicitly during initial installation:

```sh
sudo sh ./install.sh install --node 1000 --web-access standalone --port 8085 --bind 192.168.50.10 --netwatch --allstarnets --execute
```

This is an initial-install variant of the reviewed plan, not a second installation
command for an installed system. Replace the node/address and preview without
--execute first. Use only the desired source flags. Disabled sources' timers remain disabled. NetWatch
refreshes every 30 minutes with a small randomized delay; AllStar Nets refreshes
daily around 03:00 UTC with a randomized delay. Neither adds NetLogger polling.
Existing monitor API backoff remains separate from timers.

For a later change, edit the source's `enabled` value in the TOML, restart the web
interface to reload source policy, and explicitly enable/start its timer, e.g.:

```sh
sudo systemctl enable --now kc1ray-hub-scanner-netwatch.timer
```

Disable a timer as well as its TOML flag when turning a source off. Upgrades
preserve existing enabled/running unit states, not newly inferred operator intent.
Use `systemctl edit` drop-ins for timer cadence changes; do not edit generated
base units. Drop-ins are retained unless a confirmed purge removes them.

The installer never changes Tailscale, Funnel, alternative firewalls, router port forwarding,
TLS certificates or internet exposure. Follow [security.md](security.md) to choose
an exact HTTPS origin and trusted proxy address. A proxy must preserve Host and
safely set the accepted protocol/client headers. Built-in admin login remains
required. No proxy is configured automatically.

## 4. Migrate an existing manually installed copy

Do this only in an authorized maintenance environment, with original files backed
up separately. Stop the **old Hub Scanner** processes/jobs and quiesce external
DTMF/script callers; do not stop or rewrite Asterisk. A running old dashboard on
the chosen port will make preflight fail. The installer will not stop unknown old
units or search home/AllScan directories on its own.

Use explicit local source copies, for example:

```sh
sudo sh ./install.sh install --node 1000 --port 8085 \
  --config-import /absolute/private/copy/config.toml \
  --favorites-source /absolute/private/copy/favorites.json \
  --history-source /absolute/private/copy/monitor-history.json \
  --admin-credentials /absolute/private/copy/credentials.json
```

First review without --execute, then repeat with it after separate authorization.
Every import option is optional; omit sources you do not have. A fresh passphrase
is prompted if no credential file is provided. For INI favorites, paired labels
and commands are validated through the strict migration parser; duplicates and
unsupported entries cause failure rather than loss. JSON descriptions/order are
preserved exactly. Original sources are never modified; keep those copies until
acceptance is complete. Imported history must be a supported version-1 JSON
snapshot and fit the monitor's 2 MiB bound. Timestamp freshness is still enforced
by the monitor, so importing history cannot revive stale activity.

Imported TOML settings are retained except explicitly remapped managed data/code
paths, identities/socket, credential path, and the selected node/port. Those remaps
are shown in the plan. Custom origins, anonymous-view choice, intervals, cooldown,
schedule URLs and session limits remain operator choices, not new defaults.
Sources already enabled in imported TOML stay enabled; source flags can explicitly
enable an additional integration. If a destination already exists without a
managed registry, installation refuses rather than overwriting/adopting it.

## 5. Upgrade safely

Use the **new reviewed source's installer**, so it knows its own schemas/migrations:

```sh
sudo sh /absolute/new-checkout/install.sh upgrade
sudo sh /absolute/new-checkout/install.sh upgrade --execute
```

Initial-install choices/import flags cannot be used to reset upgrade settings.
Upgrades retain TOML bytes/comments, credential hashes/usernames, favorites,
history and numeric service identities. Root-edited program/base unit files or
unsafe credential/config permissions stop preflight; use reviewed source changes
and unit drop-ins instead of silently overwriting modifications.

The application units are stopped (timers first, then web/monitor/updaters/broker)
so history flushes and snapshots are consistent. Asterisk is not stopped, restarted
or rewritten. External DTMF/cron/script writers must be quiesced separately because
the broker's runtime directory and lock files are recreated on restart. A snapshot
contains program releases, configuration/credentials, state/history/caches, owned
unit files/launcher/tmpfiles and previous enable/active state. It has per-file
hashes and recorded ownership/modes, with durable bytes/directories before its
complete marker. A durable root transaction journal supports interrupted-operation
recovery. Do not manually remove it to bypass a failed transaction.

Current data formats need no destructive conversion. Compatible unversioned
configuration metadata (schema 0) is promoted to schema 1 after validation without
rewriting TOML bytes. Unsupported future schemas fail closed until a reviewed
migration exists. Explicit initial JSON/INI imports handle the older favorites
layout. Corrupt existing history is backed up and retained for the monitor's
cold-baseline behavior; an unknown future history version blocks upgrade.

A failed switch/startup restores the previous files, release pointer and service
states automatically. Successful upgrades preserve previously disabled/stopped
units too. An unchanged release with no pending migration is a no-op. Backup IDs
use UTC plus a random suffix and are printed in the result. Backups and historical
releases are not automatically pruned; monitor free space on SD cards and archive
reviewed old backups separately. The installer refuses insufficient backup space.

## 6. Roll back or recover an interrupted operation

List backup directories as root, identify a complete snapshot, then use a trusted
source checkout (the installed command may be unavailable after removal):

```sh
sudo sh /absolute/trusted-checkout/install.sh rollback --backup BACKUP_ID
sudo sh /absolute/trusted-checkout/install.sh rollback --backup BACKUP_ID --execute
```

The first command validates the backup without changing it. Rollback validates
hashes and fixed-path boundaries, stops application units, takes a safety snapshot
of current data, and restores the selected full snapshot and unit states. This
restores **data as of that snapshot**, not just code; later favorite/history changes
remain in the safety backup. Sessions are lost when the web process restarts.

Recovery starts even with a damaged target TOML because the CLI imports its
validators under the shipped safe example, then reads target settings explicitly.
A pending transaction blocks new operations until explicit rollback; a pending
purge is separately resumable with the purge confirmation. If both the operation
and automatic restoration fail (e.g. failing storage), keep the journal/backups,
repair the filesystem/space issue, and retry explicit recovery. Complete snapshots
are required; incomplete snapshot directories are never accepted as restore input.
Very narrow crashes between account-tool completion and registry recording can
require manual reserved-account reconciliation; the tool never guesses ownership
or deletes/recycles an unknown UID.

## 7. Administrator reset and normal operations

For an authorized password reset, stop web first, prompt for a new private hash,
restore its restricted readable group, then start web:

```sh
sudo systemctl stop kc1ray-hub-scanner-web.service
sudo /usr/bin/python3 -B -E -s /opt/kc1ray-hub-scanner/current/manage_admin.py \
  --credentials /etc/kc1ray-hub-scanner/credentials.json --username admin --replace
sudo chown root:kc1ray-web /etc/kc1ray-hub-scanner/credentials.json
sudo chmod 0640 /etc/kc1ray-hub-scanner/credentials.json
sudo systemctl start kc1ray-hub-scanner-web.service
```

Choose the retained operator username deliberately; the example `admin` is not a
password. A passphrase mismatch/failure leaves the previous hash intact; do not
start web until file permissions and the intended hash are correct. Restarting
revokes sessions. Do not change groups/UIDs in TOML without updating actual managed
identities and reviewing the security boundary.

Use `systemctl status kc1ray-hub-scanner-web.service` and
`journalctl -u kc1ray-hub-scanner-monitor.service` for diagnosis. Keep logs, private
hashes and backup snapshots out of public issues. If no nodes appear, check favorites,
source API backoff, age and polling-cycle guidance in [activity-monitoring.md](activity-monitoring.md).
A socket readiness failure calls for checking identities, socket group, runtime
permissions and the broker journal, not relaxing web privileges. Editing TOML
requires restarting the affected app units; favorites changes are live.

## 8. Uninstall or explicitly purge

Preview, then remove owned units/program/launcher/runtime while retaining data:

```sh
sudo sh /absolute/trusted-checkout/install.sh uninstall
sudo sh /absolute/trusted-checkout/install.sh uninstall --execute
```

Configuration, administrator hash, favorites, monitor history, caches, backups,
unit drop-ins and non-login service identities remain. Reinstallation reuses the
registered identities and retained data. Asterisk services/configs, existing hooks,
Tailscale and unrelated firewall settings are untouched; tracked scanner rich rules
are removed. See [firewalld lifecycle](network-access.md#installer-managed-firewalld-rules-051-beta).

Only an explicitly confirmed purge deletes managed config/data/caches/drop-ins and
backups as well:

```sh
sudo sh /absolute/trusted-checkout/install.sh uninstall --purge --execute
```

The terminal requires the exact phrase `PURGE KC1RAY HUB SCANNER`. Automation can
supply that same phrase using --confirm-purge; there is no generic --yes shortcut.
Purge is irreversible once backups are deleted. If interrupted, the purge marker
allows a confirmed rerun to resume deletion without starting services or pretending
that deleted backups can be restored. Backups still present can instead support an
explicit rollback. Fixed-prefix boundaries prevent deleting arbitrary external
paths from config or backup metadata.

Even purge retains locked service accounts/groups and the root-only identity
registry to prevent accidental UID reuse on reinstall. It also leaves journalctl
history to the host's journal retention policy. Account removal is a separate
administrator review, not an automatic data-deletion side effect.

## Acceptance still required before publication

Unit syntax is checked with systemd-analyze and all account/service operations are
modeled in automated tests. The 0.4.4 spare-Pi acceptance covered installation, services, authentication,
favorites, monitoring, schedules, radio controls and lifecycle recovery. Optional
HTTPS/proxy deployments, other architectures and SD-card endurance need their own
validation. The LAN-first installer changes have 336 passing local regression tests; installed
acceptance of that new workflow has not yet been reported. Run the full lifecycle in a disposable
Debian 12 ASL3 environment under the actual identities before any production
installation or public release. No such deployment is authorized by this document.

## Phase 5 acceptance gate and retention proposal

The owner reports successful 0.4.4 spare-Pi hardware acceptance on Debian 12 ARM64
with ASL3 Asterisk 22.10.1. The new LAN selection and transport opt-in still require
installed hardware acceptance before publication. Review the
[release-readiness report](release-readiness.md) and [disposable harness](../acceptance/README.md)
before any deployment. The shared snapshot path now checks free bytes for rollback
and uninstall as well as install/upgrade. Snapshots remain full private copies.

Proposed retention is current plus three previous successful releases and their
corresponding backup sets, with pending-transaction and newest safety backups
pinned. No automatic pruning is implemented; disk usage remains unbounded.
Do not delete releases/backups manually while a transaction is pending. Locked
service identities remain after uninstall; manual account deletion requires a
separate ownership/reference audit and operator approval.

## Admin helper installation and upgrade

0.6.0-beta installs/enables a fourth primary service,
`kc1ray-hub-scanner-admin.service`, before broker, monitor and web. It is a
restricted root helper for configuration, credentials and the two schedule timers;
it has no Asterisk access. An upgrade from older manifests automatically adds and
starts it without new configuration keys, preserving operator configuration,
credentials, favorites, history and existing service states. Existing backups
without the new unit remain accepted for rollback. Normal uninstall removes the
unit and retains operator data and locked service identities.

After a separately approved installation or upgrade, inspect:

```sh
systemctl status kc1ray-hub-scanner-admin.service --no-pager
stat -c '%U:%G %a %n' /run/kc1ray-hub-scanner-admin /run/kc1ray-hub-scanner-admin/admin.sock
```

Expect root:kc1ray-control, directory 750 and socket 660. Sign in, open Admin,
check the reported statuses, change refresh and verify live behavior. Test source
timer changes, a failed operation/rollback, password reauthentication and rejection
of old sessions. Verify anonymous API mutations remain forbidden. Repeat through
`/hubscanner/` if using Apache. These are acceptance instructions, not operations
performed on the development host.

## Admin helper recovery

If Admin reports recovery required, do not delete its transaction file or manually
retry an installer rollback over it. Restarting the helper attempts recovery of the
previous settings/timer state first. For diagnosis without starting the listener,
on a separately authorized target:

```sh
sudo systemctl stop kc1ray-hub-scanner-admin.service
sudo /usr/bin/python3 -B -E -s /opt/kc1ray-hub-scanner/current/admin_service.py --recover-only
sudo systemctl start kc1ray-hub-scanner-admin.service
```

If recovery fails, retain the private journal and backups, inspect fixed timer
availability and permissions, and repair the reported prerequisite before retrying.
Do not publish the journal or credentials. Package install/upgrade/rollback/uninstall
refuse a pending Admin transaction, preventing recovery from overwriting restored
package configuration. Damaged configuration may require restoring a validated
operator backup before helper recovery; never erase retained favorites or history.
