# Spare Raspberry Pi ARM64 / Debian 12 acceptance

Status: **pre-installation review only; installation awaiting owner approval**.
Run the commands in stage A only, on the dedicated spare Pi. No remote connection
or target command has been executed by the development agent. Never use the
the production installation host, its credentials, or its running services for this procedure.

This checklist adapts [Phase 5](release-readiness.md), the [disposable harness](../acceptance/README.md)
and [installation documentation](installation.md). **Do not run
`acceptance/installed.py` or `acceptance/mock_asterisk.py` on this Pi.** They are
synthetic-container fixtures, including a fake Asterisk package, service and node
configuration. Do not bypass their guards or create their image marker here.

## A. Read-only checks — authorized now

Commands query the target; they do not install dependencies, create accounts,
change permissions, submit radio controls, write Asterisk configuration, or start,
stop, enable or reload services. `sudo` is used where inspection needs privilege.
Keep outputs locally; share only a sanitized summary, not configuration contents,
credentials, registration secrets, cookies, hashes of administrator credentials,
private addresses or complete journals.

### A1. Identify the spare and establish physical RF inhibition

Before connecting, positively identify the spare by its physical label, console
and expected hostname. Do not select a machine solely from a saved SSH alias.
Record who verified the physical setup and when.

```sh
hostnamectl --static
cat /etc/os-release
uname -m
dpkg --print-architecture
getconf LONG_BIT
tr -d '\000' < /proc/device-tree/model
printf '\n'
id
ps -p 1 -o comm=
```

Pass: the expected spare, `ID=debian`, `VERSION_ID="12"`, `aarch64`, `arm64`,
64-bit userspace, expected Pi model and systemd PID 1. `armhf`/32-bit userspace
might pass the installer's wider architecture policy, but does not satisfy this
ARM64 acceptance run. Debian 13, a derivative, a mismatched host or an unexpected
model is a stop for review. No identity/OS conversion is part of these checks.

**RF gate:** physically inhibit transmitter keying using the test setup's
established hardware/PTT isolation procedure; verify local transmitters cannot
key. If a transmitter remains connected, use an appropriate test load and the
operator's approved isolation procedure. Removing an antenna alone is not an RF
inhibit. Keep the inhibit throughout acceptance. Software flags, no active links,
a quiet dashboard or an unkeyed statistic do not prove RF is disabled. Any later
remote link must use a cooperating test endpoint with its transmitters inhibited
as well. Do not connect FIRST/NEXT to ordinary public hubs for these tests.

Confirm the spare is not using a production node identity/registration or automated
linking hooks that would interfere with the production installation. If uncertain, stop; do not change
node numbers, registrations or hooks as part of preflight. No radio controls are
authorized in stage A even with RF inhibited.

### A2. Python and required tools

```sh
/usr/bin/python3 -B -I - <<'PY'
import hashlib, ssl, sys, tomllib
print('Python:', sys.version.split()[0])
print('tomllib: available')
print('scrypt available:', hasattr(hashlib, 'scrypt'))
print('CA certificates:', ssl.create_default_context().cert_store_stats()['x509_ca'])
PY
for tool in systemctl systemd-analyze groupadd useradd runuser passwd nologin dpkg-query ss stat namei sha256sum; do
    command -v "$tool" || printf 'MISSING: %s\n' "$tool"
done
sudo -l
```

Pass: Python >=3.11, tomllib, scrypt support, a positive CA count and required
commands. This checks scrypt availability, not a successful memory-intensive hash
on ARM64. Node.js is needed only if running the development syntax suite on the
Pi, not for application operation. `ss`, `stat`, `namei` and sha256sum are inspection
tools; installer prerequisites are listed in installation.md. Missing items stop
preflight; do not install packages now. An authorized administrator must later
be able to provision system users, chown managed files and manage application
units. `sudo -l` inspects privileges; do not change sudoers or grant web access.

### A3. Asterisk package, running service and socket

```sh
dpkg-query -W -f='${binary:Package} ${db:Status-Status} ${Version}\n' asl3-asterisk
sudo /usr/sbin/asterisk -V
systemctl is-active asterisk.service
systemctl show asterisk.service -p FragmentPath -p User -p Group -p MainPID -p ActiveState -p SubState
readlink -f /usr/sbin/asterisk
namei -l /usr/sbin/asterisk
sudo stat -c '%F %U:%G %a %n' /run/asterisk /run/asterisk/asterisk.ctl
sudo namei -l /run/asterisk/asterisk.ctl
sudo stat -c '%F %U:%G %a %n' /etc/asterisk /etc/asterisk/rpt.conf
```

Pass: installed `asl3-asterisk`, an active existing service, a root-owned executable
and resolved ancestors without group/world write, and a real Unix socket at the
standard path. Its non-root group must have socket write and directory traversal.
Record the actual group; do not assume its name. The installer refuses privileged
groups such as root/sudo/adm/disk/shadow/docker/lxd. Mode 0660 is common, but record
the actual mode; broad world access is refused by preflight and requires review. A custom binary may be configured after review; a custom control socket
path is currently unsupported. Missing/unexpected permissions or paths are a stop:
no chmod, chown, Asterisk restart or configuration rewrite is authorized here.

For the reported ASL3 `asterisk:asterisk` socket at 0755, see the
[restricted group-access procedure](asterisk-socket-access.md). This is a known
owner-access layout, not a reason to bypass the preflight failure. World-accessible
sockets are now refused outright; retain the existing 0755 directory if traversable.

### A4. Time, storage and headroom

```sh
date -u
timedatectl show -p TimeUSec -p NTPSynchronized
free -h
df -h / /opt /etc /var /run
df -i / /opt /etc /var /run
findmnt -T /var
uptime
sudo journalctl -k -b -p warning --no-pager -n 40
```

Pass: correct UTC time, writable/healthy intended storage, free inodes and space
for code plus full private backup sets, and adequate idle memory/CPU headroom.
NTP synchronization is useful evidence, but verify actual clock accuracy; neither
an incorrect synchronized clock nor absence of NTP alone decides freshness.
Stop for I/O/read-only filesystem errors, severe memory pressure, throttling or
power problems. Review kernel messages locally; do not paste unredacted logs.
There is no validated minimum Pi RAM/CPU margin yet. Scrypt's main memory array
is approximately 128 MiB per hash (serialized), plus process/services/Asterisk
memory. Do not weaken password hashing to force a pass. The installer's 16 MiB
reserve is not a recommended total free-space budget; backups copy managed files
and all retained releases. Retention is currently unbounded.

### A5. Conflicts and existing state

```sh
sudo ss -ltnp
systemctl list-unit-files 'kc1ray-hub-scanner-*' --no-pager
for account in kc1ray-web kc1ray-radio kc1ray-monitor; do
    getent passwd "$account"
done
for group in kc1ray-web kc1ray-read kc1ray-control; do
    getent group "$group"
done
sudo ls -ld /opt/kc1ray-hub-scanner /etc/kc1ray-hub-scanner /var/lib/kc1ray-hub-scanner /var/lib/kc1ray-hub-scanner-monitor /var/lib/kc1ray-hub-scanner-package /var/cache/kc1ray-hub-scanner /run/kc1ray-hub-scanner /usr/local/sbin/kc1ray-hub-scanner /etc/tmpfiles.d/kc1ray-hub-scanner.conf
```

For a fresh installation, no reserved accounts/groups, units or managed paths
should exist; missing entries/nonzero getent/ls exits are expected. Existing
managed state needs upgrade/reinstall review; unmanaged collisions must not be
deleted or adopted automatically. Review listener output locally, choose a free
unprivileged port (8085 is the example), and preserve current network exposure.
No firewall, Tailscale, reverse proxy or port forwarding changes are needed now.

### A6. Reviewed-source installer inspection and node selection

Use a trusted local copy on the **spare**, if already present. Do not fetch/copy or
deploy automatically. From that source directory:

```sh
sudo sh ./install.sh inspect
```

No `--execute`: this invokes package/platform/service/socket/config discovery only.
It does not run `#exec`, change files or send connect/disconnect commands. The
report lists numeric node sections, architecture, versions, socket group and
whether dynamic config exists. It does not prove current node operation. Includes
must remain within `/etc/asterisk`; missing/oversized/symlinked/external includes
can legitimately block discovery. Stop for review rather than bypassing checks.

Choose the spare's existing test node from that report. Replace YOUR_TEST_NODE
below with that exact numeric node before running; never use a production node.
This query can contain private variables, so filter output locally:

```sh
sudo /usr/sbin/asterisk -rx 'rpt show variables YOUR_TEST_NODE' | sed -n '/^[[:space:]]*RPT_ALINKS=/p'
```

Pass: a recognizable `RPT_ALINKS` result for the chosen running node. No output,
CLI error or unexpected link state requires review. Inspect current test links
without disconnecting them. A positive result under root does not establish
future radio-account access; installation later tests that separately.

Read-only fresh-install plan, with YOUR_TEST_NODE replaced:

```sh
sudo sh ./install.sh install --node YOUR_TEST_NODE --port 8085
```

Pass: no changes performed, correct node/port/layout and no conflicts. Defaults
must remain localhost/private, controls disabled, 1800-second idle and
28800-second maximum sessions; schedules initially off. Do not supply imported
TOML/credential/history/favorites data before separately reviewing its origin and
settings. Plan success does not test actual systemd startup, allocated identities,
scrypt execution, HTTPS access or effective socket authorization.

Optional read-only preservation baseline, kept privately in the terminal record:

```sh
sudo find /etc/asterisk -type f -exec sha256sum {} +
sudo find /etc/asterisk -type l -printf '%p -> %l\n'
```

Record package version and service state too. These hashes cover configuration
files, not targets of external symlinks, external hooks, or a full recovery image.
Do not publish filenames/node details if private; never print file contents.

### A7. Stop and review

Return a sanitized checklist: spare identity verified; physical RF inhibit
verified; OS/arch/Python/package versions; active Asterisk; socket owner/group/mode;
node discovery/query success (node may be redacted); selected port availability;
memory/free disk/inodes; conflicts; installer plan status; any errors. Do not
send administrator hashes, complete node variables, configuration or login tokens.

**Wait for owner approval here.** No installation, account provisioning, package
installation, code deployment, service changes or link commands are authorized by
completion of these checks. Any failed/ambiguous gate must be resolved in review.

## B. Controlled checklist — reference only, separately approved later

The following sequence is prepared for the next approval. It is not authorization
to execute it now. Use installation.md for exact lifecycle commands.

1. Reconfirm spare identity and physical RF inhibit. Agree on permitted test
   destinations; both endpoints must be RF-inhibited. Inventory existing hooks,
   DTMF callers and auto-links. Preserve node settings. If callbacks can mutate
   Hub Scanner state, agree how to quiesce those callers without changing ASL
   configuration. Make an offline SD-card recovery image or equivalent tested
   backup of the spare, plus private configuration baselines, before installing.
2. Re-run the read-only plan against the exact reviewed source. Approve node,
   port, source checksum and backup location/free space. Only then use the
   documented install command with `--execute`. Keep both schedule integrations
   off initially. Create the administrator interactively with a hidden 8+ character
   passphrase; never pass it through shell arguments or environment. Record backup
   IDs/release identity, not passwords. Installation starts/enables application
   units; it only queries Asterisk and does not start/restart/configure ASL.
3. Inspect actual services and roles:

   ```sh
   systemctl status kc1ray-hub-scanner-broker.service kc1ray-hub-scanner-monitor.service kc1ray-hub-scanner-web.service --no-pager
   systemctl show kc1ray-hub-scanner-broker.service kc1ray-hub-scanner-monitor.service kc1ray-hub-scanner-web.service -p User -p Group -p SupplementaryGroups -p MainPID -p ActiveState -p After -p Requires
   sudo stat -c '%U:%G %a %n' /run/kc1ray-hub-scanner /run/kc1ray-hub-scanner/control.sock /etc/kc1ray-hub-scanner/config.toml /etc/kc1ray-hub-scanner/credentials.json
   id kc1ray-web
   id kc1ray-radio
   id kc1ray-monitor
   sudo passwd -S kc1ray-web
   sudo passwd -S kc1ray-radio
   sudo passwd -S kc1ray-monitor
   sudo ss -ltnp
   ```

   Require three distinct nonroot, locked/nologin identities. Only radio has the
   existing Asterisk socket group; web and monitor do not. Broker socket must be
   radio:kc1ray-control 0660, directory radio:kc1ray-read 2750; config root:read
   0640, credentials root:web 0640. Web must listen only on loopback. Check actual
   process UIDs/groups against the unit and generated broker UID settings. Do not
   expose credential contents. Read-only `runuser ... test -r/-w PATH` checks should
   confirm web cannot write code/config/state/runtime, monitor cannot access the
   control socket, and only web/root can read credentials. Authorized favorites
   requests must work through the real socket; never relax peer-UID checks.
4. Access loopback through a separately agreed SSH tunnel or reviewed HTTPS proxy.
   Do not bind externally as a shortcut. Check login, logout/revocation, HttpOnly/
   SameSite cookies, default private views, session expiry, wrong-CSRF and spoofed
   forwarded headers. Unauthenticated `/api/activity` and `/api/favorites` return
   401; mutations fail without authorization. With the maintenance switch off,
   controls/favorites can return 403 before authentication. After explicitly
   enabling mutations for tests, verify unauthenticated mutations still fail and
   valid-cookie requests without CSRF return 403. Test the five-attempt login
   limit in a controlled window; honor Retry-After. For HTTPS, require Secure
   cookies, exact origins and explicit proxy addresses. Keep secrets out of CLI
   history/logs; use browser or an approved in-memory test client, not password args.
5. Enabling `controls_enabled` also enables radio requests, so maintain physical
   inhibition. Through the authenticated UI, add/edit/reorder/remove only agreed
   test favorites. Verify JSON order/names and monitor cache refresh without a
   restart. Restore intended test favorites at completion; never import production
   favorites automatically. Record monitor PID before/after to prove live reload.
6. Verify fresh stats, unknown on failures/staleness, saved counter baselines and
   last-activity retention. After approval, restart only the monitor and compare
   valid retained counters/timestamps; a saved active label is not proof of activity.
   Use the offline harness for deliberately corrupted/missing history and 429
   injections rather than damaging the real Pi's data or flooding the provider.
   Keep the normal four-second polling interval, 15-second cooldown and existing
   history/cache write throttles. Small favorite lists simplify freshness testing.
7. Separately enable optional NetWatch using configuration.md/installation.md;
   explicitly manage its timer. Check current generated timestamps and imported
   Nets entries, upcoming information and Add to Favorites. AllStar Nets fallback
   is optional and separately approved. No NetLogger polling. Keep changes to
   external requests within provider limits. Do not treat a cached schedule as
   confirmation that a remote endpoint is safe for link testing.
8. Radio gate: reconfirm physical local AND remote inhibition and destination
   authorization. First record `RPT_ALINKS`; test FIRST, NEXT, STOP, manual and Nets
   Connect/Disconnect one at a time, >=15 seconds after completion. Query reported
   links (dashboard may cache for five seconds) after each command and compare the
   expected state. HTTP200 is submission, not link confirmation. Stop on unexpected
   links/timeouts; do not retry blindly. Do not invoke unrestricted public endpoints.
   Verify the [application-owned policy](link-transitions.md): all old direct links
   clear before connect, and failure/timeouts abort. No hook installation, DTMF
   rewrite or Asterisk configuration change is part of this acceptance test.
9. Recompare Asterisk configuration hashes/symlinks, node identity and existing
   service state. Confirm no automatic exposure or Asterisk configuration changes.
   Record installed results separately from mock tests. Full reboot/startup-order
   tests need a separately agreed interruption of the spare, still RF-inhibited.
10. Upgrade/rollback/uninstall rehearsal: approve a reviewed candidate and recovery
    window; quiesce external application writers, check space and record private
    config/favorites/history/account baselines. Use read-only upgrade plan, then
    approved execute; verify data and UID preservation. Rollback has its own safety
    snapshot and restores **data at the selected snapshot time**, not code alone.
    Verify login with retained administrator, favorite ordering/history, identity
    IDs and service states. Test uninstall without purge; data and locked identities
    must remain. Three-previous-release retention is a proposal; no pruning runs.

## C. Recovery reference — only after installation is separately approved

- Failed install/upgrade should restore previous managed files/services; record the
  error and inspect app journals locally. Do not delete transaction journals or
  broaden permissions to force startup. Asterisk must remain unchanged.
- For a valid recorded backup, from a trusted retained source checkout:

  ```sh
  sudo sh ./install.sh rollback --backup BACKUP_ID
  ```

  That is validation only. A separate recovery approval is required before adding
  `--execute`. Verify sufficient space for the safety backup and expected snapshot
  date/data. Re-check accounts, services, config, favorites and history afterward.
- To remove an approved test installation, first review `uninstall` without execute;
  then use the documented approved execution path without `--purge`. Keep data,
  private backups and locked identities. Do not delete identities manually.
- If managed recovery cannot restore the spare, preserve journal/backups for diagnosis
  and use the previously verified SD image. Restoration overwrites later test data;
  it is a separate explicit operation, never an automatic command in this checklist.
- Never restore any image/configuration onto the production installation. Leave RF inhibited until the
  hardware test session is explicitly closed by the operator.
