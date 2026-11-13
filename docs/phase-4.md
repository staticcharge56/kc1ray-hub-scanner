# Phase 4 packaging implementation and review

## Implemented scope

The project now has explicit install/upgrade/rollback/uninstall commands, generated
systemd units/timers, account/layout provisioning, administrator setup, optional
data imports, validation and recoverable transactions. Default CLI behavior is
read-only planning; system changes require root and --execute on a supported target.
No such installation was performed in this development session.

[installation.md](installation.md) provides the step-by-step procedure, including
legacy migration, password reset, recovery and irreversible purge behavior.
[asterisk-integration.md](asterisk-integration.md) documents optional, separately
reviewed DTMF/single-link integration without altering any Asterisk file.

## Changed files

| Files | Purpose |
| --- | --- |
| install.sh (new) | Quoted local-checkout entry point; defaults to planning |
| tools/installer.py (new) | Host discovery, fixed-path lifecycle manager, three account roles, staging, private snapshots/checksums, transaction journal, upgrade/rollback/uninstall/purge handling and CLI |
| tools/runtime_check.py (new) | Read-only schema/data validation and broker/web readiness checks |
| packaging/release.json (new) | Local development version and supported format schemas, not a published release |
| packaging/systemd/*.service.in (five new) | Broker, monitor, web, NetWatch and AllStar Nets roles, ordering, identity and filesystem boundaries |
| packaging/systemd/*.timer.in (two new) | Optional NetWatch and daily AllStar Nets refresh |
| configuration.py, monitor.py | Optional monitor-owned persistence directory with backward-compatible fallback; the monitor's only change is that path constant |
| config/config.example.toml | Explain managed history location and optional schedule timers |
| tools/check.py | Shell syntax, actual systemd static verification, broken-config recovery CLI check and larger suite timeout |
| tests/test_packaging.py (new) | Simulated target filesystem/accounts/services, lifecycle/permissions/failure/recovery/readiness tests |
| tests/fixtures/phase-4-protected.json (new) | Thirteen unchanged runtime modules hashed for scope protection |
| tests/test_control_security.py | Retire the Phase 3 whole-monitor edit ban for the explicit history-path change |
| README and current documentation | Installation links, layout/security clarification, phase status and review limits |

No application password hashing, session/CSRF/proxy policy, radio commands,
favorites mutations, monitoring/retry logic, schedule parser, or screen-awake code
was rewritten. Thirteen runtime modules remain byte-for-byte unchanged. A separate
normalized hash test proves that replacing the monitor's one new history-path key
with the old one reproduces its Phase 3 source exactly.

## Architecture and preservation

- Three non-root locked/no-home roles: web, radio, monitor. Only radio receives the
  existing Asterisk control socket group. Web is a read-only data reader and exact
  authorized Unix-socket client; monitor writes its own history/cache without
  Asterisk membership. The new history directory avoids ACLs or a world-readable/
  group-writable shared data tree.
- Code/config remain root-owned; credentials are readable only by root/web. SGID
  read-group directories preserve read-only sharing across atomic replacements.
- Asterisk package/service/config/includes/socket permissions are detected/read,
  never overwritten. Tailscale, firewall, Funnel and port forwarding are unchanged.
- Versioned root-owned releases and an atomic current pointer support rollback.
  Only allowlisted source/docs/templates are packaged; historical backups, runtime
  state, tests and environment metadata are excluded from releases.
- Upgrade validates retained settings/identities/integrity, quiesces owned units,
  takes a durable private snapshot and switches/restarts. It preserves original
  config bytes/comments, favorite names/order, history, credentials and service
  identities, as well as existing stopped/disabled unit choices.
- Supported schema metadata migration is explicit and nondestructive. Unknown
  schemas require a reviewed migration. Initial imports preserve existing settings
  except documented layout/identity bindings; JSON/strict legacy favorites and
  version-1 history can be supplied explicitly. Source files are never modified.
- Uninstall retains data, hashes, backups and locked identity registrations by
  default. Purge requires an exact confirmation and is explicitly irreversible;
  a partial purge is resumable, not misreported as recoverable after backup deletion.

## Validation and scope of evidence

Final validation: `python3 -B tools/check.py` passed **226 tests** in about
49 seconds: all **183 previous cases** (with the authorized monitor-path scope
adjustment) and **43 packaging/readiness/CLI cases**. Python and
both application/login JavaScript syntax, shell syntax, and actual systemd unit
verification are checked. systemd verification uses a temporary Asterisk unit
stub; it does not start or install a unit.

The target backend is simulated under temporary directories. All user/group,
Asterisk and systemctl commands are intercepted; the real staged backend refuses
to execute system commands. Ownership is modeled while content/modes/atomic file
operations are exercised on temporary files. Coverage includes platform/architecture,
include discovery, missing prerequisites, reserved-name conflicts, permissions,
optional sources, least-privilege role separation, partial failures, low space,
exact upgrade preservation, disabled units, future schemas, backup integrity,
explicit rollback, interrupted journals, retained-data reinstall, purge confirmation/
resume, readiness, and unchanged Asterisk files/settings.

A separate read-only `sh install.sh inspect` check on this Mint development host
correctly refused installation before any system changes. Local documentation
links and all thirteen protected runtime hashes were also checked.

The existing security socket-pair tests require the previously approved local
execution outside the sandbox's socket restriction. They use no TCP listener or
production connection. No actual OS account, service, Asterisk process, network
exposure or production Raspberry Pi was changed.

## Assumptions and remaining review

1. Real Debian 12 ASL3/ARM64 boot, actual service-account isolation, systemd sandbox
   behavior, password hashing performance and Tailscale HTTPS acceptance remain
   required in a disposable environment. Simulations/static verification cannot
   establish those results; Mint is intentionally not an installation target.
2. The standard Asterisk socket and a suitable non-root writable control group
   are required. Nonstandard sockets/groups and dynamic/external includes need
   operator review, not automatic permission/configuration changes.
3. Review the three proposed service names/roles/groups, fixed managed paths and
   root-only backup policy. Existing unmanaged destinations/accounts are refused.
   The monitor-owned state path is a backward-compatible configuration addition.
4. External DTMF/cron/script writers must be quiesced during maintenance. Optional
   sudoers/hooks are documented but never installed or removed automatically.
   Existing single-link behavior remains topology-dependent and unconfirmed.
5. Backups and old releases are retained; no automatic pruning/retention policy
   deletes rollback material. Check free space on Pi SD cards. Narrow hard-crash
   windows in external account-tool execution can need manual identity reconciliation.
6. Confirmed purge permanently deletes managed data and backups, but deliberately
   retains locked UIDs/groups and the private identity registry. Journal retention
   remains with the host. Review this account-retention choice before publication.
7. There is no signed release/download pipeline and no final license grant. Version
   0.4.0-dev is local package metadata only. MIT approval and publication remain
   with the owner. No commit, push, deployment or GitHub release occurred.

## Documentation files in this increment

New: `docs/installation.md`, `docs/asterisk-integration.md`, `docs/phase-4.md`.
Updated: `README.md`, `docs/security.md`, `docs/configuration.md`,
`docs/activity-monitoring.md`, `docs/phase-3.md`, `docs/validation.md`, and
`docs/development-plan.md`.

The seven templates are `kc1ray-hub-scanner-broker.service.in`,
`kc1ray-hub-scanner-monitor.service.in`, `kc1ray-hub-scanner-web.service.in`,
`kc1ray-hub-scanner-netwatch.service.in`, `kc1ray-hub-scanner-allstarnets.service.in`,
`kc1ray-hub-scanner-netwatch.timer.in`, and `kc1ray-hub-scanner-allstarnets.timer.in`,
all under `packaging/systemd/`.
