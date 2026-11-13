# Phase 2A implementation and review (historical)

Phase 2B subsequently adds monitor persistence and API reliability as recorded in
[phase-2b.md](phase-2b.md). The remaining-scope statements below describe the
Phase 2A handoff.

## Changes

| Files | Change |
| --- | --- |
| configuration.py (new) | Shared TOML loading, explicit environment selection, merged defaults, strict schema/type/value validation; no configuration writes |
| favorites_store.py | One authoritative validated JSON store; serialized atomic updates, file and directory fsync; no generated INI; exact persisted descriptions |
| monitor.py | Configured node/paths/timings/stats URL; shared JSON reads and live reload; malformed reload retains previous list |
| scanner.py | Configured node/paths/Asterisk; selection order/names/membership from live store, observations from cache; existing command/CLI flow preserved; valid leading shebang |
| dashboard.py | Configured network/node/paths/cooldown; dynamic UI values; current favorites joined with statistics; configurable optional schedules; default mutation gate |
| update_netwatch.py, update-nets.py | Configured source/detail URLs, cache paths, request timeout and enable switches; disabled sources perform no I/O |
| migrate_favorites.py (new) | Dry-run default, validated JSON/INI import, exact source backup, no-clobber atomic publication, idempotence and conflict refusal |
| config/config.example.toml | Implemented schema replacing the earlier design-only proposal |
| tests/test_baseline.py | Existing 22 cases retained; fixtures adapted from INI/cache favorites to the authoritative JSON interface |
| tests/test_configuration_favorites.py (new) | Configuration, migration, concurrency/failure, live reload and command-compatibility coverage |
| tools/check.py | Syntax/config/regression checks under the isolated example configuration; Phase 1 hashes remain historical rather than banning authorized edits |
| README.md, docs/configuration.md, docs/phase-2a.md, historical phase docs | Current setup/migration/preservation instructions and explicit phase boundaries |
| .gitignore | Ignore potentially private migration backup files |

## Validation

`python3 -B tools/check.py` passes **55 tests**, including all 22 baseline cases.
Eight root Python modules plus test/tool Python syntax parse successfully.
Rendered embedded JavaScript passes `node --check`; configuration examples parse
and retain loopback binding, disabled mutations, and explicit-node setup.

New coverage includes configuration precedence, malformed/unknown values,
propagation into runtime modules, concurrent edits without lost updates, failed
atomic replacement, exact description preservation, running monitor reloads and
transient failures, cache-independent live favorites membership, disabled sources,
schedule fallback/age/duration settings, migration backup/idempotence/conflicts,
racing destination creation, and unchanged configuration during import.

Radio command strings, command counts, selection-state behavior, and scanner
selection semantics are checked with mocked Asterisk execution. External commands
and HTTP requests are blocked in tests. No production Pi was contacted; no real
Asterisk commands, services, installer, deployment, commit, or publication ran.
Historical source backups and runtime state were left in place.

No new third-party dependencies were introduced. The implementation uses Python
3.11 and Linux standard-library facilities available on Debian 12, including
flock, atomic local filesystem operations, and directory fsync. Actual Debian 12
ASL3/ARM64 and mobile-browser integration remain unverified in this local Mint
increment. No claim of completed hardware acceptance is made.

## Configuration decisions for owner review

- Configuration selection is `KC1RAY_CONFIG`, then the default /etc path. All
  processes/wrappers must select the same file. Config changes require a process
  restart; favorites changes remain live.
- New layout defaults use separate state/cache/runtime directories. Existing
  installations may explicitly retain their directories. Do not replace retained
  TOML or favorites with examples on upgrade; no automatic installer exists yet.
- Both external schedule sources default off. Enable the previously used sources
  explicitly for equivalent behavior. Source scheduling is still external.
- `web.controls_enabled` defaults false and gates both radio and favorites writes.
  True retains legacy unauthenticated controls. No proxy identity, sessions,
  authorization, or anonymous-view policy has been implemented before Phase 3.
- Earlier design-only settings for single_link, confirmation, auth/proxy policy,
  restart history and backoff are intentionally rejected as unsupported rather
  than silently accepted with no effect. Existing single-link hook behavior is
  preserved, not replaced; the default web cooldown remains 15 seconds.
- Migration rejects duplicate/conflicting or unrepresentable favorites rather
  than silently deduplicating/truncating. JSON is preferred for exact descriptions;
  INI import removes the old generated trailing node suffix. Invalid existing
  destination data is never automatically reset.
- Existing IPv4 server behavior remains; IPv6 binding is explicitly unsupported.

## Remaining scope

Phase 2B persistence and Retry-After/backoff are not started. Phase 3 authentication,
proxy trust, restricted radio privileges, disconnect-before-connect, and confirmed
link transitions are not started. Current command state still describes requests,
not proven connection success. DTMF mappings and the external single-link hook
remain missing from the supplied copy; the scanner CLI contract is retained, but
those external integrations still require sanitized evidence and later validation.
