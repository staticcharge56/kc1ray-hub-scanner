# Approved direction and development phases

## Boundaries

Develop only in this local Linux Mint copy. Do not connect to or modify the
production Raspberry Pi, running services, or Asterisk configuration. No commits,
GitHub publication, installation, or service activation are authorized here.
Phase 1 permits documentation, examples, isolated tests, and development tooling;
it does not rewrite radio controls. MIT remains proposed pending final approval.

## Release acceptance requirements

- Local-only defaults. Anonymous viewing is optional and administrator-configured.
  Radio controls and favorites management always require operator authorization.
  Define whether anonymous viewing includes favorite names; mutation is never public.
- Support Tailscale Serve and trusted HTTPS reverse proxies. Trust forwarded
  identity/headers only from explicitly configured proxies; prevent direct bypass.
  Define allowed hosts/origins, secure sessions, CSRF, and attempt rate limits.
- Persist recent activity and counter baselines across restarts. Retained history
  must never override freshness: stale/future observations cannot imply current RF
  activity. Handle counter resets, corrupted state, and clock changes.
- One authoritative favorites store; preserve existing order, names, and nodes.
  Explicit migration backs up originals, validates before replacement, and reports
  conflicts instead of silently dropping data. Optional INI import requires no
  installed/running AllScan. Changes appear live without monitor restart.
- Honor HTTP 429 Retry-After (delay seconds and HTTP date), bounded retries/backoff,
  and shared-IP API budgets. Surface the favorites-count/freshness tradeoff.
- Preserve FIRST/NEXT/STOP, manual and Nets controls, and existing DTMF CLI contract.
  Default to disconnecting the previous direct link before another connect;
  configurable single-link policy. Confirm disconnect and connect through Asterisk
  reported state with bounded waits. Fail safely on unavailable/ambiguous status.
- NetWatch is optional/configurable; favorites scanning works without it. Preserve
  Nets, upcoming information, Connect/Disconnect and Add to Favorites. No NetLogger
  polling. External sources fail independently and retain last-good caches.
- Target ASL3 on Debian 12, including Raspberry Pi ARM64. Keep mobile wake lock.

## Incremental phases and review gates

1. **Baseline and development organization (this phase):** document current behavior,
   add syntax checks and isolated regression tests, draft configuration, record
   missing deployment evidence. Keep runtime and historical files in place.
2. **Configuration and data:** shared validated config, runtime path separation,
   authoritative favorites and explicit migration, persistent monitor records and
   rate-limit handling. Test each small change before proceeding.
3. **Secure controls:** authenticated viewer/operator policy, protected mutations,
   bounded HTTP handling, shared control service, confirmed Asterisk transitions,
   configurable single-link switching, and DTMF compatibility tests using supplied
   sanitized wrapper details. No production deployment.
4. **Lifecycle packaging:** preflight Debian/ASL/architecture/dependencies/node/ports;
   restricted service identities, root-owned code, writable state separation,
   systemd services/timers, idempotent install, preserved-data upgrades/rollback,
   uninstall retaining data unless purge is explicit. Validate in disposable hosts.
5. **Integration and device verification:** offline failure cases, concurrent actions,
   disposable Debian 12 ARM64 ASL3 acceptance, trusted-proxy behavior, mobile wake
   lock and tab workflows. Mock tests alone do not establish platform compatibility.
6. **Release preparation:** complete installation/operation/API/rate-limit/upgrade/
   troubleshooting docs; review privacy and tracked history; license decision and
   owner publication review. Do not publish automatically.

Phase 1 was approved. Phase 2A (configuration and favorites) was subsequently
authorized and is implemented as recorded in phase-2a.md. Phase 2B was then
authorized for persistent history/API reliability and is recorded in phase-2b.md.
Phase 3 was subsequently authorized for security and is recorded in phase-3.md.
Phase 4 packaging was subsequently authorized and is recorded in phase-4.md.
Production installation, deployment and publication remain outside the authorized increment.

## Target organization

Keep root runtime files unchanged for now. Future implementation will introduce
`src/kc1ray_hub_scanner/` for shared config, auth, control, Asterisk adapter,
monitor/scanner/favorites and schedules; `web/` for HTML/CSS/JS;
`packaging/systemd/` for units; and `scripts/` for lifecycle tooling. Current
`docs/`, `config/`, `tests/fixtures/`, and `tools/` support that transition.

Proposed install paths: application `/opt/kc1ray-hub-scanner`, configuration
`/etc/kc1ray-hub-scanner`, persistent state `/var/lib/kc1ray-hub-scanner`, caches
`/var/cache/kc1ray-hub-scanner`, locks/sockets `/run/kc1ray-hub-scanner`, journal
logging. Service users must not own executable source. Privileged access to
Asterisk requires a narrowly scoped interface rather than an unrestricted web
process running as the Asterisk identity.
