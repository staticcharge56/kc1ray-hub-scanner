# Configuration and favorites (through Phase 4)

Phase 3 authentication, proxy trust, local broker and permission prerequisites are
documented in [security.md](security.md).

## Configuration selection

All application components import the same `configuration.py`, using Python
3.11's `tomllib`. Configuration is loaded once per process, without writing it:

1. `KC1RAY_CONFIG` selects an explicit TOML file. A missing/invalid file is fatal.
2. Otherwise `/etc/kc1ray-hub-scanner/config.toml` is used when present.
3. Otherwise built-in defaults apply, with an empty node. Dashboard, monitor, and
   scanner entry points refuse operation until a local node is configured.

For local development, copy `config/config.example.toml` to a new private file
once, set its absolute path in `KC1RAY_CONFIG`, and edit that file. Do not copy an
example over an existing configuration on upgrade. Do not run the application
against production paths from this development workspace.

Only documented keys are accepted. Unknown keys, wrong types (including booleans
for numbers), invalid node numbers, relative data paths, nonpositive intervals,
and insecure external URL schemes are rejected. Integer timing values use seconds.
Local node IDs accept 3–7 ASCII digits; favorites retain the legacy 4–7 digit rule.

[LAN selection and HTTPS guidance](network-access.md) describes the recommended
explicit private-LAN installation workflow. `web.allow_lan_http` defaults false;
selecting a LAN address in the installer sets it true and sets the exact HTTP origin.
Manual trusted-LAN setup must set all three deliberately. It permits HTTP admin
access only from RFC1918 clients on that exact origin; it does not encrypt traffic.
Upgrades and retained-data reinstalls preserve existing network settings, including
localhost-only policies. Existing files need no new key: false is the default.

`web.bind` supports IPv4 and host names with the existing HTTP server. Defaults
are `127.0.0.1:8085`. IPv6 binding is not implemented. `web.controls_enabled=false`
blocks both radio and favorites POSTs. Setting true enables those operations only
for a logged-in administrator with a valid session and CSRF token. Authentication,
optional anonymous viewing and explicit proxy trust are now implemented in Phase 3.
No configuration restores unauthenticated mutations.


The default cooldown remains 15 seconds via `controls.cooldown_seconds`. Existing
application-owned disconnect-before-connect and verified connection states remain
in effect. See [link transitions](link-transitions.md) and
[connection-state safety](connection-state-safety.md). No Asterisk hooks are required.

## Paths and files

| Configuration key | Files |
| --- | --- |
| paths.state_dir | authoritative favorites.json, favorites.lock, scanner-state.json, web-last-command.json |
| paths.monitor_state_dir | monitor-history.json; defaults to state_dir in manual/legacy layouts |
| paths.cache_dir | activity.json, nets.json, netwatch-nets.json |
| paths.runtime_dir | scanner.lock, web-control.lock |
| paths.scanner_script | scanner CLI script; defaults to scanner.py beside configuration.py |
| allstar.asterisk_binary | absolute Asterisk executable path |

State/cache/runtime directories must exist with suitable application permissions
before running the dashboard/monitor/scanner. The web process is now read-only;
Phase 3 delegates writes/radio actions to the configured local control service. Migration creates its destination
parent with mode 0750 when absent; it does not set service users, create service
units, or establish permissions for the whole deployment. Favorites files use
0640; migration source backups use 0600. [The Phase 4 installer](installation.md) provisions the complete managed
layout with separate radio and monitor ownership. State and runtime directories may be identical to preserve an
existing locking arrangement. Every process and DTMF wrapper must use the same
configuration and lock paths; do not mix old and new application processes.

TOML changes require restarting the affected development processes. Favorites
changes do not. Configuration is inherited by dashboard-launched scanner commands
through the process environment; the same interpreter (`sys.executable`) is used.
No command-line arguments were added to or removed from `scanner.py`.

## Favorites authority and live updates

`state_dir/favorites.json` is the only authoritative store. Each entry contains
exactly string fields `node` and `name`; entries remain in priority order. There
are at most 250 unique nodes. Existing valid JSON descriptions are preserved
exactly, including Unicode, quotes, backslashes and surrounding spaces. Interactive
add/edit continues the existing whitespace trimming behavior.

Writes validate the complete replacement, serialize under a shared flock, write
and fsync a temporary file, atomically replace JSON, and fsync the directory.
Readers see complete old or new JSON. There is no generated favorites INI.
External tools editing the store must use the same lock and atomic-write protocol;
prefer the application's favorites management interface once secured.

The monitor rereads JSON each loop and retains records for unchanged nodes; an
invalid/transient reload retains its prior list and records. Phase 2B also restores validated observations across process restarts; see
[activity monitoring](activity-monitoring.md). Dashboard and scanner use the current store
for ordering, names, and membership; cache files supply statistics only. Newly
added nodes appear without waiting for a cache rebuild but remain unknown and
ineligible for FIRST/NEXT until fresh eligible statistics arrive. A removed node
is excluded even if it remains in a previous activity cache snapshot.

## Safe migration

Prefer an existing `favorites.json`: it preserves descriptions without guessing
which trailing label text is a node suffix. Supply an explicit source path. The
tool never searches a production machine or reads AllScan deployment paths.

Preview against a new local development destination:

```sh
python3 -B migrate_favorites.py --source /absolute/local/copy/favorites.json --destination /absolute/local/dev-state/favorites.json
```

After reviewing the preview, repeat with `--apply`. If `--destination` is omitted,
the configured state directory is used; review that configuration before applying.
Dry-run creates no directory, lock, backup, or destination. Apply validates first,
backs up the exact source bytes into a unique `favorites-source-*.bak` file beside
the destination, then atomically publishes without overwriting an existing file.
The source is never changed. Repeating an identical import is a no-op. A different,
corrupt, or symlink destination is refused. Failure leaves the source and existing
destination intact; a backup can remain if publishing fails. Review the backup
and retry rather than deleting existing data automatically.

For an INI source, use `--format ini` and, when needed, `--local-node YOUR_NODE`.
The tool reads [general] plus that node's section in file order. It decodes only
quote/backslash escapes, preserves Unicode, and removes a trailing node suffix
from labels as generated by the old favorites writer. Other descriptions remain
unchanged. Duplicate nodes, malformed/unpaired entries, unsupported commands,
invalid names, and excess favorites cause an explicit failure, not silent loss.
Unrelated sections are not imported. Inspect the source for node-specific sections
before choosing a node; resolve conflicts in a separate copy, retaining the original.
The historical `parse_original` helper retains its old deduplication semantics for
compatibility, but is not used by the migration tool or any runtime consumer.

To initialize an intentionally empty store, import `config/favorites.example.json`
with an explicit local destination and `--apply`. A missing store is otherwise an
error; application startup never silently replaces or initializes existing data.

## External sources and intervals

Monitor URL template, polling interval, freshness/activity windows, and request
timeout are configurable. Keep one `{node}` placeholder in the statistics URL.
Increasing favorite count increases revisit time (at least favorites * polling
interval, plus network latency); 75 favorites already reach the default five-minute
freshness window. Phase 2B and its retry-scope follow-up add shared/per-node backoff, size limits and restart-safe history; see
[activity monitoring](activity-monitoring.md) for the added keys and behavior.

NetWatch and AllStar Nets each have `enabled`, HTTPS `url`, HTTPS `details_url`,
cache age, and request timeout. `details_url` must end in `/` and have no query.
Both sources default off. Disabled updaters do not fetch or change caches;
dashboard ignores disabled-source caches. Enable either independently. With both
enabled, fresh NetWatch data takes priority, followed by fresh AllStar Nets data.
With neither enabled, favorites monitoring/controls continue and Nets reports no
cached schedule. A stale source no longer authorizes new Nets connects. The Nets
UI, upcoming display, disconnect, and Add to Favorites remain present.

Fallback duration is configurable from 1 to 240 minutes. URLs and cache-age limits
flow into the UI without exposing filesystem paths or the full configuration.
Updater invocation/timing remains external; this phase does not install timers.
There is no NetLogger polling.

## Preserving existing behavior and upgrades

An equivalent data/monitor configuration uses the existing local node, Asterisk binary, bind/
port, data directories and timing values, enables currently used schedule sources,
and enables controls only after the Phase 3 administrator and privilege-separation
prerequisites are configured. Legacy in-process unauthenticated web operation is
not supported. In particular, the new default state/cache paths differ from the legacy
layout. To reuse legacy favorites JSON, configure state_dir to its directory;
to use a new layout, migrate a local copy explicitly. Copy any desired schedule
caches separately or regenerate them with enabled updaters in the development
layout. Legacy NetWatch cache can be regenerated in the shared cache directory.

An upgrade replaces source code only. Retain private TOML, authoritative favorites,
selection state, and backups outside the source tree; do not copy example data
over them. Load/validate the retained configuration and run migration dry-run
before switching versions. Do not run mixed versions against the same store:
legacy code still writes/reads INI. The [Phase 4 lifecycle tool](installation.md) implements these preservation rules
for its managed layout; unmanaged installations require explicit reviewed imports.

## Apache URL prefix and proxy transport

The preferred optional installer integration is described in [network access](network-access.md).
`web.url_prefix` defaults to an empty string for existing standalone deployments;
Apache mode sets `/hubscanner`. It must be one safe path component without a
trailing slash. API paths in documentation are relative to this prefix. Cookies
are scoped and named independently in prefix mode. Backend requests must retain
the prefix; a proxy that strips it is incompatible with that setting.

`web.http_proxy_origins` defaults empty. Apache HTTP selection deliberately adds
its exact origin, also present in allowed_origins, enabling the private-client
HTTP exception behind the explicitly trusted loopback proxy. Do not use this to
trust arbitrary forwarding headers. HTTPS origins use the existing trusted-proxy
transport and Secure cookies. All other auth and broker configuration is retained.

## Phase 1 web administration (0.6.0-beta)

Authenticated administrators can change only `web.refresh_seconds` (5, 10, 15,
30 or 60; an existing nonstandard value may be retained), `web.controls_enabled`,
`web.anonymous_view`, `schedules.netwatch.enabled` and
`schedules.allstarnets.enabled` in **Admin**. All other fields remain intact.
No new configuration keys are required. The ordinary upgrade still preserves
configuration bytes and administrator credentials. Saving through Admin uses
atomic replacement preserving ownership/mode and all unedited values; TOML
comments and formatting are rewritten. Keep an operator copy if comments matter.

Changes are serialized with radio operations and package lifecycle operations;
a busy operation returns a retry message rather than interrupting a command.
Conflicting edits require Reload before Save. Controls/anonymous-view changes
reach the server immediately and other dashboards on their next refresh. Refresh
changes do not change upstream polling. Disabling controls retains the existing
maintenance policy that blocks favorites mutations as well as radio commands;
Admin itself remains usable. No existing link is disconnected by this switch.

Source switches reconcile only the two existing timers and retain cached nets.
A failed operation restores the prior configuration and timer state; an unresolved
rollback is recorded for recovery and prevents further updates. Other configuration
settings, including node, proxies, Apache and firewall, remain outside Admin.
Manual configuration edits still require the usual validation/restarts for fields
outside these five supported live settings.

## Advanced Admin settings (0.7.0-beta)

[The Phase 2 guide](admin-advanced.md) defines supported node selection, cooldown,
polling/freshness ranges and actual timer semantics. Existing TOML keys are reused;
there are no mandatory new keys or configuration schema changes. Schedule frequency
is stored as owned systemd timer drop-ins, not invented TOML polling options.
The configuration revision now covers those files as well as TOML, so stale browser
edits cannot overwrite another administrator's schedule change. Unedited fields,
credentials, ownership and modes retain Phase 1 protections.
