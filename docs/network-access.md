# LAN access, optional HTTPS and troubleshooting

## Preferred: existing Apache at /hubscanner/

The installer detects a running Apache2, validates its current configuration and
checks proxy, proxy_http, headers and rewrite modules. Active includes/listeners
are inspected read-only, and existing HTTPS hosts must pass a local TLS negotiation
without sending credentials or generating certificates. It reads `apache2ctl -S`
for existing HTTP/80 and HTTPS/443 hosts; it does not enable modules, add a new
virtual host, alter listeners or generate certificates. Incompatible/absent Apache
leaves standalone mode available. Inspection lists `apache_sites`; a compatible
Apache on a fresh installation prompts an explicit access-method choice rather
than silently publishing a route. Noninteractive execution must choose a method.

Preview an example using identifiers actually reported by your target:

```sh
sudo sh ./install.sh install --node 1000 --web-access apache \
  --apache-vhost /etc/apache2/sites-enabled/000-default.conf:1 \
  --apache-origin http://192.168.50.10
```

Replace all example values. `--apache-vhost` is the exact file:line identifier from
the active dump. If multiple hosts exist, explicitly choose; at most one host per
HTTP/HTTPS port can be selected. Repeat the option for an existing HTTPS host and
repeat `--apache-origin https://scanner.example.org` for its browser address.
An origin contains only scheme and hostname/IPv4, with no path, trailing slash or
explicit default port. If omitted it uses the host's canonical ServerName; for
an ASL3 default host named localhost/127.x, explicitly supply the desired LAN IP.
An origin must map to that host's canonical name, exact alias or unambiguous default
host. Duplicated names, wildcard routing ambiguity and unsupported layouts fail
closed rather than selecting another site. Use the exact configured origin in
the browser; additional aliases are not implicitly authorized.

After reviewing `web_access`, `apache`, `web_policy` and `firewall` in the dry run,
repeat with `--execute` under separate authorization. Browse the selected origin
plus `/hubscanner/`. The backend is fixed to 127.0.0.1:8085 in this mode; other
backend ports are refused. Firewall management adds no port 8085 rule and removes
only old scanner-owned standalone rules when switching to Apache. Existing Apache
ports/firewall reachability remain the operator's responsibility.

The installer creates only `/etc/apache2/conf-enabled/kc1ray-hub-scanner.conf`,
root-owned mode 0644, loaded by Debian's existing conf-enabled include. Existing virtual hosts and AllScan are never rewritten.
The snippet uses a LocationMatch restricted to `/hubscanner` and `/hubscanner/`,
with host/port conditions scoped to selected routes, and a fixed loopback proxy
target. Nonselected virtual hosts and `/allscan/` do not match. A separate candidate
is syntax-tested before activation, then the active configuration is checked and
Apache gracefully reloaded. There is no restart, new listener or broad ProxyPass
for `/`. The original site's redirects and access controls remain in force.

The prefix is an explicit backend setting (`web.url_prefix="/hubscanner"`), not a
forwarded-header hint. UI API calls, login/logout navigation and cookies use that
prefix. The proxy forwards it unchanged. Cookies use distinct HTTP/HTTPS names and
Path=/hubscanner/ to avoid old standalone sessions and insecure cookie reuse when
both protocols are selected; switching to HTTPS requires a separate sign-in. Existing sessions are revoked
on the normal web restart; operator credentials/favorites are retained.

Apache overwrites X-Forwarded-For with the actual connection peer (CONN_REMOTE_ADDR),
independent of incoming forwarding headers or mod_remoteip rewrites, and
X-Forwarded-Proto with the real request scheme; it disables proxy header appending
and strips untrusted alternate forwarding headers. The backend trusts only
127.0.0.1/32 and the selected exact origins. HTTPS uses Secure cookies. Selecting
an HTTP host explicitly permits unencrypted admin access through this trusted
loopback proxy only for RFC1918 clients (or genuine loopback access). Public HTTP
clients cannot sign in; use an existing HTTPS host for remote access. Authentication,
CSRF, expiry, limits, broker ownership and radio safeguards remain mandatory.
Selecting a publicly reachable HTTPS host exposes the login route to that host's
existing audience; review its network/access policy before execution.

A root-only ownership ledger records snippet hashes and selected hosts before
activation. Unknown files at the reserved path, modified managed files and missing
managed configurations block changes. No operator file is adopted or overwritten.
Do not edit the generated snippet; use installer selection or review custom
integration separately. Snapshots include Apache ownership metadata; failure,
rollback and uninstall restore/remove only that owned snippet and reload Apache.
Older snapshots without Apache metadata restore no owned integration. Recovery
uses the updated installer and preserves transaction evidence on failure; an older
installer cannot manage new Apache metadata. Original site/certificate files are
outside app backups because the app never changes them.

Existing managed installations keep their access method during ordinary upgrades.
To opt into Apache, use the new reviewed source's `upgrade --web-access apache`
with explicit host selections/origins. Only web routing settings are deliberately
updated; passwords, favorites, NetWatch, cooldown and identities are retained.
`upgrade --web-access standalone` removes the owned snippet and resets prefix/proxy
trust; the backend remains localhost unless the operator deliberately configures
a private LAN bind/origin/HTTP policy in the retained TOML before that plan.
A retained-data reinstall revalidates and restores the previous managed Apache
selection without resetting operator data; purge removes that retained intent.
Ordinary upgrades revalidate the selected active hosts. If host IDs change after
operator edits, select the new reported IDs explicitly rather than guessing.

Limits: supported Debian include layout is `/etc/apache2/conf-enabled/*.conf`;
only wildcard listener/vhost layouts on standard HTTP/80 and HTTPS/443 are
offered; custom/address-specific listeners require manual integration review. No certificate provisioning,
URL alias discovery beyond exact Apache dump aliases, wildcard host mapping or
custom listener support is promised. Existing rewrites/auth policies can still
redirect or deny the path; the installer does not relax them. Test the actual
selected site, HTTPS cookies and reboot/lifecycle behavior on the spare. Local
isolated Apache tests do not certify the real server's configuration.

Troubleshooting: a 404 can mean wrong host, unselected HTTPS after an HTTP redirect,
changed dump ID or missing prefix. A 403 can mean exact-origin/transport policy,
private HTTP client restrictions, Apache access control or maintenance mode.
Check `sudo apache2ctl configtest`, `sudo apache2ctl -S`, the owned snippet and the
web journal. A 503 can mean the loopback backend is down. Do not solve these by
opening port 8085, disabling authentication or broadening trusted proxies.

## Standalone LAN workflow (alternative)

Use a specific private LAN IPv4 address deliberately selected by the operator.
Run `sudo sh ./install.sh inspect` on the authorized Debian 12 ASL3 target and
review `lan_candidates` (address and interface). Discovery only reads local
interface metadata using `ip`; it sends no network probes. Only up physical
interfaces with RFC1918 addresses are offered. It does not guess which network
you trust. VPN, container, CGNAT and public addresses are not offered. Some bridges,
VLANs and virtualized LAN interfaces need a separately reviewed manual TOML setup.

For example, replace both placeholders with your actual detected values:

```sh
sudo sh ./install.sh install --node YOUR_NODE --web-access standalone --port 8085 --bind YOUR_LAN_IP
```

Review that read-only plan before adding `--execute`. During interactive fresh
installation, leaving the address selection empty keeps localhost. Noninteractive
installation without `--bind` also keeps localhost. Never select `0.0.0.0` for this
workflow. The installer tests the selected address/port, refuses unoffered binds,
and never configures routers or public forwarding. If firewalld is running, it
manages a tracked rule restricted to the selected LAN subnet, destination address
and TCP port; it does not modify other rules or alternative firewalls. Reserve the
chosen address in your router's DHCP configuration to avoid later address changes.

A selected LAN address writes this policy (illustrative address only):

```toml
[web]
bind = "192.168.50.10"
port = 8085
allow_lan_http = true
allowed_origins = ["http://192.168.50.10:8085"]
trusted_proxies = []
anonymous_view = false
controls_enabled = false
```

Open exactly `http://192.168.50.10:8085` in a browser on your trusted LAN and sign
in using your administrator account. No default password exists. Radio and
favorites writes remain disabled until you deliberately enable controls as
explained in [installation](installation.md). Do not change Asterisk configuration,
DTMF commands, hooks or single-link.sh to enable application controls.

**Plain HTTP does not encrypt credentials or sessions.** A person or compromised
device able to observe/alter LAN traffic may steal the password or session and
operate your node. Use a trusted LAN only; use HTTPS on shared or untrusted networks.
The opt-in allows administrator HTTP only at the exact configured bind/port origin
and from RFC1918 clients; private addressing is not proof that a network is safe.
Authentication, CSRF, expiry, rate limits, HttpOnly and SameSite=Strict remain
required. Secure cookies cannot work over HTTP; HTTPS sessions receive Secure
cookies and cannot be downgraded to HTTP. Never port-forward the HTTP dashboard.

## Localhost fallback and optional HTTPS

Without selection, `127.0.0.1:8085`, `allow_lan_http=false`, empty trusted proxies
and private viewing remain the defaults. Access it locally or through an SSH
local-port tunnel, e.g. `ssh -L 8085:127.0.0.1:8085 USER@PI`, then browse
`http://127.0.0.1:8085`. SSH encrypts the tunnel; it does not add HTTPS in the browser.
Existing upgrades/reinstalls retain their settings rather than enabling LAN HTTP.

HTTPS is optional and independent of a particular vendor. Use a TLS-terminating
reverse proxy with a valid certificate, keep the backend on loopback where possible,
and configure the exact external origin and actual proxy peer:

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

Replace the example origin and peer with your deployment. Preserve the external
Host and overwrite X-Forwarded-Proto; optionally overwrite X-Forwarded-For with
one client address. Strip client-supplied forwarding headers. Do not trust an
entire LAN as a proxy. Untrusted forwarded headers and identity headers never grant
administrator access. Restrict backend reachability to the proxy. Built-in login
and CSRF remain required, even with an authenticated proxy. See [security](security.md).

Tailscale is an optional remote-network choice. Tailscale Serve can supply an
HTTPS reverse proxy within a tailnet; configure the same explicit origin/peer
policy. No Tailscale service, Funnel or public forwarding is configured by the
installer. See [Tailscale Serve documentation](https://tailscale.com/docs/features/tailscale-serve).

44Net Connect is another optional connectivity choice. It supplies WireGuard
connectivity and routable 44Net addresses, as described by the
[44Net Connect documentation](https://wiki.ampr.org/wiki/44Net_Connect).
It does **not** terminate HTTPS for the Hub Scanner. WireGuard tunnel encryption
is not browser-to-dashboard HTTPS and does not encrypt traffic beyond tunnel
endpoints. Plan routing and access restrictions explicitly, and supply a separate
HTTPS reverse proxy/certificate if exposing the dashboard remotely. A 44Net address
is not an RFC1918 trusted-LAN address; the installer does not offer it as a LAN bind.
Do not treat routable addresses as private or enable anonymous controls.

## Troubleshooting

- **No LAN address offered:** check `ip -4 address show up`; confirm the interface
  has an RFC1918 address and a physical device. Missing iproute2, malformed discovery
  output or unsupported virtual interfaces fall back to localhost. Do not substitute
  a wildcard. Review a manual configuration separately if necessary.
- **Address/port unavailable:** confirm the address still belongs to the Pi and
  inspect `ss -ltn`. A DHCP change requires deliberate bind/origin updates. The
  installer never stops unknown services to free a port.
- **403 Host/protocol not permitted:** use exactly the allowed origin, including
  port. An IP origin does not authorize a hostname alias. If using a hostname,
  explicitly add its origin and use HTTPS for administrator access; the LAN HTTP
  opt-in intentionally permits only the configured numeric bind origin.
- **Sign-in says HTTPS required:** LAN HTTP needs all three explicit settings:
  private bind, its exact allowed HTTP origin, and allow_lan_http=true. Public or
  CGNAT clients cannot use this opt-in. Otherwise configure HTTPS or localhost;
  do not add broad trusted proxies or enable anonymous viewing to bypass login.
- **HTTPS proxy fails or cookies lack Secure:** check the actual proxy peer,
  exact HTTPS origin, Host and overwritten protocol header. Never trust arbitrary
  forwarding headers to solve a mismatch. Secure sessions cannot be reused on HTTP.
- **Controls unavailable:** sign in, review controls_enabled, broker readiness and
  cooldown. Restart affected app services after TOML edits. Never grant the web
  account Asterisk membership or loosen the Unix socket.
- **Schedules missing:** enable the source in TOML and its corresponding timer;
  see installation instructions. Favorites reload live without a restart.
- **Keep Screen Awake unavailable:** many browsers require an HTTPS secure context
  for Screen Wake Lock on LAN addresses. The dashboard retains feature detection
  and reports the restriction. Use HTTPS or the device's display settings.

For existing installations, back up the private TOML before editing and restart
only the affected scanner services (web for transport, broker for control policy).
No changes to Asterisk or RF settings are needed. Keep private logs and credentials
out of public troubleshooting reports.

## Installer-managed firewalld rules (0.5.1-beta)

A LAN dry run includes `firewall`: status, discovered interface/subnet/zone, desired
rules, and additions/removals. With a selected physical RFC1918 address the installer
uses that interface's active firewalld zone, not a guessed default zone. An unknown
zone, ambiguous address, unavailable prefix, conflicting pre-existing rule or
failed firewall operation stops the lifecycle with an error. No public/VPN subnet
is inferred. The connected subnet is treated as the explicitly selected trusted
LAN; review its width in the dry run before executing.

For an illustrative eth0 address 192.168.50.10/24 in zone allstarlink and port 8085,
the rule allows IPv4 TCP only from 192.168.50.0/24 to 192.168.50.10/32:8085. It uses
positive rich-rule priority 32760 so it does not override existing earlier deny
rules. A broader operator rule or source-based zone policy can affect reachability;
the installer does not weaken those policies or promise browser connectivity.

Permanent and runtime rich rules are updated individually and verified; no global
reload or runtime-to-permanent operation is needed. This preserves unrelated
runtime-only settings; [firewalld documents that reload replaces runtime settings](https://firewalld.org/documentation/man-pages/firewall-cmd.html).
ASL3, Cockpit and SSH rules are never edited, and no global port/service opening
is used. Localhost installs add no firewall rule. Upgrading to localhost removes
only previously tracked scanner rules. Without installed/running firewalld no
firewall is installed or substituted; check any operator-managed firewall yourself.
If scanner-owned rules already exist, firewalld must run to remove/reconcile them.

Ownership is recorded durably in the root-only package registry's firewall.json
before mutation. Repeated upgrades query existing rules rather than duplicating
entries. Changes to port, interface, zone, subnet or bind remove obsolete owned
rules and ensure the desired restricted rule. Matching pre-existing permanent and
runtime rules are used without ownership; uninstall leaves them untouched.
A pre-existing match in only one configuration requires operator review rather
than silently adopting it. Do not manually edit the ownership ledger or mutate
the same exact rule concurrently during a lifecycle transaction.

Snapshots include the tracked rule set. Automatic recovery and explicit rollback
reconcile it along with files/service states; older snapshots without firewall
metadata mean no scanner-owned rules. Normal uninstall/purge removes only tracked
rules and retains unrelated rules. Keep the updated installer source for recovery
of snapshots created by this release: an older installer cannot reconcile the new
firewall metadata. If firewalld is unavailable during recovery, the operation
reports failure and retains its transaction evidence for repair/retry.

Use read-only checks such as `sudo firewall-cmd --get-active-zones`,
`sudo firewall-cmd --zone=allstarlink --list-rich-rules` and the same list command
with `--permanent`. Use your detected zone. Verify the browser from an allowed LAN
client after installation; never diagnose with an unrestricted open-port rule.
