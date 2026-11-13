# LAN access, optional HTTPS and troubleshooting

## Recommended personal-node workflow

Use a specific private LAN IPv4 address deliberately selected by the operator.
Run `sudo sh ./install.sh inspect` on the authorized Debian 12 ASL3 target and
review `lan_candidates` (address and interface). Discovery only reads local
interface metadata using `ip`; it sends no network probes. Only up physical
interfaces with RFC1918 addresses are offered. It does not guess which network
you trust. VPN, container, CGNAT and public addresses are not offered. Some bridges,
VLANs and virtualized LAN interfaces need a separately reviewed manual TOML setup.

For example, replace both placeholders with your actual detected values:

```sh
sudo sh ./install.sh install --node YOUR_NODE --port 8085 --bind YOUR_LAN_IP
```

Review that read-only plan before adding `--execute`. During interactive fresh
installation, leaving the address selection empty keeps localhost. Noninteractive
installation without `--bind` also keeps localhost. Never select `0.0.0.0` for this
workflow. The installer tests the selected address/port, refuses unoffered binds,
and never configures routers, firewall rules or public exposure. Reserve the
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
