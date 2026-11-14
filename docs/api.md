# HTTP API (Phase 3)

The API is same-origin and has no CORS allowlist. It defaults to local loopback
access with private viewing. See [security.md](security.md) for the trust model,
TLS proxy settings, limits and service identities.

In managed Apache mode prepend `/hubscanner` to every route below (for example
`GET /hubscanner/api/session`). Standalone root mode keeps the listed paths.
Browser code uses the configured prefix, and cookies are scoped to that prefix.
Never infer a prefix from untrusted forwarded headers.

## Authentication sequence

1. `GET /api/session` obtains an unprivileged HttpOnly cookie and a JSON `csrf`
   token. Retain the cookie in a private cookie jar, not a URL or application log.
2. `POST /api/auth/login` sends a JSON object with `username` and `password`, plus
   `X-CSRF-Token` from step 1 and the cookie. Use HTTPS for remote access; the explicit trusted-LAN HTTP opt-in is unencrypted (see [network access](network-access.md)). Never
   put credentials in query strings, command arguments, shell history or logs.
3. On success, replace the cookie and CSRF token with the rotated values. The
   response contains `authenticated` and `csrf`, not the opaque session ID.
4. For each mutation, send `Content-Type: application/json`, the administrator
   cookie and `X-CSRF-Token`. Browser Origin must match the exact request origin;
   non-browser clients may omit Origin but cannot omit cookie/CSRF.
5. `POST /api/auth/logout` with an empty JSON object revokes the cookie. The old
   token cannot be used for subsequent requests.

There are no bearer API keys or forwarded-user authentication modes. Anonymous
viewing does not authorize API mutations. An authenticated session also needs the
`controls_enabled` maintenance switch on for radio/favorites writes. Session touch
and logout do not need this switch. Idle and maximum lifetimes still apply to API
clients; background reads do not prolong authentication.

## Routes

| Method and route | Access and result |
| --- | --- |
| GET / or /login | Login page, or dashboard for an authorized/explicit anonymous viewer |
| GET /api/session | Session bootstrap/status; authenticated, csrf, transport_safe, unencrypted_lan |
| POST /api/auth/login | Pre-login session + CSRF; username/password; rotates cookie/token |
| POST /api/auth/logout | Administrator + CSRF; `{}`; revokes session |
| POST /api/session/touch | Administrator + CSRF; `{}`; records explicit user activity |
| GET /api/activity | Administrator, or configured anonymous viewer; cached activity/schedule/retry diagnostics |
| GET /api/links | Administrator, or configured anonymous viewer; broker-cached links ID array plus structured link_states |
| GET /api/favorites | Administrator; authoritative ordered favorites |
| POST /api/favorites | Administrator + CSRF + maintenance switch; mutated ordered favorites |
| POST /api/control | Administrator + CSRF + maintenance switch; requested radio operation result |

Radio request shape is `{"action":"first"}`, `{"action":"next"}` or
`{"action":"stop"}`. A null node may be present for these existing UI calls.
Individual requests use actions `connect-node`/`disconnect-node` and a string
`node`. Nets requests use `connect-net`/`disconnect-net` and a string `node`.
No extra fields, executable paths or raw commands are accepted. Destinations are
validated against favorites/schedules/selected-state policy, not just digit syntax.

Favorites actions are `add`, `edit`, `remove`, `up`, `down`. Each uses a string
`node`; add/edit also require a string `name`. An unused name from the existing UI
is permitted for reorder/remove. Names, uniqueness and count limits remain as in
[configuration.md](configuration.md). Successful writes return `favorites` with
the new order and names. The monitor reloads that authoritative store live.

Body size is capped at 4 KiB. Bodies must be JSON objects with one unambiguous
Content-Length, no Transfer-Encoding, no duplicate keys and no nonfinite constants.
The former X-Scanner-Control header alone is never sufficient authorization.

## Responses, cooldown and failure handling

Errors return a sanitized JSON `message`. Typical statuses are 400 for malformed
requests, 401 for missing/expired login, 403 for CSRF/origin/role/destination or a
disabled mutation switch, 415 for non-JSON, 429 for limits/busy/cooldown, 503 for
unavailable data/control service, and 504 for a scanner command timeout.
429 responses include Retry-After; honor it and avoid automatic tight retries.

Radio commands share the configured 15-second default cooldown and a command lock.
Failed accepted attempts also consume cooldown. Connect/FIRST/NEXT success reports a confirmed sole destination, an already-only
no-op, or no eligible destination. Disconnect/STOP confirms the applicable link
is absent. See [application link transitions](link-transitions.md). A timeout
or state-write error can still occur after a command was submitted; inspect direct links
before deciding whether to retry. `GET /api/links` is cached for five seconds to
bound Asterisk queries, and can briefly lag an actual change.

Login attempts are limited per client and globally before hashing; expensive hashes
are serialized. Sensitive operations share an administrator bucket across sessions.
General read/request limits apply per validated client address. See security.md for
all configurable limits. These web/API limits are separate from upstream statistics
429 backoff, documented in [activity-monitoring.md](activity-monitoring.md).

## Link-state metadata

GET /api/links retains `links` as present node-ID strings and adds `link_states`
records with node, mode, keyed, state and raw suffix. C is connecting, T/R is
established, and unsupported metadata is unknown. Presence is not establishment.
See [connection-state safety](connection-state-safety.md). Empty status returns
both arrays empty. The display cache is not used for transition confirmation.

`transport_safe` is the historical compatibility field indicating whether the
configured transport policy permits sign-in. It is also true for explicitly
opted-in LAN HTTP; it does not certify encryption. `unencrypted_lan=true` identifies
that exception so the login page can show the cleartext warning. Secure cookies
remain limited to HTTPS; sessions created through HTTPS cannot be reused on HTTP.

The activity response's favorite records may include `node_description`, a bounded
cached AllStarLink directory string independent of `name` (the custom favorite
name). Its presence does not imply fresh statistics or current RF activity.
It is display-only metadata: do not send it in favorites mutations. The Favorites
management API/store continues to use only node/name. See
[node-directory caching](activity-monitoring.md#node-directory-descriptions).
