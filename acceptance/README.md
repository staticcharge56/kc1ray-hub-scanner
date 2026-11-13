# Disposable Debian 12 acceptance environment

This harness is prepared for review; execution on this development host is
blocked by missing container/VM tooling and a single-UID user namespace. Its
installed-service assertions must pass before release. A passing local unittest
suite does not substitute for this run or for ASL3 hardware testing.

Use a **disposable Debian 12 VM with a snapshot**, or a dedicated test machine
with rootful Podman capable of booting systemd in a private container. Do not run
on an ASL production host. No host volumes, devices, network, Docker socket or
Asterisk configuration may be passed through. Build uses Debian package mirrors;
runtime has no external network. The image contains an explicitly fake
`asl3-asterisk` package and fixed synthetic node 1000. It cannot drive a radio.

Create a sanitized build context (a new directory outside the repository):

```sh
python3 -B acceptance/prepare.py /tmp/kc1ray-acceptance-context
cd /tmp/kc1ray-acceptance-context
podman build -t localhost/kc1ray-acceptance -f Containerfile .
podman run -d --name kc1ray-acceptance --network=none --systemd=always \
  --tmpfs /tmp localhost/kc1ray-acceptance
podman exec kc1ray-acceptance python3 -B /src/acceptance/installed.py
podman cp kc1ray-acceptance:/tmp/kc1ray-acceptance-results.json ./results.json
podman rm -f kc1ray-acceptance
```

Container boot/cgroup behavior depends on the test host; these commands have not
been executed here. Do not solve boot failures by sharing writable host cgroups,
host PID namespaces, host devices or production directories. Prefer a snapshot
VM if private systemd containers are unavailable. The runner refuses missing
image markers, non-Debian-12 systems, non-root execution, an undetected virtualization environment,
missing systemd PID 1, and nonempty application/Asterisk destinations. These
checks reduce accidents; a marker is not a sandbox.

The installed runner creates real users/groups, installs real application units,
starts real web/broker/monitor processes, uses the Unix socket with separate UIDs,
and sends HTTP requests. Asterisk alone is synthetic. It tests authentication,
CSRF, session expiry, favorites reload, control commands/cooldown, upgrade,
rollback and uninstall retention. It saves an assertion report even on failure.
No secrets or cookies are included in that report. Failure leaves the disposable
environment available for inspection; discard it afterward.

Offline regressions additionally cover API429/backoff, damaged history, net
schedule parsing, account provisioning failure and partial lifecycle rollback.
These are modeled tests, explicitly separate from installed acceptance evidence.
The installed runner is a smoke test, not comprehensive hardware/browser testing.
