# ASL3 Asterisk control-socket access

The reported ASL3 22.10.1 setup has `/run/asterisk/asterisk.ctl` owned by
`asterisk:asterisk`, mode **0755**, with `/run/asterisk` owned by `asterisk:root`,
mode **0755**. This is recognized as an owner-access configuration. Linux Unix
stream connections require socket write access; the executable bits do not grant
connection access. The Asterisk owner can connect, but adding a different UID to
the asterisk group does not help while that group lacks write permission.

The installer now explains this condition and stops. Recognition is **not** an
exception to the security policy. It never chmods/chowns the socket, edits
asterisk.conf, reloads/restarts Asterisk, adds the web UID to Asterisk, or runs the
web interface as Asterisk/root. The reported 0755 `asterisk:root` directory can
remain unchanged: its traversal permission is sufficient with the restricted
socket below. Do not recursively change directory ownership/permissions.

## Operator-reviewed configuration (not an automatic installer action)

Perform only on the spare test system during a separately approved maintenance
window, with physical RF inhibition in place. Keep the production installation untouched.
Asterisk restart interrupts existing calls and recreates its socket; account for
other consumers and callbacks before authorizing it.

1. Record the current socket/directory metadata, active Asterisk service identity,
   node configuration hashes and the current effective Asterisk configuration file
   location (including any service `-C` override). Preserve a private root-only
   backup of that configuration and its metadata. Do not print secrets or copy
   production settings onto the spare.
2. Manually review the existing **[files]** section in `/etc/asterisk/asterisk.conf`
   (or the actual configured main file). Uncomment/update the three applicable
   settings in that section, preserving unrelated settings and includes:

   ```ini
   [files]
   astctlpermissions = 0660
   astctlowner = asterisk
   astctlgroup = asterisk
   ```

   Do not append competing sections/options blindly. Leave `astctl`, `astrundir`,
   the service's existing `-U asterisk`, node numbers, rpt.conf, DTMF and hooks
   unchanged. The owner/group above fit the reported spare; a different supported
   nonroot socket group requires review of its memberships and privileges.
   Asterisk documents these directives in the
   [main configuration file reference](https://docs.asterisk.org/Configuration/Core-Configuration/Asterisk-Main-Configuration-File/).
3. Only after the maintenance restart has been explicitly approved, use the spare's
   normal Asterisk service restart procedure. A config reload must not be assumed
   to recreate the control socket. This document and installer do not execute the
   restart. A one-time chmod is not a persistent configuration solution.
4. Recheck read-only, without submitting radio commands:

   ```sh
   systemctl is-active asterisk.service
   sudo stat -c '%F %U:%G %a %n' /run/asterisk /run/asterisk/asterisk.ctl
   sudo namei -l /run/asterisk/asterisk.ctl
   sudo sh ./install.sh inspect
   sudo sh ./install.sh install --node YOUR_TEST_NODE --port 8085
   ```

   Replace the node placeholder with the spare's existing test node. Do not add
   `--execute` until installation is separately approved. Expect a real socket
   `asterisk:asterisk 660`, the existing traversable directory, and passing static
   inspection. If the mode/owner/group reverts, inspect the active configuration,
   includes, service overrides or other permissions managers; do not patch files
   automatically or broaden access to make the check pass.

No existing Asterisk configuration changes have been performed in developing
this fix. Hardware verification of the operator's resulting setup remains pending.

## Policy and effective-access verification

Static inspection requires a real socket (no symlink), a real directory without
world write, an existing nonroot/nonprivileged socket group, socket owner/group
write, no other-user access and no special mode bits. Recommended socket mode is
0660; narrower owner/group permissions can work if the effective checks pass.
Directory group `root` at mode0755 is not the same as a root-owned socket group:
the former permits traversal without granting root membership.

Groups root/sudo/adm/disk/shadow/docker/lxd and the application's shared groups
kc1ray-read/kc1ray-control/kc1ray-web are refused as the Asterisk socket group.
Missing, regular-file or symlink sockets, missing group write (including 0755),
world-accessible sockets, unsafe directories and unknown groups fail closed.
ACL grants do not override this static restricted-mode policy.

During an explicitly executed install/upgrade, after provisioning and validating
the identities, the installer runs two checks using **runuser -u kc1ray-radio**:

1. An isolated Python process confirms its real/effective UID is the configured
   named radio account, opens an AF_UNIX stream connection to the standard socket
   with a five-second timeout, and closes it **without sending a CLI command**.
   This exercises actual directory traversal, group membership and ACL effects.
2. The existing Asterisk CLI performs only `rpt show variables NODE`. Both a zero
   exit status and a real `RPT_ALINKS=` output line are required. A successful
   connect without a readable configured node is insufficient.

These checks use the managed service account's primary and supplementary groups,
matching the broker unit's role. They precede staging/switching and application
service activation. No connect/disconnect/DTMF command is issued. Command processes
retain the installer's bounded timeout. Failures keep raw command diagnostics out
of the returned error, explain the radio-access failure after managed rollback,
and prevent the candidate from starting. Previously active application units are
restored on an upgrade failure. Newly allocated locked identities are retained
under the existing recovery policy, never replaced with privileged fallbacks.

Only **kc1ray-radio** receives the existing Asterisk socket group among the three
application identities. Web has read/control groups only; monitor has read only.
The broker's separate UID-checked Unix socket and all web auth/CSRF protections
remain unchanged. Asterisk's own account and pre-existing operator memberships
are neither removed nor changed by the installer; administrators should review
those memberships separately.

If accounts already exist from an approved managed attempt, these manual checks
can be performed read-only after review (do not manually create accounts to run
preflight):

```sh
id kc1ray-radio
id kc1ray-web
id kc1ray-monitor
sudo runuser -u kc1ray-radio -- /usr/sbin/asterisk -rx 'rpt show variables YOUR_TEST_NODE' | sed -n '/^[[:space:]]*RPT_ALINKS=/p'
sudo runuser -u kc1ray-web -- test -w /run/asterisk/asterisk.ctl
sudo runuser -u kc1ray-monitor -- test -w /run/asterisk/asterisk.ctl
```

The last two commands should exit **1** (denied), with no output. They are useful
negative checks, not substitutes for the actual radio connection/query or deployed
systemd sandbox tests. Do not share complete variable output or credentials.

## Recovery

If a separately approved manual Asterisk change fails, preserve diagnostics and
restore the exact prior private configuration/metadata through the operator's
maintenance procedure, then recreate the socket through an approved restart.
Expect Hub Scanner preflight to refuse owner-only 0755 again after that rollback.
Do not change node configuration or permanently weaken socket permissions.
Application lifecycle rollback does not restore Asterisk configuration, because
the application installer never owns or edits it. Follow installation.md for
managed transaction recovery; do not delete journals or backup sets to bypass a
failed access check. Old acceptance archives do not contain this fix; build and
validate a fresh reviewed package before another acceptance attempt.

## Local validation record

`python3 -B tools/check.py` passed **253 tests in 66.647 seconds** with local
socket access enabled, including 16 new regressions in `tests/test_asterisk_socket.py`.
Python, embedded JavaScript, shell and rendered systemd syntax checks passed.
Protected runtime hashes passed; no dashboard, monitor, scanner, favorites,
NetWatch, authentication or radio-command implementation changed.

Coverage includes the reported 0755 socket and 0755 asterisk:root directory,
restricted-mode success, missing group write, world/special bits, unsafe/shared
groups, non-sockets/symlinks, actual probe code against a temporary local Unix
listener with zero payload, runuser argument/UID policy, simulated traversal/ACL
or timeout failures, read-only node-query failures and safe fresh-install rollback.
No host account command or real Asterisk invocation runs in these tests. The
multi-UID runuser transition and Asterisk endpoint are modeled; actual ASL3 ARM64
access and systemd sandbox behavior still need the authorized spare-Pi acceptance
procedure. Neither spare nor production Pi was contacted. No deployment or new
acceptance archive was made by this change.
