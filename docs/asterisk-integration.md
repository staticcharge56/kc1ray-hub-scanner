# Application controls and existing local CLI

Hub Scanner now manages disconnect-before-connect within its own shared radio
code and restricted broker. See [link transitions](link-transitions.md) for the
policy, confirmation, STOP scope, cooldown and limitations.

No Asterisk connection hook, single-link.sh edit, rpt.conf change or DTMF mapping
is required or supplied. Existing public-node connection policies are not modified
or replaced. Do not add connpgm/discpgm callbacks or new mappings for this feature.

The trusted local CLI retains exactly these action names and argument ordering:

```text
/usr/bin/python3 -B -E -s /opt/kc1ray-hub-scanner/current/scanner.py first [--apply]
/usr/bin/python3 -B -E -s /opt/kc1ray-hub-scanner/current/scanner.py next [--apply]
/usr/bin/python3 -B -E -s /opt/kc1ray-hub-scanner/current/scanner.py stop [--apply]
```

Existing mappings and scripts that already call that interface can retain their
commands. No mappings, sudoers rules, wrappers or digits have been installed or
changed. The intended execution identity remains the dedicated radio account;
do not grant the web user Asterisk privileges or broaden the broker's peer UID.
Trusted local --apply calls now share the broker's 15-second cooldown and locks,
with nonblocking busy rejection. Without --apply the CLI only reports selection,
opens the scanner lock and submits no Asterisk queries or radio commands.

Configuration of restricted Asterisk socket access is a separate operator-reviewed
prerequisite, documented in [socket access](asterisk-socket-access.md). The app never
changes that configuration itself. Keep any existing operator integrations outside
the application's files unchanged; coordinate external callers before upgrade or
rollback because runtime locks are recreated. Test new application behavior only
on a separately authorized spare with physical RF inhibition and approved remote
endpoints. No production or spare Pi was accessed during development.
