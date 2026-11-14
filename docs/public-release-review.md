# Next beta review — 0.5.1-beta

## Status and evidence

The first public-release candidate is **0.5.1-beta**, as recorded in
packaging/release.json. All four data/configuration schemas and the package schema
remain version 1. The owner has approved MIT and the attribution
"Copyright (c) 2026 KC1RAY Hub Scanner contributors". Root LICENSE and the complete
notice in docs/license-and-attribution.md match. The latter is included by the
existing installer, which does not copy the root LICENSE.

The current increment adds preferred managed Apache routing at `/hubscanner/`
with explicit site/origin selection, a loopback-only backend, scoped HTTP/HTTPS
sessions, prefix-aware UI/API/navigation and recoverable owned configuration.
The completed firewalld and 8-character password changes are preserved. These
changes remain unstaged; the index still contains the reviewed 0.5.0-beta tree.

The full current suite passed **371 tests in 113.232 seconds** using
`python3 -B tools/check.py`, with no failures, errors or skips. Python, embedded
JavaScript, shell, systemd and Git whitespace checks passed. A real Apache process
using temporary configuration and loopback ports verified unchanged prefixed paths,
forwarding-header overwrite, nonselected-site content and AllScan-path coexistence.
Modeled tests cover selection, scoped firewall removal, no-op/custom-policy upgrades,
validation/reload failures, rollback, old snapshots, uninstall and retained-data
reinstall. HTTP parser tests cover prefixed auth, CSRF, cookie paths, Secure flags,
separate HTTP/HTTPS sessions, logout and maintenance mode. Original security and
radio-control regression tests remain in the suite.

Radio-control, monitoring, favorites, schedules and all seven service templates
are byte-identical to the original staged baseline. Existing settings keep their
values; new URL-prefix/proxy-HTTP keys default to standalone-safe behavior. The
80-file public allowlist and release version 0.5.1-beta are unchanged. No archive,
commit, remote, tag or publication was created; neither Pi was contacted. Real
system Apache/firewall/Asterisk configuration was never modified by development.

The owner reports prior 0.4.4 hardware acceptance; that and prior 336/352-test runs
are historical evidence. Actual installation on the spare's Debian 12 ARM64 ASL3
Apache, browser/HTTPS verification using its existing certificates, scoped firewalld
behavior and reboot/lifecycle acceptance remain unverified for this increment.
The local real-Apache fixture is not proof of that deployment's compatibility.
Use the updated installer for recovery of new Apache/firewall metadata. Custom
listeners, address-specific vhosts, wildcard aliases or external Apache includes
are refused for manual integration review; current automatic support is standard
wildcard HTTP/80 and HTTPS/443. No certificate is generated or virtual host replaced.

## Historical staging review (0.5.0-beta)

The original 0.5.0-beta local repository was initialized on branch main with no commits or
remotes. Exactly **80 files** are staged, matching the existing
packaging/public-files.txt allowlist. Staging contains source, installer, example
configuration, seven systemd templates, admin/migration tools, tests and synthetic
fixtures, acceptance tooling, documentation and LICENSE.

The index review checks the actual staged object bytes and file modes against the
allowlist and working files, rather than relying only on ignored-file patterns.
Results: staged/allowlist equality, staged/working-file equality, safe file modes,
secret-pattern review, local documentation links and `git diff --cached --check`
all passed at that review. There were no unstaged changes or nonignored untracked files. The prior Python/configuration/service-template bytes matched the original
pre-preparation baseline; current installer/security changes supersede that claim.

The 11 local historical source snapshots/runtime files are not staged. Neither
are credentials, private configuration, operator favorites/history, caches,
backups, archives, .git contents or environment metadata. Local copies are retained.
There are no symlinks, submodules, unexpected binary files or generated build files
in the index. No private-key block or recognizable access-token format was found.
These checks are not proof of absence of every possible secret; review the diff
again after any future edit.

Synthetic private-address examples (such as 192.168.50.10), test passwords/scrypt
fixtures and node IDs are deliberate documentation/test data, not operator
credentials. The verified 638901TU protocol fixture is not authorization to connect.
Public KC1RAY branding and configurable upstream service URLs are intentional.

## Provenance and third-party review

[License and attribution](license-and-attribution.md) records the review and the
unconfirmed origins. Python imports in approved files are standard-library/local;
no vendored dependency, downloaded JS/CSS/font, binary asset or separate upstream
implementation was identified. Host prerequisites retain their own licenses and
are not relicensed by MIT. External-service terms remain the operator's responsibility.

**Concern requiring resolution before publication:** ownership/authorship of the
original supplied code, inline HTML/CSS/JavaScript, contribution history and fixture
rights cannot be independently established from this source snapshot. MIT and
attribution approval is confirmed; source provenance is not. Do not claim a
complete chain of title or that all third-party rights have been independently
verified. Preserve applicable notices if copied material is identified.

## Configuration, installation and remaining limitations

README, example configuration and installation/network/security instructions agree
on explicit private LAN selection, localhost fallback, unencrypted-HTTP warning,
exact origin policy, authentication/CSRF/session protections, optional HTTPS with
explicit proxy trust, and optional NetWatch/AllStar Nets timers. Upgrade and
retained-data reinstall preserve operator settings. No rpt.conf, DTMF, hook or
single-link.sh change is required or supplied.

The installed LAN-first workflow has not yet been reported as hardware-tested.
Confirm the new address-selection/sign-in/control/logout/fallback workflow on the
authorized spare, or explicitly accept that documented validation gap before
publication. Earlier 0.4.4 acceptance predates that change. No additional test or
installation is authorized by this document.

Known beta limitations: backups/releases are not automatically pruned; monitor
space and retain recoverable snapshots. Pi minimum capacity/SD endurance, other
architectures and ASL versions are not hardware-certified. Actual HTTPS proxy
configurations need deployment-specific verification. Plain LAN HTTP does not
encrypt passwords or sessions and may not support browser Screen Wake Lock.
Sessions and rate-limit counters reset with the web process. Historical phase
documents retain their original test counts and are marked as historical.

## Owner commands — written only, not executed

Use Bash from this reviewed repository. The index still contains the prior beta; current changes are unstaged. After
owner review, use `git add --pathspec-from-file=packaging/public-files.txt` and
repeat the checks. Do not run a broad
`git add .` or import historical data. Reinspect before any separately authorized
commit. If files change, stage only the approved allowlist and repeat the review:

```sh
git status --short --untracked-files=all
git diff --cached --name-only
git diff --cached --stat
git diff --cached --check
git diff --cached
```

Only after provenance concerns, validation gaps and the staged contents are
resolved/accepted and the owner authorizes committing:

```sh
read -r -p 'Commit author name: ' COMMIT_NAME
read -r -p 'Commit email (GitHub no-reply if desired): ' COMMIT_EMAIL
git config user.name "$COMMIT_NAME"
git config user.email "$COMMIT_EMAIL"
git commit -m "Prepare KC1RAY Hub Scanner 0.5.1-beta"
git ls-tree -r --name-only HEAD
git log --oneline --all
```

The following commands **create a public repository and publish**. They require
separate final authorization, an installed GitHub CLI, and rights to create the
named repository. The GitHub owner/organization is not assumed. The destination
must not already exist; no access token belongs in a remote URL. Options are
documented in the [GitHub CLI reference](https://cli.github.com/manual/gh_repo_create).

```sh
gh auth login
read -r -p 'GitHub owner or organization: ' GITHUB_OWNER
gh repo create "$GITHUB_OWNER/kc1ray-hub-scanner" --public --source=. --remote=origin
git remote -v
git push --set-upstream origin main
```

If the owner instead creates an empty public repository on GitHub's website
(without initializing README, LICENSE or .gitignore), use these commands instead
of `gh repo create`; SSH authentication must already be configured:

```sh
read -r -p 'GitHub owner or organization: ' GITHUB_OWNER
git remote add origin "git@github.com:${GITHUB_OWNER}/kc1ray-hub-scanner.git"
git remote -v
git push --set-upstream origin main
```

These instructions create neither a version tag nor a GitHub Release. Do not
publish until the separately approved commit and public tree have been reviewed.
