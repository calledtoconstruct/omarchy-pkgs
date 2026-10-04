# Omarchy risk streams

Three independent tracks. Same sidecar schema. Different failure policy.

This is not an Arch STIG and not a DISA product. Mil/gov work is a GPOS SRG V3R3 overlay we can submit. Corporate work is an opt-in profile. Average-user work never tightens the default desktop.

## Shared facts

- Sidecar path: `pkgs.omarchy.org/<channel>/<arch>/<pkgname>-<pkgver>-<pkgrel>-<arch>.advisory.json` plus `.sig`, beside the package archive
- Identity key: `pkgname:pkgver-pkgrel:arch`
- Schema v1 fields already on `feat/opr-advisory-rfc-gaps`: `cve_ids`, `cve_max_severity`, `severity_scale`, `advisory_as_of`, `scanned_at`, `scan_source`, `scan_status` in `ok|stale|missing|error`
- No `safety_score`. No capability tags. OPR ingests OSV; it does not scan package bits
- Arch distro packages stay on `arch-audit` / Arch Security Tracker. The sidecar covers OPR-built artifacts only
- Writer is OPR-operated (`bin/fetch-advisories`, `bin/sync-advisories`). Maintainers do not write CVEs into PKGBUILDs
- Ryan parked omarchy-pkgs#416. Do not wait for it. Do not push or publish a feed
- Do not invent STIG IDs. Overlay rows use GPOS SRG V-IDs from V3R3 (2025-09-22)

## Stream 1. Average user

Goal: a person on default Omarchy can see known CVEs on OPR packages without the desktop becoming fail-closed.

Policy: missing sidecar, missing row, or stale row is a warning. Install and update still proceed.

First slice:

1. Default PURL map so `fetch-advisories` can query OSV for `mise-bin` without a one-off flag
2. Local mini OPR demo: one channel `edge`, one arch `x86_64`, one package `mise-bin`, `--no-sign`, no package rebuild
3. Client CLI `omarchy-pkg-advisories` that prints fail-open warnings from a sidecar file

Out of this slice: KEV/EPSS fields, transaction join, bar widget, `omarchy-update` gating.

## Stream 2. Corporate

Goal: an admin can opt into a tighter profile and get an exposure report they can hand to a reviewer.

Policy: opt-in. Default Omarchy stays passwordless-sudo-capable, 300s lock, fail-open advisories. The regulated profile is a marker plus settings, not a new ISO.

First slice:

1. `omarchy-profile-regulated` apply/status/disable
2. Apply sets `idle.lock` to 900 and refuses `omarchy-sudo-passwordless`
3. `omarchy-risk-report` joins sidecar + optional arch-audit input. Exit non-zero under `--fail-closed` or when the regulated marker is on and the sidecar is missing/error

Out of this slice: CIS/SOC2 mappings, MDM, disabling AUR system-wide, FIPS.

## Stream 3. Mil/gov

Goal: a packet DISA (or an AO) can read, plus a package tree that is smaller and signed-only.

Policy: overlay, not a STIG. Restricted tree is a copy-from-stable allowlist, not a fourth edge→rc→stable stage.

First slice:

1. GPOS SRG V3R3 overlay: all 20 CAT I rows plus V-203599 (15-minute lock, CAT II). Honest status: implemented / partial / gap / not applicable
2. Cover letter that states what this is and what it is not
3. `restricted` channel scaffolding: allowlist + `bin/sync-restricted` that copies signed packages from a stable tree. Sidecar copied when present. No live publish

Out of this slice: FIPS kernel, auditd STIG-complete rules, DoD banner in SDDM, talking to DISA.

## CAT I IDs this overlay must cover

From GPOS SRG V3R3 (finding count 203: 20 CAT I / 173 CAT II / 10 CAT III):

V-203603, V-203629, V-203630, V-203653, V-203669, V-203682, V-203695, V-203720, V-203736, V-203737, V-203739, V-203745, V-203746, V-203748, V-203749, V-203776, V-203782, V-252688, V-259333, V-278977.

Known default-Omarchy conflicts to record as gaps, not hide:

- V-203782 automatic logon (ISO/SDDM autologin)
- V-203695 privileged functions (`omarchy-sudo-passwordless` exists on default)
- V-203776 / V-203739 FIPS / NSA-approved crypto
- V-259333 30-day patch evidence needs sidecar + arch-audit, not a blog claim
- V-278977 vendor-supported version is honest only on `stable`

## Branch map

| Stream | Repo | Branch | Base |
| --- | --- | --- | --- |
| 1 producer | omarchy-pkgs | feat/opr-user-sidecar-demo | feat/opr-advisory-rfc-gaps |
| 1 client | omarchy | feat/advisory-warnings | quattro |
| 2 | omarchy | feat/corporate-regulated-profile | quattro |
| 3 overlay | omarchy | feat/gpos-srg-overlay | quattro |
| 3 stream | omarchy-pkgs | feat/opr-restricted-channel | feat/opr-advisory-rfc-gaps |

Do not edit the same file on two stream branches. Stream 3 pkgs work adds new files under `data/restricted/` and `bin/sync-restricted`. Stream 1 pkgs work may edit `bin/fetch-advisories` and add `data/opr-purl-map`.

## Stop conditions

Stop and ask before: pushing to origin/upstream, publishing a sidecar, changing default `idle.lock` 300, removing passwordless sudo from the default product, or naming the overlay an "Omarchy STIG".
