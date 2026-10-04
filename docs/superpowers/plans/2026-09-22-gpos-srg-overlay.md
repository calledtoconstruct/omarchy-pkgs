# GPOS SRG overlay and restricted stream Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a GPOS SRG V3R3 overlay packet we can submit, plus a `restricted` package tree copied from stable by allowlist.

**Architecture:** Overlay lives in omarchy docs. Restricted tree lives in omarchy-pkgs as a copy tool, not a fourth pipeline stage. Honest gap rows beat fake compliance.

**Tech Stack:** markdown, CSV, bash, jq

**Spec:** `docs/superpowers/specs/2026-09-22-opr-risk-streams-design.md`

## Global Constraints

- Overlay worktree: `/home/joseph/.grok/worktrees/omarchy-gpos-srg-overlay` branch `feat/gpos-srg-overlay`
- Restricted worktree: `/home/joseph/code/omarchy-pkgs/.worktrees/feat-opr-restricted-channel` branch `feat/opr-restricted-channel`
- Never title the overlay a STIG. Never mint STIG IDs. Use GPOS V-IDs only
- Do not add `restricted` to `VALID_MIRRORS` in `helpers/paths.sh` (that would put it on edge→rc→stable)
- Do not publish, sign with production keys, or push
- Cover every CAT I ID listed in the spec, plus V-203599
- Status vocabulary: `implemented`, `partial`, `gap`, `not-applicable`. No `compliant`

## File structure (omarchy)

- Create: `docs/compliance/README.md`
- Create: `docs/compliance/gpos-srg-v3r3-overlay.md`
- Create: `docs/compliance/gpos-srg-v3r3-overlay.csv`
- Create: `test/shell.d/gpos-srg-overlay-test.sh`

## File structure (omarchy-pkgs)

- Create: `data/restricted/allowlist`
- Create: `bin/sync-restricted`
- Create: `tests/sync-restricted.sh`

---

### Task 1: Overlay catalog and cover letter (omarchy)

**Files:**
- Create: `docs/compliance/README.md`
- Create: `docs/compliance/gpos-srg-v3r3-overlay.md`
- Create: `docs/compliance/gpos-srg-v3r3-overlay.csv`
- Create: `test/shell.d/gpos-srg-overlay-test.sh`

**Interfaces:**
- Consumes: GPOS SRG V3R3 CAT I IDs from the spec
- Produces: CSV with header `vuln_id,severity,title,status,omarchy_mechanism,evidence,gap,srg_id` and one row per required ID; markdown that repeats those rows in prose; README that says this is an overlay submission packet

Required vuln_id values (exactly these 21 rows):

```
V-203603
V-203629
V-203630
V-203653
V-203669
V-203682
V-203695
V-203720
V-203736
V-203737
V-203739
V-203745
V-203746
V-203748
V-203749
V-203776
V-203782
V-252688
V-259333
V-278977
V-203599
```

Status seed (do not upgrade a gap to implemented):

- V-203745 / V-203746: `implemented` (mandatory LUKS)
- V-203720: `partial` (OPR and Arch sign; AUR does not; restricted stream is the intended close)
- V-203782: `gap` (ISO/SDDM autologin on default)
- V-203695: `gap` on default because `omarchy-sudo-passwordless` exists; note regulated profile as the close
- V-203599: `partial` (default lock 300s; regulated profile sets 900)
- V-203776 / V-203739: `gap` (no FIPS kernel story)
- V-259333: `partial` (omarchy-update exists; sidecar + arch-audit evidence is the close)
- V-278977: `partial` (honest on stable channel only)
- V-203629: `implemented` (shadow/yescrypt via pam_unix, not plaintext)
- Others: best-effort honest `partial` or `gap` with a one-line mechanism. Prefer `gap` when unsure.

- [ ] **Step 1: Write the failing test**

`test/shell.d/gpos-srg-overlay-test.sh`:

```bash
#!/bin/bash
set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/base-test.sh"

csv="$ROOT/docs/compliance/gpos-srg-v3r3-overlay.csv"
md="$ROOT/docs/compliance/gpos-srg-v3r3-overlay.md"
readme="$ROOT/docs/compliance/README.md"

[[ -f $csv ]] || fail "overlay csv exists"
[[ -f $md ]] || fail "overlay markdown exists"
[[ -f $readme ]] || fail "compliance README exists"

grep -qi 'not an official STIG' "$readme" || fail "README denies STIG status"
grep -qi 'GPOS SRG' "$readme" || fail "README names GPOS SRG"
grep -qiE 'omarchy STIG|official STIG of Arch' "$readme" && fail "README must not claim an Omarchy or Arch STIG"

header=$(head -1 "$csv")
[[ $header == "vuln_id,severity,title,status,omarchy_mechanism,evidence,gap,srg_id" ]] || fail "csv header matches contract" "$header"

ids='V-203603 V-203629 V-203630 V-203653 V-203669 V-203682 V-203695 V-203720 V-203736 V-203737 V-203739 V-203745 V-203746 V-203748 V-203749 V-203776 V-203782 V-252688 V-259333 V-278977 V-203599'
for id in $ids; do
  grep -q "^$id," "$csv" || fail "csv contains $id"
  grep -q "$id" "$md" || fail "markdown contains $id"
done

row_count=$(tail -n +2 "$csv" | grep -c .)
[[ $row_count -eq 21 ]] || fail "csv has 21 data rows" "$row_count"

while IFS= read -r line; do
  [[ -z $line ]] && continue
  status=$(printf '%s\n' "$line" | cut -d, -f4)
  case $status in
  implemented|partial|gap|not-applicable) ;;
  *) fail "status vocabulary" "$status" ;;
  esac
done < <(tail -n +2 "$csv")

grep -q '^V-203782,.*,gap,' "$csv" || fail "autologin remains a gap"
grep -q '^V-203776,.*,gap,' "$csv" || fail "FIPS remains a gap"
grep -q '^V-203739,.*,gap,' "$csv" || fail "NSA crypto remains a gap"

pass "gpos srg overlay packet"
```

CSV fields after status may contain commas. If so, quote those fields. Then the `cut -d, -f4` status check is wrong. Keep mechanism/evidence/gap free of commas, or use a dummy awk that only validates the first four columns:

```bash
awk -F, 'NR>1 {s=$4; if(s!="implemented"&&s!="partial"&&s!="gap"&&s!="not-applicable"){print s; exit 1}}' "$csv"
```

If you quote fields, switch the test to python3 csv. Prefer unquoted rows with no internal commas so the shell test stays dumb.

- [ ] **Step 2: Run test to verify it fails**

Run: `bash test/shell.d/gpos-srg-overlay-test.sh`

Expected: FAIL `overlay csv exists`

- [ ] **Step 3: Write the packet**

`docs/compliance/README.md` must include:

```
This directory is an overlay onto DISA General Purpose OS SRG V3R3 (2025-09-22).
It is not a DISA STIG, not an Arch Linux STIG, and not an authorization to operate.
Submit it as vendor-produced evidence with an Omarchy stable image and the restricted package stream.
```

`docs/compliance/gpos-srg-v3r3-overlay.md` starts with the same disclaimer, then a table of the 21 rows, then a short "how to use" that names `omarchy-profile-regulated` and `bin/sync-restricted` as related work on sibling branches.

CSV example row:

```
V-203599,CAT II,session lock after 15 minutes,partial,idle.lock in shell.json,default 300 seconds,regulated profile sets 900,
```

Fill title from the SRG short title, not from invention. CAT I rows use severity `CAT I`. V-203599 uses `CAT II`.

- [ ] **Step 4: Run test to verify it passes**

Run: `bash test/shell.d/gpos-srg-overlay-test.sh`

Expected: `ok - gpos srg overlay packet`

- [ ] **Step 5: Commit in the omarchy overlay worktree**

```bash
git add docs/compliance test/shell.d/gpos-srg-overlay-test.sh
git commit -m "docs: GPOS SRG V3R3 overlay packet"
```

---

### Task 2: Restricted allowlist copy (omarchy-pkgs)

**Files:**
- Create: `data/restricted/allowlist`
- Create: `bin/sync-restricted`
- Create: `tests/sync-restricted.sh`

Work from: `/home/joseph/code/omarchy-pkgs/.worktrees/feat-opr-restricted-channel`

**Interfaces:**
- Consumes: `--from-root <stable-tree>` `--to-root <restricted-tree>` `--arch x86_64` `--allowlist data/restricted/allowlist`
- Allowlist: one pkgname per line, comments with `#`
- First allowlist: `omarchy`, `omarchy-settings`, `omarchy-keyring`
- Copies `$from/stable/$arch/${pkg}-*.pkg.tar.zst`, the matching `.sig`, and that package's `*.advisory.json` when present. Does not copy packages absent from the allowlist, or their advisories. Does not call GPG.

- [ ] **Step 1: Write the failing test**

`tests/sync-restricted.sh`:

```bash
#!/bin/bash
set -euo pipefail
ROOT=$(realpath "${BASH_SOURCE[0]%/*}/..")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

from="$work/from"
to="$work/to"
mkdir -p "$from/stable/x86_64" "$to"
# allowlisted
: >"$from/stable/x86_64/omarchy-1.0-1-x86_64.pkg.tar.zst"
: >"$from/stable/x86_64/omarchy-1.0-1-x86_64.pkg.tar.zst.sig"
: >"$from/stable/x86_64/omarchy-settings-1.0-1-x86_64.pkg.tar.zst"
: >"$from/stable/x86_64/omarchy-settings-1.0-1-x86_64.pkg.tar.zst.sig"
: >"$from/stable/x86_64/omarchy-keyring-1.0-1-x86_64.pkg.tar.zst"
: >"$from/stable/x86_64/omarchy-keyring-1.0-1-x86_64.pkg.tar.zst.sig"
# not allowlisted
: >"$from/stable/x86_64/mise-bin-1.0-1-x86_64.pkg.tar.zst"
printf '{ "schema": 1, "pkgname": "omarchy", "scan_status": "ok" }\n' >"$from/stable/x86_64/omarchy-1.0-1-x86_64.advisory.json"

"$ROOT/bin/sync-restricted" --from-root "$from" --to-root "$to" --arch x86_64 \
  --allowlist "$ROOT/data/restricted/allowlist"

[[ -f $to/restricted/x86_64/omarchy-1.0-1-x86_64.pkg.tar.zst ]] || {
  echo "allowlisted package not copied" >&2
  exit 1
}
[[ -f $to/restricted/x86_64/omarchy-1.0-1-x86_64.pkg.tar.zst.sig ]] || {
  echo "signature not copied" >&2
  exit 1
}
[[ -f $to/restricted/x86_64/omarchy-1.0-1-x86_64.advisory.json ]] || {
  echo "advisory not copied with the allowlisted package" >&2
  exit 1
}
[[ ! -e $to/restricted/x86_64/mise-bin-1.0-1-x86_64.pkg.tar.zst ]] || {
  echo "non-allowlisted package leaked into restricted" >&2
  exit 1
}

echo "PASS: sync-restricted copies allowlisted signed packages only"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bash tests/sync-restricted.sh`

Expected: FAIL because `bin/sync-restricted` is missing.

- [ ] **Step 3: Write minimal implementation**

`data/restricted/allowlist`:

```
# Packages copied from stable into the restricted tree.
# Keep this small. Adding a name is a security review, not a courtesy.
omarchy
omarchy-settings
omarchy-keyring
```

`bin/sync-restricted`: bash that parses `--from-root --to-root --arch --allowlist`, reads allowlist, copies matching `${pkg}-*.pkg.tar.zst` and `.sig` with `cp -a`, copies sidecar if present. Exits 1 if an allowlisted name has a package file but no `.sig`.

Do not invoke `bin/advance-channel`. Do not change `VALID_MIRRORS`.

chmod +x.

- [ ] **Step 4: Run test to verify it passes**

Run: `bash tests/sync-restricted.sh`

Expected: `PASS: sync-restricted copies allowlisted signed packages only`

- [ ] **Step 5: Commit in the pkgs restricted worktree**

```bash
git add data/restricted/allowlist bin/sync-restricted tests/sync-restricted.sh
git commit -m "feat: copy-from-stable restricted package stream"
```
