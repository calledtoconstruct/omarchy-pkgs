# Average-user sidecar demo Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a default OSV PURL map and a local `mise-bin` sidecar demo so average-user warning tools have a real feed to read, without signing or publishing.

**Architecture:** Reuse `bin/fetch-advisories` and `bin/sync-advisories` on `feat/opr-advisory-rfc-gaps`. Add `data/opr-purl-map` as the default map. Add a no-network test that builds a fake `edge/x86_64` db for `mise-bin`, stubs OSV, and asserts the sidecar appears beside the untouched package archive.

**Tech Stack:** bash, jq, tar, existing advisory helpers

**Spec:** `docs/superpowers/specs/2026-09-22-opr-risk-streams-design.md`

## Global Constraints

- Work only in this omarchy-pkgs worktree on `feat/opr-user-sidecar-demo`
- Do not push, sign with a real key, or write into a live `pkgs.omarchy.org`
- Do not add `safety_score` or capability tags
- Empty OSV `vulns` must still write no feed file (row stays `missing`)
- Tests must not hit `https://api.osv.dev`
- Do not modify `helpers/paths.sh` `VALID_MIRRORS` (that is stream 3)
- Do not edit omarchy client code here (that is the sibling omarchy worktree `feat/advisory-warnings`)

## File structure

- Create: `data/opr-purl-map`
- Create: `tests/demo-local-opr.sh`
- Modify: `bin/fetch-advisories` default `--purl-map` to `$BUILD_ROOT/data/opr-purl-map`
- Modify: `tests/fetch-advisories.sh` to prove the default map is used when `--purl-map` is omitted
- Modify: `docs/opr-advisory-sidecar.md` mini-demo section to name the default map and the test
- Modify: `.github/workflows/test.yml` to run `./tests/demo-local-opr.sh`

---

### Task 1: Default PURL map

**Files:**
- Create: `data/opr-purl-map`
- Modify: `bin/fetch-advisories`
- Modify: `tests/fetch-advisories.sh`
- Modify: `docs/opr-advisory-sidecar.md`

**Interfaces:**
- Consumes: existing `purl_for()` in `bin/fetch-advisories` (map file lines `pkgname purl-with-{version}`, then hardcoded `mise-bin` fallback)
- Produces: `$BUILD_ROOT/data/opr-purl-map` loaded when `--purl-map` is omitted; `purl_for mise-bin 1.0.0` still yields `pkg:github/jdx/mise@1.0.0`

- [ ] **Step 1: Write the failing test**

In `tests/fetch-advisories.sh`, after the existing PASS path that uses `--purl-map`, add a second invocation that omits `--purl-map` and uses a different OSV stub so it cannot succeed by leftover files:

```bash
# Default map: omit --purl-map. The committed data/opr-purl-map must supply mise-bin.
rm -rf "$FEED"
mkdir -p "$FEED"
printf '{ "vulns": [ { "id": "GHSA-dddd-eeee-ffff", "aliases": ["CVE-2026-9999"], "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }] } ] }\n' >"$work/osv-default.json"
OSV_STUB_RESPONSE="$work/osv-default.json" PATH="$work/bin:$PATH" \
  "$ROOT/bin/fetch-advisories" --mirror edge --arch x86_64 \
  --feed "$FEED" --package mise-bin >/dev/null
feed_file="$FEED/mise-bin/1.0.0-1/x86_64.json"
[[ -f $feed_file ]] || {
  echo "default purl map must let fetch-advisories query mise-bin without --purl-map" >&2
  exit 1
}
jq -e '.cve_ids | index("CVE-2026-9999")' "$feed_file" >/dev/null || {
  echo "default-map feed must collect CVE ids" >&2
  exit 1
}
```

Keep the original `--purl-map` case. Do not delete it.

- [ ] **Step 2: Run test to verify it fails**

Run: `bash tests/fetch-advisories.sh`

Expected: FAIL with `default purl map must let fetch-advisories query mise-bin without --purl-map` because `purl_for` only reads `--purl-map` today and the hardcoded `mise-bin` case only runs after that file is set. If the hardcoded case already makes this pass, still add `data/opr-purl-map` and make `fetch-advisories` load it by default so unmapped packages have a committed place to grow. Then add a test package name that is only in the file, not hardcoded:

```bash
# If mise-bin is hardcoded, also map a second name exclusively via the default file.
```

Ruling if the hardcoded `mise-bin` already passes the omit-flag test: still create the file and default-load it. Add `data/opr-purl-map` line:

```
# extra name used only by tests/fetch-advisories.sh default-map coverage
opr-purl-map-canary pkg:github/example/canary@{version}
```

And a canary desc in the fake db so the default map is proven independently of the hardcoded fallback.

- [ ] **Step 3: Write minimal implementation**

Create `data/opr-purl-map`:

```
# pkgname  purl with {version} replaced by pkgver (not pkgver-pkgrel)
# Unmapped packages stay missing. That is correct for v1.
mise-bin pkg:github/jdx/mise@{version}
bun-bin pkg:github/oven-sh/bun@{version}
localsend-bin pkg:github/localsend/localsend@{version}
basecamp-cli pkg:github/basecamp/basecamp-cli@{version}
opr-purl-map-canary pkg:github/example/canary@{version}
```

In `bin/fetch-advisories`, after option parsing, before `purl_for` is used:

```bash
DEFAULT_PURL_MAP="$BUILD_ROOT/data/opr-purl-map"
if [[ -z ${PURL_MAP:-} && -f $DEFAULT_PURL_MAP ]]; then
  PURL_MAP="$DEFAULT_PURL_MAP"
fi
```

Keep the hardcoded `mise-bin` fallback in `purl_for` as a last resort.

Extend `read_db_manifest` fixture in the test to include `opr-purl-map-canary` with version `0.0.1-1` and assert a feed file is written for it when using the default map.

- [ ] **Step 4: Run test to verify it passes**

Run: `bash tests/fetch-advisories.sh`

Expected: `PASS: fetch-advisories writes a version-pinned OSV feed without touching packages`

- [ ] **Step 5: Commit**

```bash
git add data/opr-purl-map bin/fetch-advisories tests/fetch-advisories.sh docs/opr-advisory-sidecar.md
git commit -m "feat: default OSV purl map for advisory fetch"
```

---

### Task 2: Local mini OPR demo (mise-bin, no sign, no network)

**Files:**
- Create: `tests/demo-local-opr.sh`
- Modify: `.github/workflows/test.yml`

**Interfaces:**
- Consumes: `bin/fetch-advisories`, `bin/sync-advisories --no-sign`, `data/opr-purl-map`
- Produces: a test that leaves `omarchy.advisories.json` next to an unchanged `mise-bin-*.pkg.tar.zst` under a temp `OMARCHY_REPO_ROOT`

- [ ] **Step 1: Write the failing test**

Create `tests/demo-local-opr.sh`:

```bash
#!/bin/bash
# Mini OPR: one channel, one arch, one package. No live OSV. No signing.
set -euo pipefail

ROOT=$(realpath "${BASH_SOURCE[0]%/*}/..")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

export OMARCHY_REPO_ROOT="$work/repo"
mkdir -p "$OMARCHY_REPO_ROOT/edge/x86_64" "$work/feed" "$work/bin" "$work/db-stage/mise-bin"

REPO_DIR="$OMARCHY_REPO_ROOT/edge/x86_64"
cat >"$work/db-stage/mise-bin/desc" <<EOF
%FILENAME%
mise-bin-2026.9.4-1-x86_64.pkg.tar.zst
%NAME%
mise-bin
%VERSION%
2026.9.4-1
%ARCH%
x86_64
EOF
tar -C "$work/db-stage" -cf "$REPO_DIR/omarchy.db.tar.zst" mise-bin
printf 'pkg-bytes\n' >"$REPO_DIR/mise-bin-2026.9.4-1-x86_64.pkg.tar.zst"
pkg_hash=$(sha256sum "$REPO_DIR/mise-bin-2026.9.4-1-x86_64.pkg.tar.zst" | awk '{print $1}')

cat >"$work/osv.json" <<'EOF'
{
  "vulns": [
    {
      "id": "GHSA-1111-2222-3333",
      "aliases": ["CVE-2026-4242"],
      "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }]
    }
  ]
}
EOF

cat >"$work/bin/curl" <<EOF
#!/bin/bash
cat "\$OSV_STUB_RESPONSE"
EOF
chmod +x "$work/bin/curl"

OSV_STUB_RESPONSE="$work/osv.json" PATH="$work/bin:$PATH" \
  "$ROOT/bin/fetch-advisories" --mirror edge --arch x86_64 \
  --feed "$work/feed" --package mise-bin

"$ROOT/bin/sync-advisories" --mirror edge --arch x86_64 \
  --feed "$work/feed" --no-sign --stale-after 720h

sidecar="$REPO_DIR/omarchy.advisories.json"
key="mise-bin:2026.9.4-1:x86_64"
[[ -f $sidecar ]] || { echo "demo must write omarchy.advisories.json" >&2; exit 1; }
[[ $(jq -r --arg k "$key" '.advisories[$k].scan_status' "$sidecar") == ok ]] || {
  echo "mise-bin row must be ok" >&2
  exit 1
}
[[ $(jq -r --arg k "$key" '.advisories[$k].cve_ids[0]' "$sidecar") == CVE-2026-4242 ]] || {
  echo "sidecar must carry the stub CVE" >&2
  exit 1
}
[[ $(sha256sum "$REPO_DIR/mise-bin-2026.9.4-1-x86_64.pkg.tar.zst" | awk '{print $1}') == "$pkg_hash" ]] || {
  echo "demo rewrote the package archive" >&2
  exit 1
}
[[ ! -e $sidecar.sig ]] || {
  echo "demo must not sign" >&2
  exit 1
}

echo "PASS: local mini OPR wrote a mise-bin sidecar without signing or rebuilding"
```

The file will fail until fetch-advisories default map + sync-advisories exist in this branch (they should already, from the sidecar base plus Task 1).

- [ ] **Step 2: Run test to verify it fails**

Run: `bash tests/demo-local-opr.sh`

Expected: FAIL only if Task 1 is incomplete. If it already PASSes on this branch after Task 1, that is acceptable: chmod +x, wire CI, commit.

- [ ] **Step 3: Wire CI**

In `.github/workflows/test.yml` self-tests docker script, after `./tests/fetch-advisories.sh` add:

```
./tests/demo-local-opr.sh
```

chmod +x `tests/demo-local-opr.sh`.

Add a short subsection to `docs/opr-advisory-sidecar.md` titled `Local mini OPR` that says:

```
# from a checkout, no production host
OMARCHY_REPO_ROOT=/tmp/mini-opr ./tests/demo-local-opr.sh
```

- [ ] **Step 4: Run tests**

Run: `bash tests/fetch-advisories.sh && bash tests/demo-local-opr.sh && bash tests/advisory-sidecar.sh`

Expected: all three print PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/demo-local-opr.sh .github/workflows/test.yml docs/opr-advisory-sidecar.md
git commit -m "test: local mini OPR sidecar demo for mise-bin"
```

---

## Later slices (not this plan)

- Client warnings live on omarchy `feat/advisory-warnings` (sibling plan)
- KEV/EPSS as v2 sidecar fields
- Join arch-audit into the producer
