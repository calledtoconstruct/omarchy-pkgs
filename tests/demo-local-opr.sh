#!/bin/bash
# Mini OPR: one channel, one arch, mise-bin plus two mapped packages.
# No live OSV. No signing. Leaves a copy at /tmp/opr-local-demo.
set -euo pipefail

ROOT=$(realpath "${BASH_SOURCE[0]%/*}/..")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

export OMARCHY_REPO_ROOT="$work/repo"
mkdir -p "$OMARCHY_REPO_ROOT/edge/x86_64" "$work/feed" "$work/bin" "$work/db-stage"

REPO_DIR="$OMARCHY_REPO_ROOT/edge/x86_64"

# pkgver-pkgrel values taken from the PKGBUILDs (not invented).
demo_pkgs=(
  "mise-bin 2026.9.4-1"
  "yay 13.0.1-1"
  "walker 2.17.0-1"
)
declare -A pkg_hash
for row in "${demo_pkgs[@]}"; do
  name=${row%% *}
  version=${row#* }
  mkdir -p "$work/db-stage/$name"
  cat >"$work/db-stage/$name/desc" <<EOF
%FILENAME%
${name}-${version}-x86_64.pkg.tar.zst
%NAME%
${name}
%VERSION%
${version}
%ARCH%
x86_64
EOF
  archive="$REPO_DIR/${name}-${version}-x86_64.pkg.tar.zst"
  printf 'pkg-bytes\n' >"$archive"
  pkg_hash[$name]=$(sha256sum "$archive" | awk '{print $1}')
done
tar -C "$work/db-stage" -cf "$REPO_DIR/omarchy.db.tar.zst" mise-bin yay walker

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
  --feed "$work/feed" --package mise-bin --package yay --package walker

"$ROOT/bin/sync-advisories" --mirror edge --arch x86_64 \
  --feed "$work/feed" --no-sign --stale-after 720h \
  --package mise-bin --package yay --package walker

for row in "${demo_pkgs[@]}"; do
  name=${row%% *}
  version=${row#* }
  archive="$REPO_DIR/${name}-${version}-x86_64.pkg.tar.zst"
  sidecar="$REPO_DIR/${name}-${version}-x86_64.advisory.json"
  [[ -f $sidecar ]] || { echo "demo must write ${name}-${version}-x86_64.advisory.json" >&2; exit 1; }
  [[ $(jq -r '.scan_status' "$sidecar") == ok ]] || {
    echo "$name advisory must be ok" >&2
    exit 1
  }
  [[ $(jq -r '.cve_ids[0]' "$sidecar") == CVE-2026-4242 ]] || {
    echo "$name advisory must carry the stub CVE" >&2
    exit 1
  }
  [[ $(sha256sum "$archive" | awk '{print $1}') == "${pkg_hash[$name]}" ]] || {
    echo "demo rewrote the $name package archive" >&2
    exit 1
  }
  [[ ! -e $sidecar.sig ]] || {
    echo "demo must not sign $name" >&2
    exit 1
  }
done

keep=/tmp/opr-local-demo
rm -rf "$keep"
mkdir -p "$keep"
cp -a "$OMARCHY_REPO_ROOT/." "$keep/"

echo "PASS: local mini OPR wrote mise-bin, yay, and walker sidecars without signing or rebuilding"
