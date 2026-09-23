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

sidecar="$REPO_DIR/mise-bin-2026.9.4-1-x86_64.advisory.json"
[[ -f $sidecar ]] || { echo "demo must write mise-bin-2026.9.4-1-x86_64.advisory.json" >&2; exit 1; }
[[ $(jq -r '.scan_status' "$sidecar") == ok ]] || {
  echo "mise-bin advisory must be ok" >&2
  exit 1
}
[[ $(jq -r '.cve_ids[0]' "$sidecar") == CVE-2026-4242 ]] || {
  echo "advisory must carry the stub CVE" >&2
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
