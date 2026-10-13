#!/bin/bash
# Local OPR tree for every mapped package with a static pkgver and pkgrel.
# No live OSV. No signing. Copies the tree to /tmp/opr-local-demo.
set -euo pipefail

ROOT=$(realpath "${BASH_SOURCE[0]%/*}/..")
if [[ -d /home/joseph/code/omarchy-pkgs/pkgbuilds ]]; then
  PKGBUILDS=/home/joseph/code/omarchy-pkgs/pkgbuilds
else
  PKGBUILDS="$ROOT/pkgbuilds"
fi
MAP="$ROOT/data/opr-purl-map"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

export OMARCHY_REPO_ROOT="$work/repo"
mkdir -p "$OMARCHY_REPO_ROOT/edge/x86_64" "$work/feed" "$work/bin" "$work/db-stage"
REPO_DIR="$OMARCHY_REPO_ROOT/edge/x86_64"

python3 - "$MAP" "$PKGBUILDS" >"$work/rows.tsv" <<'PY'
import re
import sys

map_path, pkgbuilds = sys.argv[1], sys.argv[2]

def strip_comment(line):
    out = []
    quote = None
    i = 0
    while i < len(line):
        char = line[i]
        if quote:
            out.append(char)
            if char == "\\" and quote == '"':
                if i + 1 < len(line):
                    i += 1
                    out.append(line[i])
            elif char == quote:
                quote = None
        elif char in "\"'":
            quote = char
            out.append(char)
        elif char == "#":
            break
        else:
            out.append(char)
        i += 1
    return "".join(out)

def plain_value(raw):
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'":
        inner = raw[1:-1]
    else:
        inner = raw
    if "$" in raw or "`" in raw or not re.fullmatch(r"[A-Za-z0-9._+:~]+", inner):
        return None
    return inner

def last_assignments(path):
    last = {}
    in_func = False
    depth = 0
    opened = False
    for raw in open(path, errors="replace"):
        line = strip_comment(raw).strip()
        if not line:
            continue
        if in_func:
            depth += line.count("{") - line.count("}")
            if "{" in line:
                opened = True
            if opened and depth <= 0:
                in_func = False
            continue
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*\(\s*\)", line):
            in_func = True
            depth = line.count("{") - line.count("}")
            opened = "{" in line
            if opened and depth <= 0:
                in_func = False
            continue
        match = re.match(r"^(pkgver|pkgrel)\s*=\s*(.*)$", line)
        if not match:
            continue
        value = plain_value(match.group(2))
        last[match.group(1)] = value if value is not None else False
    return last

for raw in open(map_path):
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    name = line.split(None, 1)[0]
    if name == "opr-purl-map-canary":
        continue
    path = f"{pkgbuilds}/{name}/PKGBUILD"
    try:
        found = last_assignments(path)
    except FileNotFoundError:
        print(f"SKIP\t{name}\tno PKGBUILD at {path}")
        continue
    pkgver = found.get("pkgver")
    pkgrel = found.get("pkgrel")
    if pkgver is None:
        print(f"SKIP\t{name}\tpkgver missing")
        continue
    if pkgver is False:
        print(f"SKIP\t{name}\tpkgver is not a plain value")
        continue
    if pkgrel is None:
        print(f"SKIP\t{name}\tpkgrel missing")
        continue
    if pkgrel is False:
        print(f"SKIP\t{name}\tpkgrel is not a plain value")
        continue
    print(f"INCLUDE\t{name}\t{pkgver}\t{pkgrel}")
PY

declare -A pkg_hash
included=0
skipped=0
while IFS=$'\t' read -r kind name pkgver pkgrel; do
  if [[ $kind == SKIP ]]; then
    echo "skip $name: $pkgver"
    skipped=$((skipped + 1))
    continue
  fi
  version="${pkgver}-${pkgrel}"
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
  included=$((included + 1))
done <"$work/rows.tsv"

echo "included $included packages, skipped $skipped"
[[ $included -ge 1 ]] || {
  echo "demo included no packages" >&2
  exit 1
}

tar -C "$work/db-stage" -cf "$REPO_DIR/omarchy.db.tar.zst" .

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

cat >"$work/bin/curl" <<'EOF'
#!/bin/bash
cat "$OSV_STUB_RESPONSE"
EOF
chmod +x "$work/bin/curl"

OSV_STUB_RESPONSE="$work/osv.json" PATH="$work/bin:$PATH" \
  "$ROOT/bin/fetch-advisories" --mirror edge --arch x86_64 --feed "$work/feed"

"$ROOT/bin/sync-advisories" --mirror edge --arch x86_64 \
  --feed "$work/feed" --no-sign --stale-after 720h

json_count=0
while IFS=$'\t' read -r kind name pkgver pkgrel; do
  [[ $kind == INCLUDE ]] || continue
  version="${pkgver}-${pkgrel}"
  archive="$REPO_DIR/${name}-${version}-x86_64.pkg.tar.zst"
  sidecar="$REPO_DIR/${name}-${version}-x86_64.advisory.json"
  [[ -f $sidecar ]] || {
    echo "demo must write ${name}-${version}-x86_64.advisory.json" >&2
    exit 1
  }
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
  json_count=$((json_count + 1))
done <"$work/rows.tsv"

[[ $json_count -eq $included ]] || {
  echo "advisory count $json_count does not match included $included" >&2
  exit 1
}
if find "$REPO_DIR" -name '*.sig' | grep -q .; then
  echo "demo must not sign advisories" >&2
  exit 1
fi

keep=/tmp/opr-local-demo
rm -rf "$keep"
mkdir -p "$keep"
cp -a "$OMARCHY_REPO_ROOT/." "$keep/"

echo "PASS: local mini OPR wrote $json_count sidecars without signing or rebuilding"
