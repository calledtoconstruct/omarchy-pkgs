#!/bin/bash
# Local OPR tree for every package name declared by pkgbuilds/*/PKGBUILD,
# including split packages, on each arch that package publishes.
# Mapped packages get an ok sidecar from the OSV stub. Unmapped packages get
# scan_status missing. No live OSV. No signing. Copies the tree to /tmp/opr-local-demo.
set -euo pipefail

ROOT=$(realpath "${BASH_SOURCE[0]%/*}/..")
PKGBUILDS="$ROOT/pkgbuilds"
MAP="$ROOT/data/opr-purl-map"
REPO_ARCHES=(x86_64 aarch64)

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

export OMARCHY_REPO_ROOT="$work/repo"
mkdir -p "$OMARCHY_REPO_ROOT/edge/x86_64" "$work/feed" "$work/bin" "$work/db-stage"
REPO_DIR="$OMARCHY_REPO_ROOT/edge/x86_64"

declare -A in_map=()
while IFS= read -r line || [[ -n $line ]]; do
  [[ -z $line || $line == \#* ]] && continue
  map_name=${line%% *}
  [[ $map_name == opr-purl-map-canary ]] && continue
  in_map[$map_name]=1
done <"$MAP"

: >"$work/packages.tsv"
pkgbuild_count=0
shopt -s nullglob
for pkgbuild in "$PKGBUILDS"/*/PKGBUILD; do
  pkgbuild_count=$((pkgbuild_count + 1))
  if ! bash --noprofile --norc -c '
    set -eo pipefail
    shopt -s extglob nullglob
    source "$1"
    [[ -n ${pkgver:-} && -n ${pkgrel:-} && -n ${pkgname:-} ]] || exit 3
    if [[ $(declare -p arch) == declare\ -a* ]]; then
      arch_words="${arch[*]}"
    else
      arch_words="${arch}"
    fi
    [[ -n $arch_words ]] || exit 4
    emit() {
      printf "PKG\t%s\t%s\t%s\t%s\n" "$1" "$pkgver" "$pkgrel" "$arch_words"
    }
    if [[ $(declare -p pkgname) == declare\ -a* ]]; then
      [[ ${#pkgname[@]} -gt 0 ]] || exit 5
      for pkg_name in "${pkgname[@]}"; do
        [[ -n $pkg_name ]] || exit 5
        emit "$pkg_name"
      done
    else
      emit "$pkgname"
    fi
  ' _ "$pkgbuild" >>"$work/packages.tsv"; then
    echo "demo could not read package names from $pkgbuild" >&2
    exit 1
  fi
done
shopt -u nullglob

[[ $pkgbuild_count -gt 0 ]] || {
  echo "demo found no PKGBUILDs in $PKGBUILDS" >&2
  exit 1
}

publishes_for() {
  local want=$1 words=$2 word
  for word in $words; do
    [[ $word == any || $word == "$want" ]] && return 0
  done
  return 1
}

: >"$work/rows.tsv"
declare -A pkg_hash
declare -A pkg_mapped
declare -A expected_name
declare -A seen_name
included=0
mapped_count=0
name_count=0

while IFS=$'\t' read -r kind name pkgver pkgrel arch_words; do
  [[ $kind == PKG ]] || continue
  if [[ -z ${expected_name[$name]:-} ]]; then
    expected_name[$name]=1
    name_count=$((name_count + 1))
  fi
  flag=unmapped
  [[ -n ${in_map[$name]:-} ]] && flag=mapped
  pkg_mapped[$name]=$flag
  version="${pkgver}-${pkgrel}"
  published=0
  for repo_arch in "${REPO_ARCHES[@]}"; do
    publishes_for "$repo_arch" "$arch_words" || continue
    published=1
    seen_name[$name]=1
    repo_dir="$OMARCHY_REPO_ROOT/edge/$repo_arch"
    stage="$work/db-stage/$repo_arch"
    mkdir -p "$repo_dir" "$stage/$name"
    cat >"$stage/$name/desc" <<EOF
%FILENAME%
${name}-${version}-${repo_arch}.pkg.tar.zst
%NAME%
${name}
%VERSION%
${version}
%ARCH%
${repo_arch}
EOF
    archive="$repo_dir/${name}-${version}-${repo_arch}.pkg.tar.zst"
    printf 'pkg-bytes\n' >"$archive"
    pkg_hash["$repo_arch/$name"]=$(sha256sum "$archive" | awk '{print $1}')
    printf 'INCLUDE\t%s\t%s\t%s\t%s\t%s\n' "$flag" "$name" "$pkgver" "$pkgrel" "$repo_arch" >>"$work/rows.tsv"
    included=$((included + 1))
    [[ $flag == mapped ]] && mapped_count=$((mapped_count + 1))
  done
  [[ $published -eq 1 ]] || {
    echo "demo has no edge repo for $name (arch: $arch_words)" >&2
    exit 1
  }
done <"$work/packages.tsv"

for map_name in "${!in_map[@]}"; do
  [[ -n ${seen_name[$map_name]:-} ]] || {
    echo "purl map package $map_name is not in the local tree" >&2
    exit 1
  }
done

[[ $name_count -eq ${#seen_name[@]} ]] || {
  echo "local tree names ${#seen_name[@]} do not match PKGBUILD names $name_count" >&2
  exit 1
}

for required in hyprpm rog-control-center caja-open-any-terminal yaru-gtk-theme \
  linux-omarchy-headers libretro-vice-x64-git dotnet-sdk-bin ghostty-terminfo; do
  [[ -n ${seen_name[$required]:-} ]] || {
    echo "local tree is missing split package $required" >&2
    exit 1
  }
done

echo "included $name_count packages as $included artifacts ($mapped_count mapped), from $pkgbuild_count PKGBUILDs"
[[ $name_count -ge $pkgbuild_count ]] || {
  echo "package names $name_count are fewer than PKGBUILDs $pkgbuild_count" >&2
  exit 1
}

for repo_arch in "${REPO_ARCHES[@]}"; do
  tar -C "$work/db-stage/$repo_arch" -cf "$OMARCHY_REPO_ROOT/edge/$repo_arch/omarchy.db.tar.zst" .
done

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

for repo_arch in "${REPO_ARCHES[@]}"; do
  OSV_STUB_RESPONSE="$work/osv.json" PATH="$work/bin:$PATH" \
    "$ROOT/bin/fetch-advisories" --mirror edge --arch "$repo_arch" --feed "$work/feed"
  "$ROOT/bin/sync-advisories" --mirror edge --arch "$repo_arch" \
    --feed "$work/feed" --no-sign --stale-after 720h
done

json_count=0
ok_count=0
while IFS=$'\t' read -r kind mapped name pkgver pkgrel repo_arch; do
  [[ $kind == INCLUDE ]] || continue
  version="${pkgver}-${pkgrel}"
  repo_dir="$OMARCHY_REPO_ROOT/edge/$repo_arch"
  archive="$repo_dir/${name}-${version}-${repo_arch}.pkg.tar.zst"
  sidecar="$repo_dir/${name}-${version}-${repo_arch}.advisory.json"
  [[ -f $sidecar ]] || {
    echo "demo must write ${repo_arch}/${name}-${version}-${repo_arch}.advisory.json" >&2
    exit 1
  }
  status=$(jq -r '.scan_status' "$sidecar")
  if [[ ${pkg_mapped[$name]} == mapped ]]; then
    [[ $status == ok ]] || {
      echo "$name $repo_arch advisory must be ok" >&2
      exit 1
    }
    [[ $(jq -r '.cve_ids[0]' "$sidecar") == CVE-2026-4242 ]] || {
      echo "$name $repo_arch advisory must carry the stub CVE" >&2
      exit 1
    }
    ok_count=$((ok_count + 1))
  else
    [[ $status == missing ]] || {
      echo "$name $repo_arch advisory must be missing" >&2
      exit 1
    }
  fi
  [[ $(sha256sum "$archive" | awk '{print $1}') == "${pkg_hash[$repo_arch/$name]}" ]] || {
    echo "demo rewrote the $name $repo_arch package archive" >&2
    exit 1
  }
  json_count=$((json_count + 1))
done <"$work/rows.tsv"

[[ $json_count -eq $included ]] || {
  echo "advisory count $json_count does not match included $included" >&2
  exit 1
}
[[ $ok_count -eq $mapped_count ]] || {
  echo "ok advisories $ok_count do not match mapped packages $mapped_count" >&2
  exit 1
}
if find "$OMARCHY_REPO_ROOT" -name '*.sig' | grep -q .; then
  echo "demo must not sign advisories" >&2
  exit 1
fi

keep=/tmp/opr-local-demo
rm -rf "$keep"
mkdir -p "$keep"
cp -a "$OMARCHY_REPO_ROOT/." "$keep/"

echo "PASS: local OPR wrote $json_count sidecars for $name_count packages ($ok_count ok, $((json_count - ok_count)) missing) without signing or rebuilding"
