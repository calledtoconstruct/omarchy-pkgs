#!/bin/bash
# Producer for versioned advisory feed JSON (omacom/omarchy-pkgs#378).
# Stubs OSV HTTP. No live network.

set -euo pipefail

ROOT=$(realpath "${BASH_SOURCE[0]%/*}/..")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

REPO_ROOT_TMP="$work/repo"
FEED="$work/feed"
mkdir -p "$REPO_ROOT_TMP/edge/x86_64" "$FEED" "$work/bin"
export OMARCHY_REPO_ROOT="$REPO_ROOT_TMP"

REPO_DIR_TMP="$REPO_ROOT_TMP/edge/x86_64"
DB="$REPO_DIR_TMP/omarchy.db.tar.zst"

mkdir -p "$work/db-stage/mise-bin" "$work/db-stage/opr-purl-map-canary"
cat >"$work/db-stage/mise-bin/desc" <<EOF
%FILENAME%
mise-bin-1.0.0-1-x86_64.pkg.tar.zst
%NAME%
mise-bin
%VERSION%
1.0.0-1
%ARCH%
x86_64
EOF
cat >"$work/db-stage/opr-purl-map-canary/desc" <<EOF
%FILENAME%
opr-purl-map-canary-0.0.1-1-x86_64.pkg.tar.zst
%NAME%
opr-purl-map-canary
%VERSION%
0.0.1-1
%ARCH%
x86_64
EOF
tar -C "$work/db-stage" -cf "$DB" mise-bin opr-purl-map-canary
printf 'pkg\n' >"$REPO_DIR_TMP/mise-bin-1.0.0-1-x86_64.pkg.tar.zst"

cat >"$work/osv.json" <<'EOF'
{
  "vulns": [
    {
      "id": "GHSA-aaaa-bbbb-cccc",
      "aliases": ["CVE-2026-4242"],
      "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }]
    }
  ]
}
EOF

cat >"$work/bin/curl" <<'EOF'
#!/bin/bash
if [[ -n ${OSV_STUB_LOG:-} ]]; then
  args=("$@")
  i=0
  while [[ $i -lt ${#args[@]} ]]; do
    if [[ ${args[$i]} == -d || ${args[$i]} == --data || ${args[$i]} == --data-raw ]]; then
      printf '%s\n' "${args[$((i + 1))]}" >>"$OSV_STUB_LOG"
    fi
    i=$((i + 1))
  done
fi
cat "$OSV_STUB_RESPONSE"
EOF
chmod +x "$work/bin/curl"

cat >"$work/purls" <<'EOF'
mise-bin pkg:github/jdx/mise@{version}
EOF

OSV_STUB_RESPONSE="$work/osv.json" PATH="$work/bin:$PATH" \
  "$ROOT/bin/fetch-advisories" --mirror edge --arch x86_64 \
  --feed "$FEED" --purl-map "$work/purls" --package mise-bin >/dev/null

feed_file="$FEED/mise-bin/1.0.0-1/x86_64.json"
[[ -f $feed_file ]] || {
  echo "producer did not write a versioned feed file" >&2
  exit 1
}
[[ $(jq -r '.pkgver' "$feed_file") == 1.0.0 ]] || {
  echo "feed must pin pkgver" >&2
  exit 1
}
[[ $(jq -r '.pkgrel' "$feed_file") == 1 ]] || {
  echo "feed must pin pkgrel" >&2
  exit 1
}
[[ $(jq -r '.scan_source' "$feed_file") == osv.dev ]] || {
  echo "scan_source must be osv.dev" >&2
  exit 1
}
jq -e '.cve_ids | index("CVE-2026-4242")' "$feed_file" >/dev/null || {
  echo "producer must collect CVE ids from OSV aliases" >&2
  exit 1
}
[[ $(jq -r '.cve_max_severity' "$feed_file") == HIGH ]] || {
  echo "CVSS vector with Confidentiality/Integrity/Availability High should map to HIGH" >&2
  exit 1
}

"$ROOT/bin/sync-advisories" --mirror edge --arch x86_64 \
  --feed "$FEED" --no-sign --stale-after 720h >/dev/null

sidecar="$REPO_DIR_TMP/mise-bin-1.0.0-1-x86_64.advisory.json"
[[ $(jq -r '.scan_status' "$sidecar") == ok ]] || {
  echo "ingest of produced feed should scan ok" >&2
  exit 1
}

pkg_hash=$(sha256sum "$REPO_DIR_TMP/mise-bin-1.0.0-1-x86_64.pkg.tar.zst" | awk '{print $1}')
[[ $(jq -r '.cve_ids[0]' "$sidecar") == CVE-2026-4242 ]] || {
  echo "advisory file should carry the produced CVE" >&2
  exit 1
}
[[ $(sha256sum "$REPO_DIR_TMP/mise-bin-1.0.0-1-x86_64.pkg.tar.zst" | awk '{print $1}') == "$pkg_hash" ]] || {
  echo "producer+ingest rewrote the package archive" >&2
  exit 1
}

# Empty vulns means the source has no report yet: do not write a "clean" feed.
printf '{ "vulns": [] }\n' >"$work/osv-empty.json"
rm -f "$feed_file"
OSV_STUB_RESPONSE="$work/osv-empty.json" PATH="$work/bin:$PATH" \
  "$ROOT/bin/fetch-advisories" --mirror edge --arch x86_64 \
  --feed "$FEED" --purl-map "$work/purls" --package mise-bin >/dev/null
[[ ! -f $feed_file ]] || {
  echo "empty OSV vulns must not write a feed (row stays missing)" >&2
  exit 1
}

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

# If mise-bin is hardcoded, also map a second name exclusively via the default file.
OSV_STUB_RESPONSE="$work/osv-default.json" PATH="$work/bin:$PATH" \
  "$ROOT/bin/fetch-advisories" --mirror edge --arch x86_64 \
  --feed "$FEED" --package opr-purl-map-canary >/dev/null
canary_file="$FEED/opr-purl-map-canary/0.0.1-1/x86_64.json"
[[ -f $canary_file ]] || {
  echo "default purl map must supply opr-purl-map-canary without --purl-map" >&2
  exit 1
}
jq -e '.cve_ids | index("CVE-2026-9999")' "$canary_file" >/dev/null || {
  echo "default-map canary feed must collect CVE ids" >&2
  exit 1
}

# New PKGBUILD-backed names must resolve from data/opr-purl-map with no --purl-map.
# Db pkgver is 1.2.3 so the posted purl is the map line with {version} replaced.
map_cases=(
  "aether pkg:github/omacom/aether@1.2.3"
  "asdcontrol pkg:github/omakasui/asdcontrol@1.2.3"
  "asusctl pkg:github/OpenGamingCollective/asusctl@1.2.3"
  "caja-open-any-terminal pkg:github/Stunkymonkey/nautilus-open-any-terminal@1.2.3"
  "cliamp pkg:github/bjarneo/cliamp@1.2.3"
  "crush-bin pkg:github/charmbracelet/crush@1.2.3"
  "cua-driver-bin pkg:github/trycua/cua@1.2.3"
  "dbxcli-bin pkg:github/dropbox/dbxcli@1.2.3"
  "elephant pkg:github/abenz1267/elephant@1.2.3"
  "elephant-all pkg:github/abenz1267/elephant@1.2.3"
  "elephant-archlinuxpkgs pkg:github/abenz1267/elephant@1.2.3"
  "elephant-bluetooth pkg:github/abenz1267/elephant@1.2.3"
  "elephant-calc pkg:github/abenz1267/elephant@1.2.3"
  "elephant-clipboard pkg:github/abenz1267/elephant@1.2.3"
  "elephant-desktopapplications pkg:github/abenz1267/elephant@1.2.3"
  "elephant-files pkg:github/abenz1267/elephant@1.2.3"
  "elephant-menus pkg:github/abenz1267/elephant@1.2.3"
  "elephant-providerlist pkg:github/abenz1267/elephant@1.2.3"
  "elephant-runner pkg:github/abenz1267/elephant@1.2.3"
  "elephant-symbols pkg:github/abenz1267/elephant@1.2.3"
  "elephant-todo pkg:github/abenz1267/elephant@1.2.3"
  "elephant-unicode pkg:github/abenz1267/elephant@1.2.3"
  "elephant-websearch pkg:github/abenz1267/elephant@1.2.3"
  "flea pkg:github/thisisgm/flea@1.2.3"
  "github-copilot-cli pkg:github/github/copilot-cli@1.2.3"
  "herdr pkg:github/herdrdev/herdr@1.2.3"
  "hermes-desktop pkg:github/NousResearch/hermes-agent@1.2.3"
  "heroic-games-launcher-bin pkg:github/Heroic-Games-Launcher/HeroicGamesLauncher@1.2.3"
  "hyprland pkg:github/hyprwm/Hyprland@1.2.3"
  "hyprland-guiutils pkg:github/hyprwm/hyprland-guiutils@1.2.3"
  "hyprland-preview-share-picker pkg:github/WhySoBad/hyprland-preview-share-picker@1.2.3"
  "hyprpm pkg:github/hyprwm/Hyprland@1.2.3"
  "hyprshade pkg:github/loqusion/hyprshade@1.2.3"
  "hyprtoolkit pkg:github/hyprwm/hyprtoolkit@1.2.3"
  "link-studio pkg:github/jweaver60/link-studio@1.2.3"
  "localsend pkg:github/localsend/localsend@1.2.3"
  "makima-bin pkg:github/cyber-sushi/makima@1.2.3"
  "nautilus-dropbox pkg:github/dropbox/nautilus-dropbox@1.2.3"
  "nautilus-open-any-terminal pkg:github/Stunkymonkey/nautilus-open-any-terminal@1.2.3"
  "omacalc pkg:github/omacom-io/omacalc@1.2.3"
  "omacut pkg:github/omacom-io/omacut@1.2.3"
  "omakade pkg:github/btsouth/omakade@1.2.3"
  "omapresent pkg:github/jethrojones/omapresent@1.2.3"
  "omarchy-audio-tuner pkg:github/omacom-io/omarchy-audio-tuner@1.2.3"
  "omarchy-emacs pkg:github/scottjones/omarchy-emacs@1.2.3"
  "omarchy-fish pkg:github/omacom-io/omarchy-fish@1.2.3"
  "omarchy-zsh pkg:github/omacom-io/omarchy-zsh@1.2.3"
  "omareel pkg:github/omacom/omareel@1.2.3"
  "omasnap pkg:github/tobi/omasnap@1.2.3"
  "omawrite pkg:github/omacom-io/omawrite@1.2.3"
  "omazed pkg:github/aps6/omazed@1.2.3"
  "once-bin pkg:github/basecamp/once@1.2.3"
  "openai-codex-bin pkg:github/openai/codex@1.2.3"
  "python-mediapipe pkg:github/google-ai-edge/mediapipe@1.2.3"
  "python-terminaltexteffects pkg:github/ChrisBuilds/terminaltexteffects@1.2.3"
  "qmk-hid pkg:github/FrameworkComputer/qmk_hid@1.2.3"
  "rog-control-center pkg:github/OpenGamingCollective/asusctl@1.2.3"
  "rustdesk pkg:github/rustdesk/rustdesk@1.2.3"
  "schist-bin pkg:github/Infrawrench/schist@1.2.3"
  "slap-notes-bin pkg:github/Onefailatatime/slap-notes@1.2.3"
  "strata pkg:github/lgse/strata@1.2.3"
  "symfony-cli pkg:github/symfony-cli/symfony-cli@1.2.3"
  "t3code-bin pkg:github/pingdotgg/t3code@1.2.3"
  "tensaku pkg:github/jondkinney/tensaku@1.2.3"
  "ttf-jetbrains-mono-nerd-basic pkg:github/ryanoasis/nerd-fonts@1.2.3"
  "ttfx pkg:github/omacom-io/ttfx@1.2.3"
  "tzupdate pkg:github/cdown/tzupdate@1.2.3"
  "ufw-docker pkg:github/chaifeng/ufw-docker@1.2.3"
  "voxtype-bin pkg:github/peteonrails/voxtype@1.2.3"
  "walker pkg:github/abenz1267/walker@1.2.3"
  "wayfreeze pkg:github/Jappie3/wayfreeze@1.2.3"
  "xpadneo-dkms pkg:github/atar-axis/xpadneo@1.2.3"
  "yaru-gnome-shell-theme pkg:github/ubuntu/yaru@1.2.3"
  "yaru-gtk-theme pkg:github/ubuntu/yaru@1.2.3"
  "yaru-gtksourceview-theme pkg:github/ubuntu/yaru@1.2.3"
  "yaru-icon-theme pkg:github/ubuntu/yaru@1.2.3"
  "yaru-metacity-theme pkg:github/ubuntu/yaru@1.2.3"
  "yaru-session pkg:github/ubuntu/yaru@1.2.3"
  "yaru-sound-theme pkg:github/ubuntu/yaru@1.2.3"
  "yaru-unity-theme pkg:github/ubuntu/yaru@1.2.3"
  "yaru-xfwm4-theme pkg:github/ubuntu/yaru@1.2.3"
  "yay pkg:github/Jguer/yay@1.2.3"
)
for case in "${map_cases[@]}"; do
  name=${case%% *}
  mkdir -p "$work/db-stage/$name"
  cat >"$work/db-stage/$name/desc" <<EOF
%FILENAME%
${name}-1.2.3-1-x86_64.pkg.tar.zst
%NAME%
${name}
%VERSION%
1.2.3-1
%ARCH%
x86_64
EOF
done
tar -C "$work/db-stage" -cf "$DB" .

OSV_STUB_LOG="$work/osv-posts.log"
: >"$OSV_STUB_LOG"
for case in "${map_cases[@]}"; do
  name=${case%% *}
  want=${case#* }
  OSV_STUB_RESPONSE="$work/osv-default.json" OSV_STUB_LOG="$OSV_STUB_LOG" PATH="$work/bin:$PATH" \
    "$ROOT/bin/fetch-advisories" --mirror edge --arch x86_64 \
    --feed "$FEED" --package "$name" >/dev/null
  feed_file="$FEED/$name/1.2.3-1/x86_64.json"
  [[ -f $feed_file ]] || {
    echo "default purl map must supply $name without --purl-map" >&2
    exit 1
  }
  posted=$(jq -s -r '.[-1].package.purl' "$OSV_STUB_LOG")
  [[ $posted == "$want" ]] || {
    echo "default map purl for $name: got ${posted:-<none>} want $want" >&2
    exit 1
  }
done

echo "PASS: fetch-advisories writes a version-pinned OSV feed without touching packages"
