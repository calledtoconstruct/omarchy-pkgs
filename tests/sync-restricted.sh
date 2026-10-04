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
printf '{ "schema": 1, "pkgname": "mise-bin", "scan_status": "ok" }\n' >"$from/stable/x86_64/mise-bin-1.0-1-x86_64.advisory.json"

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
[[ ! -e $to/restricted/x86_64/mise-bin-1.0-1-x86_64.advisory.json ]] || {
  echo "advisory for a non-allowlisted package leaked" >&2
  exit 1
}
[[ ! -e $to/restricted/x86_64/mise-bin-1.0-1-x86_64.pkg.tar.zst ]] || {
  echo "non-allowlisted package leaked into restricted" >&2
  exit 1
}

# Unsigned allowlisted package must fail.
unsigned="$work/unsigned"
mkdir -p "$unsigned/from/stable/x86_64" "$unsigned/to"
: >"$unsigned/from/stable/x86_64/omarchy-1.0-1-x86_64.pkg.tar.zst"
if "$ROOT/bin/sync-restricted" --from-root "$unsigned/from" --to-root "$unsigned/to" --arch x86_64 \
  --allowlist "$ROOT/data/restricted/allowlist"; then
  echo "unsigned allowlisted package should fail" >&2
  exit 1
fi

echo "PASS: sync-restricted copies allowlisted signed packages only"
