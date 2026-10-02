#!/usr/bin/env bash
# Tests scripts/site-release.sh against the real site/index.html with a
# stand-in gh, so a page edit that breaks the update after a release
# fails CI instead of leaving the published page stale. No network.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Stand-in gh: answers `release list` from FAKE_TAG/FAKE_PRE and
# `release view` with one asset of FAKE_SIZE bytes, or fails when
# FAKE_VIEW_FAIL is set.
mkdir "$work/bin"
cat >"$work/bin/gh" <<'EOF'
#!/usr/bin/env bash
case "$2" in
  list) echo "$FAKE_TAG $FAKE_PRE" ;;
  view)
    [[ -z "${FAKE_VIEW_FAIL:-}" ]] || exit 1
    echo "thawr_${FAKE_TAG}_linux_amd64.tar.gz $FAKE_SIZE"
    ;;
  *) exit 2 ;;
esac
EOF
chmod +x "$work/bin/gh"
export PATH="$work/bin:$PATH" GITHUB_REPOSITORY=Sira-Labs/Thawr

page="$work/index.html"
cp "$root/site/index.html" "$page"
start=$(sed -n 's/.*state = { tag: "\([^"]*\)".*/\1/p' "$page")
links=$(grep -o "$start" "$page" | wc -l)
fails=0

run() { FAKE_TAG=$1 FAKE_PRE=$2 FAKE_SIZE=${3:-8000000} "$root/scripts/site-release.sh" "$page" >/dev/null; }
check() {
  if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; fails=$((fails + 1)); fi
}
count() { grep -o -- "$1" "$page" | wc -l; }

run v9.8.0-rc1 true 8123456
check "pre-release: every link moves to the new tag" '[[ $(count v9.8.0-rc1) -eq $links && $(count "$start") -eq 0 ]]'
check "pre-release: release-candidate note shown" '[[ $(count "data-pre>") -eq 2 && $(count "data-pre hidden>") -eq 0 ]]'
check "pre-release: note names the final version" 'grep -q "<code data-final>v9.8.0</code>" "$page"'
check "pre-release: archive size updated" 'grep -q "<span>8.1 MB</span><small>thawr_v9.8.0-rc1_linux_amd64.tar.gz</small>" "$page"'

run v9.8.0 false
check "stable: no pre-release tag left" '[[ $(count v9.8.0-rc1) -eq 0 && $(count "v9.8.0[/_\"<]") -ge $links ]]'
check "stable: release-candidate note hidden" '[[ $(count "data-pre hidden>") -eq 2 && $(count "data-pre>") -eq 0 ]]'
cp "$page" "$work/once.html"
run v9.8.0 false
check "stable: a second run changes nothing" 'cmp -s "$page" "$work/once.html"'

run v9.8.10-rc1 true
check "next pre-release: v9.8.0 replaced without touching longer tags" '[[ $(count v9.8.10-rc1) -eq $links && $(count "v9\.8\.0[^0-9]") -eq 0 ]]'
check "next pre-release: note shown again" '[[ $(count "data-pre>") -eq 2 ]]'

cp "$page" "$work/before.html"
if FAKE_VIEW_FAIL=1 run v9.8.10-rc1 true; then rc=0; else rc=$?; fi
check "failed size lookup: exits 0 and keeps the page" '[[ $rc -eq 0 ]] && cmp -s "$page" "$work/before.html"'

sed -i 's/data-final/data-gone/' "$page"
if run v9.9.0 false 2>/dev/null; then rc=0; else rc=$?; fi
check "missing marker: fails the deploy" '[[ $rc -ne 0 ]]'

if ((fails)); then
  echo "site-release-test: $fails failed" >&2
  exit 1
fi
echo "site-release-test: all passed"
