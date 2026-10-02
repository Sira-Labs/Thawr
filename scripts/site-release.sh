#!/usr/bin/env bash
# Points the product page at the newest published release (pre-releases
# included): rewrites the release tag in its download links and snippets,
# the archive sizes, and the release-candidate note (shown for a
# pre-release, hidden for a stable one), so the page is right without
# JavaScript and when the GitHub API is rate-limited. Run by the pages
# workflow before upload; scripts/site-release-test.sh covers it in CI.
# Needs gh with GH_TOKEN and GITHUB_REPOSITORY set.
set -euo pipefail

page=${1:-site/index.html}
repo=${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}

latest=$(gh release list --repo "$repo" --exclude-drafts --limit 1 --json tagName,isPrerelease \
  --jq '.[0] | "\(.tagName) \(.isPrerelease)"')
read -r tag pre <<<"$latest"
if [[ -z "${tag:-}" || "$tag" == null ]]; then
  echo "site-release: no published release; page left as is" >&2
  exit 0
fi
semver='^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'
if [[ ! "$tag" =~ $semver ]]; then
  echo "site-release: unexpected tag $tag" >&2
  exit 1
fi
# A page edit that drops these markers would leave the page silently
# stale after every release; fail the deploy instead.
old=$(sed -n 's/.*state = { tag: "\([^"]*\)".*/\1/p' "$page")
for marker in 'state = { tag: "' 'data-pre' 'data-final'; do
  if ! grep -q "$marker" "$page"; then
    echo "site-release: $page has no $marker marker; cannot point it at $tag" >&2
    exit 1
  fi
done
if [[ ! "$old" =~ $semver ]]; then
  echo "site-release: $page holds no valid release tag (state.tag is \"$old\")" >&2
  exit 1
fi

# Whole tags only: neither neighbour may be a letter, digit, dot or dash
# (_ / " < and spaces are fine), so v0.1.0 never matches inside
# v0.1.0-rc7, v0.1.10 or dev0.1.0. The lookarounds consume nothing, so
# back-to-back tags are all replaced.
if [[ "$tag" != "$old" ]]; then
  OLD=$old NEW=$tag perl -pi -e 's/(?<![0-9A-Za-z.\-])\Q$ENV{OLD}\E(?![0-9A-Za-z.\-])/$ENV{NEW}/g' "$page"
fi
if [[ "$pre" == true ]]; then
  sed -i 's/data-pre hidden>/data-pre>/g' "$page"
else
  sed -i 's/data-pre>/data-pre hidden>/g' "$page"
fi
sed -i "s|<code data-final>[^<]*</code>|<code data-final>${tag%%-*}</code>|g" "$page"

# The sizes are cosmetic: a failed lookup keeps the old ones.
if assets=$(gh release view "$tag" --repo "$repo" --json assets --jq '.assets[] | "\(.name) \(.size)"'); then
  while read -r name size; do
    [[ -n "$name" ]] || continue
    mb=$(awk -v s="$size" 'BEGIN { printf "%.1f MB", s / 1e6 }')
    sed -i "s|<span>[0-9.]* MB</span><small>${name//./\\.}</small>|<span>${mb}</span><small>${name}</small>|" "$page"
  done <<<"$assets"
else
  echo "site-release: could not read the assets of $tag; sizes left as they were" >&2
fi
echo "site-release: $page points at $tag (pre-release: $pre)"
