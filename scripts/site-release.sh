#!/usr/bin/env bash
# Points the product page at the newest published release (pre-releases
# included): rewrites the release tag in its download links and snippets
# and the archive sizes, so the page is right without JavaScript and when
# the GitHub API is rate-limited. Run by the pages workflow before upload.
# Needs gh with GH_TOKEN and GITHUB_REPOSITORY set.
set -euo pipefail

page=${1:-site/index.html}
repo=${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}

tag=$(gh release list --repo "$repo" --exclude-drafts --limit 1 --json tagName --jq '.[0].tagName')
old=$(sed -n 's/.*state = { tag: "\([^"]*\)".*/\1/p' "$page")
if [[ -z "$tag" || -z "$old" ]]; then
  echo "site-release: no release or no tag in $page; page left as is" >&2
  exit 0
fi
if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]]; then
  echo "site-release: unexpected tag $tag" >&2
  exit 1
fi
if [[ "$tag" != "$old" ]]; then
  sed -i "s/${old//./\\.}/$tag/g" "$page"
fi
# The sizes are cosmetic: a failed lookup keeps the old ones.
if assets=$(gh release view "$tag" --repo "$repo" --json assets --jq '.assets[] | "\(.name) \(.size)"'); then
  while read -r name size; do
    mb=$(awk -v s="$size" 'BEGIN { printf "%.1f MB", s / 1e6 }')
    sed -i "s|<span>[0-9.]* MB</span><small>${name//./\\.}</small>|<span>${mb}</span><small>${name}</small>|" "$page"
  done <<<"$assets"
else
  echo "site-release: could not read the assets of $tag; sizes left as they were" >&2
fi
echo "site-release: $page points at $tag"
