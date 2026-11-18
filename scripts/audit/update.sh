#!/bin/sh
# Print the lock lines for the newest upstream files; never writes tools.lock. A human reviews and commits.
set -eu
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
lp=$(gh api repos/peass-ng/PEASS-ng/releases/latest --jq .tag_name)
dc=$(gh api repos/stealthcopter/deepce/commits/main --jq .sha)
bt=$(gh api repos/brompwnie/botb/releases/latest --jq .tag_name)
for e in "linpeas $lp https://github.com/peass-ng/PEASS-ng/releases/download/$lp/linpeas.sh" \
         "deepce $(echo "$dc" | cut -c1-12) https://raw.githubusercontent.com/stealthcopter/deepce/$dc/deepce.sh" \
         "botb $bt https://github.com/brompwnie/botb/releases/download/$bt/botb-linux-amd64"; do
	set -- $e
	curl -fsSL -o "$tmp/$1" "$3"
	echo "$1 $2 $3 $(sha256sum "$tmp/$1" | cut -d' ' -f1) $(wc -c < "$tmp/$1")"
done > "$tmp/proposed"
grep -v '^#' "$(dirname "$0")/tools.lock" | diff -u - "$tmp/proposed" || true
