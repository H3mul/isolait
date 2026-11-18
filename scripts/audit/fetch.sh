#!/bin/sh
# Download the pinned audit tools into ${XDG_CACHE_HOME:-~/.cache}/isolait-audit/<sha256>/<name>.
# Each file gets its own new directory; the checksum is verified before anything else touches the file; the file is
# made 0555; a mismatch deletes it and fails. Nothing here executes a downloaded file.
set -eu
lock=${LOCK:-$(dirname "$0")/tools.lock}
cache=${XDG_CACHE_HOME:-$HOME/.cache}/isolait-audit
status=0
while read -r name version url sha size; do
	case $name in ''|'#'*) continue ;; esac
	dir=$cache/$sha
	if [ -f "$dir/$name" ] && [ "$(sha256sum "$dir/$name" | cut -d' ' -f1)" = "$sha" ]; then
		echo "ok       $name $version (cached)"; continue
	fi
	rm -rf "$dir"; mkdir -p "$dir"
	tmp=$dir/.download
	if ! curl -fsSL --max-time 300 -o "$tmp" "$url"; then
		echo "FAILED   $name: cannot download $url" >&2; rm -rf "$dir"; status=1; continue
	fi
	got=$(sha256sum "$tmp" | cut -d' ' -f1)
	if [ "$got" != "$sha" ]; then
		echo "FAILED   $name: sha256 $got, pinned $sha" >&2; rm -rf "$dir"; status=1; continue
	fi
	mv "$tmp" "$dir/$name"; chmod 0555 "$dir/$name" "$dir"
	echo "fetched  $name $version"
done < "$lock"
exit $status
