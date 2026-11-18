#!/bin/bash
# make audit: run the pinned third-party tools inside a throwaway isolait session (own runtime, state and config
# directories, so no user session is listed or touched) and collect their output under build/audit/<date>/.
set -u
here=$(cd "$(dirname "$0")" && pwd); root=$(cd "$here/../.." && pwd)
cache=${XDG_CACHE_HOME:-$HOME/.cache}/isolait-audit
base=$(mktemp -d "${TMPDIR:-/tmp}/isolait-audit.XXXXXX")
export XDG_RUNTIME_DIR=$base/rt XDG_STATE_HOME=$base/state XDG_CONFIG_HOME=$base/cfg
cleanup() {
	"$base/bin/isolait" kill-server >/dev/null 2>&1
	rm -rf "$base"
}
trap cleanup EXIT
trap 'echo interrupted >&2; exit 130' INT TERM
mkdir -p "$XDG_RUNTIME_DIR" "$XDG_STATE_HOME" "$XDG_CONFIG_HOME" "$base/bin" "$base/ws/out" "$base/tools"
chmod 700 "$XDG_RUNTIME_DIR"
(cd "$root" && go build -o "$base/bin/isolait" .) || exit 1

# tools: re-verify every pinned file, then copy into one read-only directory
while read -r name version url sha size; do
	case $name in ''|'#'*) continue ;; esac
	f=$cache/$sha/$name
	[ -f "$f" ] && [ "$(sha256sum "$f" | cut -d' ' -f1)" = "$sha" ] || { echo "$name is missing or does not match tools.lock: run make audit-fetch" >&2; exit 1; }
	cp "$f" "$base/tools/$name"
done < "$here/tools.lock"
cp "$here/driver.sh" "$base/ws/driver.sh"

date=$(date -u +%F); dest=$root/build/audit/$date
mkdir -p "$dest"
cd "$base/ws" || exit 1
"$base/bin/isolait" start -d bash /workspaces/ws/driver.sh || exit 1
"$base/bin/isolait" mount --ro --as tools "$base/tools" || exit 1
# the session ends with the driver
for i in $(seq 1 $((${AUDIT_WAIT:-1500}))); do
	"$base/bin/isolait" list 2>&1 | grep -q 'no sessions running' && break
	sleep 1
done
for f in "$base"/ws/out/*; do [ -e "$f" ] && sed -E 's/\x1b\[[0-9;?]*[A-Za-z]//g; s/\x1b\][^\x07]*\x07//g' "$f" > "$dest/$(basename "$f")"; done
[ -f "$dest/finished" ] || { echo "the driver did not finish" >&2; exit 1; }
cp "$here/tools.lock" "$dest/tools.lock"
echo "outputs in $dest"
cd "$root" && go run ./internal/audit/cmd "$dest"
