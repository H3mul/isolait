#!/bin/bash
. /spike/lib.sh
# The relay prototype is driven inside tmux panes, used only as a terminal emulator to read the screen.
S=$(mktemp -d); T="tmux -L spike"
cap() { $T capture-pane -p -t "$1"; }
screen_has() { cap "$1" | grep -q -- "$2"; }

run_app() {  # run_app <name> <app.py> <expect-after-attach-extra>
  local n=$1 app=$2 sock=$S/$1.sock
  python3 /spike/case/relay.py daemon "$sock" python3 "/spike/case/$app" & local D=$!
  poll "$n-daemon-up" 5 test -S "$sock"

  $T new-session -d -s "$n-a" -x 80 -y 24 "python3 /spike/case/relay.py client $sock"
  poll "$n-attach-draws-at-80x24" 5 screen_has "$n-a" "size=24x80"

  $T send-keys -t "$n-a" x
  poll "$n-keystroke-reaches-app" 5 screen_has "$n-a" "got:x"

  $T resize-window -t "$n-a" -x 100 -y 30
  poll "$n-resize-forwarded-and-redrawn" 5 screen_has "$n-a" "size=30x100"

  $T send-keys -t "$n-a" 'C-\'
  poll "$n-leader-detaches-client" 5 bash -c "! $T has-session -t $n-a"
  kill -0 $D 2>/dev/null && pass "$n-app-survives-detach" || fail "$n-app-survives-detach"

  $T new-session -d -s "$n-b" -x 60 -y 20 "python3 /spike/case/relay.py client $sock"
  poll "$n-reattach-redraws-at-new-size" 5 screen_has "$n-b" "size=20x60"
  [ "$n" = inline ] && { screen_has "$n-b" "INLINE-HISTORY" && fail "inline-no-scrollback" "history was replayed (unexpected)" || pass "inline-no-scrollback-as-designed"; }
  $T kill-server 2>/dev/null; kill $D 2>/dev/null; wait $D 2>/dev/null
}
run_app alt alt.py
run_app inline inline.py
finish
