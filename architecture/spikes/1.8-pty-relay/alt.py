#!/usr/bin/env python3
"""Fake alt-screen TUI (OpenCode-like): full redraw on SIGWINCH, echoes keys."""
import os, signal, sys, tty

def draw(*_):
    rows, cols = os.get_terminal_size(0)[1], os.get_terminal_size(0)[0]
    sys.stdout.write(f"\x1b[2J\x1b[H ALT size={rows}x{cols}\x1b[{rows};1Hbottom-row")
    sys.stdout.flush()

tty.setraw(0)
sys.stdout.write("\x1b[?1049h")
signal.signal(signal.SIGWINCH, draw)
draw()
while True:
    d = os.read(0, 100)
    sys.stdout.write(f"\x1b[3;1Hgot:{d.decode()}")
    sys.stdout.flush()
