#!/usr/bin/env python3
"""Fake inline TUI (Claude Code-like): no alt screen; redraws only its footer line on SIGWINCH."""
import os, signal, sys, tty

def size():
    c, r = os.get_terminal_size(0)
    return f"{r}x{c}"

def redraw(*_):
    sys.stdout.write(f"\x1b[A\r\x1b[Kfooter size={size()}\r\n")  # cursor sits one line below the footer
    sys.stdout.flush()

tty.setraw(0)
signal.signal(signal.SIGWINCH, redraw)
sys.stdout.write(f"INLINE-HISTORY\r\nfooter size={size()}\r\n")
sys.stdout.flush()
while True:
    d = os.read(0, 100)
    sys.stdout.write(f"got:{d.decode()}\r\n")
    sys.stdout.flush()
