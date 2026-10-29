#!/usr/bin/env python3
"""Throwaway PTY relay prototype (not product code). Shows the daemon-owned PTY + raw client model.

  relay.py daemon <sock> <cmd...>   spawn cmd on a PTY, serve one client at a time on <sock>
  relay.py client <sock>            raw-mode relay; resize forwarded; Ctrl-\\ detaches

Client -> daemon frames: [type:1][len:2 BE][payload]; type 0 = input bytes, 1 = resize (rows, cols BE16).
Daemon -> client: raw PTY output. Output while detached is dropped (no scrollback), the app is
asked to redraw with SIGWINCH on every attach/resize.
"""
import fcntl, os, select, signal, socket, struct, sys, termios, tty

LEADER = b"\x1c"  # Ctrl-\


def daemon(path, argv):
    pid, mfd = os.forkpty()
    if pid == 0:
        os.execvp(argv[0], argv)
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(path)
    srv.listen(1)
    cli, buf = None, b""
    while True:
        r, _, _ = select.select([mfd, srv] + ([cli] if cli else []), [], [])
        if mfd in r:
            try:
                d = os.read(mfd, 4096)
            except OSError:
                return
            if not d:
                return
            if cli:
                try:
                    cli.sendall(d)
                except OSError:
                    cli = None
        if srv in r:
            if cli:
                cli.close()
            cli, _ = srv.accept()
            buf = b""
        if cli and cli in r:
            d = cli.recv(4096)
            if not d:
                cli.close()
                cli = None
                continue
            buf += d
            while len(buf) >= 3:
                t, n = buf[0], struct.unpack(">H", buf[1:3])[0]
                if len(buf) < 3 + n:
                    break
                p, buf = buf[3:3 + n], buf[3 + n:]
                if t == 0:
                    os.write(mfd, p)
                elif t == 1:
                    rows, cols = struct.unpack(">HH", p)
                    fcntl.ioctl(mfd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
                    os.killpg(pid, signal.SIGWINCH)  # explicit: also redraws when the size is unchanged


def client(path):
    s = socket.socket(socket.AF_UNIX)
    s.connect(path)

    def send(t, p):
        s.sendall(bytes([t]) + struct.pack(">H", len(p)) + p)

    def resize(*_):
        rows, cols = struct.unpack("HHHH", fcntl.ioctl(1, termios.TIOCGWINSZ, b"\0" * 8))[:2]
        send(1, struct.pack(">HH", rows, cols))

    signal.signal(signal.SIGWINCH, resize)
    old = termios.tcgetattr(0)
    tty.setraw(0)
    try:
        resize()
        while True:
            r, _, _ = select.select([0, s], [], [])
            if 0 in r:
                d = os.read(0, 4096)
                if not d or d == LEADER:
                    break
                send(0, d)
            if s in r:
                d = s.recv(4096)
                if not d:
                    break
                os.write(1, d)
    finally:
        termios.tcsetattr(0, termios.TCSADRAIN, old)


if __name__ == "__main__":
    daemon(sys.argv[2], sys.argv[3:]) if sys.argv[1] == "daemon" else client(sys.argv[2])
