#!/usr/bin/env python3
"""pingpong.py host port [n]: prints the p50 round trip in microseconds of 1-byte exchanges."""
import socket, sys, time
s = socket.create_connection((sys.argv[1], int(sys.argv[2])))
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
n = int(sys.argv[3]) if len(sys.argv) > 3 else 2000
t = []
for _ in range(n):
    a = time.perf_counter(); s.sendall(b"x"); s.recv(1); t.append(time.perf_counter() - a)
t.sort(); print(int(t[len(t) // 2] * 1e6))
