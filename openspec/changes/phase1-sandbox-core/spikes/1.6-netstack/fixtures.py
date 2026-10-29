#!/usr/bin/env python3
"""Local fixture servers (no internet): HTTP on 9100, TCP echo on 9200, UDP DNS on 5353."""
import socket, socketserver, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BODY = b"x" * 50000

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    def log_message(self, *a): pass
    def do_GET(self):
        self.send_response(200); self.end_headers()
        if self.path == "/stream":          # 5 chunks 0.2s apart; a buffering path would deliver them at the end
            for i in range(5):
                self.wfile.write(b"chunk%d\n" % i); self.wfile.flush(); time.sleep(0.2)
        else:
            self.wfile.write(BODY)

class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        while (d := self.request.recv(4096)):
            self.request.sendall(d)

def dns():  # answers every A query with 203.0.113.10
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 5353))
    while True:
        q, a = s.recvfrom(512)
        end = 12
        while q[end]: end += q[end] + 1
        end += 5  # root label + qtype + qclass
        r = q[:2] + b"\x81\x80" + q[4:6] + b"\x00\x01\x00\x00\x00\x00" + q[12:end] \
            + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes([203, 0, 113, 10])
        s.sendto(r, a)

class TS(socketserver.ThreadingTCPServer): allow_reuse_address = True; daemon_threads = True
threading.Thread(target=dns, daemon=True).start()
threading.Thread(target=TS(("127.0.0.1", 9200), Echo).serve_forever, daemon=True).start()
ThreadingHTTPServer(("127.0.0.1", 9100), H).serve_forever()
