# 1.6 gVisor netstack behind a TAP, vs pasta (gate for design Decision 5)

**Question:** can `netd` drive a TAP in the sandbox netns with gVisor netstack (TCP forward + DNS) fast
enough and correctly enough, and does gVisor build under Go 1.27?

**Approach:** `probe/` is a ~200-line Go program (go.mod/go.sum pin gVisor
`v0.0.0-20261029184504-f8fcbd195117`): the TAP is created by a locked thread that `setns`es into the
sandbox netns; netstack runs an ARP+IPv4 NIC (promiscuous, spoofing), a TCP forwarder that dials upstream
*before* completing the guest handshake, and a UDP:53 relay (other UDP dropped). The guest address is
configured with `nsenter ... ip`; product code does this over netlink. Fixtures (`fixtures.py`) replace the
internet: guest `203.0.113.10` is remapped to `127.0.0.1`, and a fake DNS answers `*.test`.

**Matrix:** DNS, HTTP download, chunked-streaming latency (first byte < 0.5 s while the stream lasts
>= 0.8 s), `git clone` from a local `git daemon`, 200 small requests with 50 parallel, closed port gives
curl exit 7 in < 2 s, non-DNS UDP dropped. **Deviation:** no node/npm in the image, so `npm install` is
represented by the parallel small-request burst; do the real `npm install` in task 5.6.

**Thresholds:** median of 5 iperf3 runs >= 500 Mbit/s; added p50 (1-byte ping-pong through the stack minus
the same over direct loopback) < 1000 us. pasta is measured the same way as a fallback reference (informational).

**TUN:** the host needs the `tun` driver (`grep tun /proc/misc`); `run.sh` allows `c 10:200` and the
test `mknod`s `/dev/net/tun`, so no `--device` or `--privileged`. Reported as SKIP when unusable.

**Run:** `./run.sh` (first run needs network once, to fetch the pinned module).

## Result (2026-10-29, WSL2 kernel 6.18, Go 1.27.3, bwrap 0.13.1, Docker 29.9.1)
All PASS. Measured (median of 5):

| | throughput | RTT p50 | added vs loopback |
|---|---|---|---|
| netstack (naive fdbased, no offload) | ~1.5 Gbit/s | ~320 us | ~230 us |
| pasta | ~12-13 Gbit/s | ~180 us | ~90 us |

**Verdict: GO** for Decision 5 (passes both gates with 3x margin on throughput). pasta is ~8x faster on
bulk throughput; netstack has headroom unexplored here (vnet-header/GSO offload, multiple queues,
tuned buffers) if agents ever need it. Not verified: IPv6-disabled guest (task 5.2), dial-time policy (5.5),
and a real `npm install`.
