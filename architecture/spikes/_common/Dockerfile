# Shared spike image. Pin by digest once resolved: `docker buildx imagetools inspect debian:trixie-slim`
# and pass --build-arg DEBIAN=debian@sha256:... (and GO=golang@sha256:...).
ARG GO=golang:1.27
ARG DEBIAN=debian:trixie-slim
FROM ${GO} AS go

FROM ${DEBIAN}
RUN apt-get update && apt-get install -y --no-install-recommends \
      bubblewrap util-linux iproute2 iperf3 procps ca-certificates python3 tmux git curl passt \
    && rm -rf /var/lib/apt/lists/*
COPY --from=go /usr/local/go /usr/local/go
ENV PATH=/usr/local/go/bin:$PATH GOFLAGS=-mod=mod
COPY lib.sh fixture.sh /spike/
WORKDIR /spike
