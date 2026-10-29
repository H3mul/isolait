#!/bin/sh
# Builds the shared spike image once. Run this before any spike's run.sh (run-all.sh does it for you).
# Extra args go to `docker build`, e.g. --build-arg DEBIAN=debian@sha256:... --build-arg GO=golang@sha256:...
exec docker build -t isolait-spike "$(dirname "$0")" "$@"
