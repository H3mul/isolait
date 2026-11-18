# Fast checks run everywhere; the security tier needs real user namespaces (see docs/security-tests.md).
GO ?= go

.PHONY: all build check test security canary mutations isolation e2e audit-fetch audit-update audit

all: check test

build:
	$(GO) build -o isolait .

# formatting and vet, including the security-tagged files
check:
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }
	$(GO) vet ./...
	$(GO) vet -tags security ./...

# fast tier: units, parsers, protocol, plan; no kernel features needed
test:
	$(GO) test -race ./...

# fast tier plus real-kernel tests of the sandbox (user namespaces, bwrap, mounts, cgroups)
security:
	$(GO) test -race -tags security ./...

# only the host-assumption canaries: run these after a kernel, bwrap or systemd upgrade
canary:
	$(GO) test -tags security -count=1 -run Canary -v ./internal/canary

# apply every mutation in scripts/mutations.py to a scratch copy and require a test to fail
mutations:
	python3 scripts/mutations.py

# the CI gate over the sandbox's core guarantees; fails if any of its tests was skipped
isolation:
	./scripts/isolation.sh

# the whole user workflow (start, detach, attach, exec, mounts, ports, agent restart, stop) on the real kernel
e2e:
	$(GO) test -tags security -count=1 -v -run TestFullWorkflow ./internal/cli

audit-fetch:
	./scripts/audit/fetch.sh

audit-update:
	./scripts/audit/update.sh

audit:
	./scripts/audit/run.sh
