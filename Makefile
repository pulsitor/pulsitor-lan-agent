VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)
TARGETS := linux/amd64 linux/arm64 linux/arm linux/386 darwin/arm64 darwin/amd64 windows/amd64 windows/386 windows/arm64

# The matrix vet has caught more than the local one ever has: three of the four files
# that matter here compile only on one platform each, so building for this machine
# proves almost nothing about the release.
VET_TARGETS := $(TARGETS) freebsd/amd64

.PHONY: build test vet vet-all check dist clean install

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o pulsitor-lan-agent ./cmd/pulsitor-lan-agent

test:
	go test ./...

vet:
	go vet ./...

# Compiles and vets every platform-specific file, including the tests, without needing
# one machine of each.
vet-all:
	@for target in $(VET_TARGETS); do \
		printf '  %-16s' $$target; \
		CGO_ENABLED=0 GOOS=$${target%/*} GOARCH=$${target#*/} go vet ./... || exit 1; \
		echo ok; \
	done

check: vet-all test

# Every target is CGO-free, so one machine builds the whole fleet and each artefact is a
# single file with nothing to install alongside it. -trimpath keeps the build machine's
# directory layout out of the binary, which also makes the build reproducible: the same
# source and version stamp produce the same bytes, and the checksums below are worth
# something as a result.
dist: check
	@rm -rf dist && mkdir -p dist
	@for target in $(TARGETS); do \
		os=$${target%/*}; arch=$${target#*/}; \
		out=dist/pulsitor-lan-agent-$$os-$$arch; \
		if [ "$$os" = "windows" ]; then out=$$out.exe; fi; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o $$out ./cmd/pulsitor-lan-agent || exit 1; \
		echo "  $$out"; \
	done
	@cp packaging/install.sh packaging/install.ps1 dist/
	@cd dist && if command -v sha256sum >/dev/null 2>&1; then \
		sha256sum * > SHA256SUMS; \
	else \
		shasum -a 256 * > SHA256SUMS; \
	fi
	@echo "  dist/SHA256SUMS"

# Installs this machine's build as a service. Needs root, and an enrollment token the
# first time. The endpoint is compiled in, so SERVER is only for pointing a build at a
# development server:
#
#   sudo make install ENROLL=<token>
#   sudo make install ENROLL=<token> SERVER=http://127.0.0.1:8123
install: build
	./pulsitor-lan-agent service install $(if $(SERVER),--server "$(SERVER)",) $(if $(ENROLL),--enroll "$(ENROLL)",)

clean:
	rm -rf dist pulsitor-lan-agent
