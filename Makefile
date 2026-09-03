.PHONY: build test lint clean release deps tidy dev-ui build-ui build-ui-windows build-all

BINARY     = idenaro
CMD        = ./cmd/scanner
BIN_DIR    = bin
DIST_DIR   = dist

# Falls back to /usr/local/go/bin/go for machines where `go` isn't on PATH
# in a non-interactive shell; CI (actions/setup-go) puts `go` on PATH, so
# the PATH lookup wins there.
GO             := $(shell command -v go 2>/dev/null || echo /usr/local/go/bin/go)
GOBIN          := $(shell dirname $(GO))
WAILS          := $(shell $(GO) env GOPATH)/bin/wails
WAILS_BIN_DIR  := cmd/wails/build/bin

build:
	$(GO) build -ldflags="-s -w" -o $(BIN_DIR)/$(BINARY) $(CMD)

run: build
	./$(BIN_DIR)/$(BINARY)

# cmd/wails is excluded: it go:embeds frontend/dist, which only exists after
# `npm run build` (see build-ui).
test:
	$(GO) test $$($(GO) list ./... | grep -v /cmd/wails) -v -count=1

lint:
	golangci-lint run $$($(GO) list ./... | grep -v /cmd/wails)

tidy:
	$(GO) mod tidy

deps:
	$(GO) mod download

clean:
	rm -rf $(BIN_DIR) $(DIST_DIR)

release:
	mkdir -p $(DIST_DIR)
	GOOS=linux   GOARCH=amd64 $(GO) build -ldflags="-s -w" -o $(DIST_DIR)/$(BINARY)-linux-amd64   $(CMD)
	GOOS=windows GOARCH=amd64 $(GO) build -ldflags="-s -w" -o $(DIST_DIR)/$(BINARY)-windows.exe   $(CMD)
	@echo "Release binaries:"
	@ls -lh $(DIST_DIR)/

scan-test:
	./$(BIN_DIR)/$(BINARY) scan --target example.com -v

scan-json:
	./$(BIN_DIR)/$(BINARY) scan --target example.com --format json | jq '.summary'

# ── Wails UI (desktop app) ──────────────────────────────────────────────
# Requires: wails CLI installed (go install github.com/wailsapp/wails/v2/cmd/wails@latest)

dev-ui:
	cd cmd/wails && PATH="$(GOBIN):$$PATH" $(WAILS) dev

WAILS_OUT = idenaro

build-ui:
	mkdir -p $(DIST_DIR)
	cd cmd/wails/frontend && npm ci && npm run build
	cd cmd/wails && PATH="$(GOBIN):$$PATH" $(WAILS) build -s
	cp $(WAILS_BIN_DIR)/$(WAILS_OUT) $(DIST_DIR)/idenaro-ui-linux-amd64

# Requires: sudo apt-get install mingw-w64
build-ui-windows:
	mkdir -p $(DIST_DIR)
	cd cmd/wails/frontend && npm ci && npm run build
	cd cmd/wails && CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc PATH="$(GOBIN):$$PATH" \
		$(WAILS) build -platform windows/amd64 -s
	cp $(WAILS_BIN_DIR)/$(WAILS_OUT).exe $(DIST_DIR)/idenaro-ui-windows.exe

build-all: release build-ui build-ui-windows
