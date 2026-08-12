.PHONY: build test lint clean release deps tidy

BINARY     = idenaro
CMD        = ./cmd/scanner
BIN_DIR    = bin
DIST_DIR   = dist

build:
	go build -ldflags="-s -w" -o $(BIN_DIR)/$(BINARY) $(CMD)

run: build
	./$(BIN_DIR)/$(BINARY)

test:
	go test ./... -v -count=1

lint:
	golangci-lint run ./...

tidy:
	go mod tidy

deps:
	go mod download

clean:
	rm -rf $(BIN_DIR) $(DIST_DIR)

release:
	mkdir -p $(DIST_DIR)
	GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o $(DIST_DIR)/$(BINARY)-linux-amd64   $(CMD)
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o $(DIST_DIR)/$(BINARY)-windows.exe   $(CMD)
	@echo "Release binaries:"
	@ls -lh $(DIST_DIR)/

scan-test:
	./$(BIN_DIR)/$(BINARY) scan --target example.com -v

scan-json:
	./$(BIN_DIR)/$(BINARY) scan --target example.com --format json | jq '.summary'
