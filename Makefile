BINARY_NAME := shellgate
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: build test lint dev install clean fmt vet

build:
	go build -ldflags="$(LDFLAGS)" -o $(BINARY_NAME) ./cmd/shellgate/

build-all: build-linux-amd64 build-linux-arm64 build-darwin-amd64 build-darwin-arm64

build-linux-amd64:
	GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o dist/$(BINARY_NAME)-linux-amd64 ./cmd/shellgate/

build-linux-arm64:
	GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o dist/$(BINARY_NAME)-linux-arm64 ./cmd/shellgate/

build-darwin-amd64:
	GOOS=darwin GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o dist/$(BINARY_NAME)-darwin-amd64 ./cmd/shellgate/

build-darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o dist/$(BINARY_NAME)-darwin-arm64 ./cmd/shellgate/

test:
	go test ./... -race -cover -timeout 30s

test-verbose:
	go test ./... -race -cover -v -timeout 30s

lint:
	golangci-lint run ./...

fmt:
	gofmt -w .

vet:
	go vet ./...

dev:
	go run ./cmd/shellgate/ --verbose --auth none --i-know-what-im-doing

install: build
	cp $(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)
	@echo "Installed $(BINARY_NAME) to /usr/local/bin/"

clean:
	rm -f $(BINARY_NAME)
	rm -rf dist/

check: fmt vet test lint
	@echo "All checks passed."
