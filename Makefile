# Makefile for tls-scanner

BINARY_NAME = tls-scanner
BUILD_DIR   = bin

GOCMD   = go
GOBUILD = $(GOCMD) build
GOCLEAN = $(GOCMD) clean
GOTEST  = $(GOCMD) test
GOMOD   = $(GOCMD) mod

GOLANGCI_LINT_VERSION = v2.12.2

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)

.PHONY: all
all: build

.PHONY: build
build:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GOBUILD) -mod=readonly -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/tls-scanner

.PHONY: clean
clean:
	$(GOCLEAN)
	rm -rf $(BUILD_DIR) coverage.out

.PHONY: deps
deps:
	$(GOMOD) download
	$(GOMOD) tidy

.PHONY: test
test:
	$(GOTEST) -v -short ./...

.PHONY: bench
bench:
	$(GOTEST) -bench=. -benchmem -short ./internal/...

.PHONY: bench-integration
bench-integration:
	$(GOTEST) -v -run Integration -count=1 -timeout=600s ./internal/scanner/

.PHONY: vet
vet:
	$(GOCMD) vet ./...

.PHONY: fmt-check
fmt-check:
	@test -z "$$(gofmt -l $$(find . -name '*.go' -not -path './vendor/*'))" || \
		(echo "Run gofmt on the files above" && gofmt -l $$(find . -name '*.go' -not -path './vendor/*') && exit 1)

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: lint-fix
lint-fix:
	golangci-lint run --fix ./...

.PHONY: govulncheck
govulncheck:
	govulncheck ./...

.PHONY: coverage
coverage:
	$(GOTEST) -short -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -func=coverage.out

.PHONY: check
check: fmt-check vet lint govulncheck test

.PHONY: tools
tools:
	$(GOCMD) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	$(GOCMD) install golang.org/x/vuln/cmd/govulncheck@latest

.PHONY: install
install:
	$(GOCMD) install ./cmd/tls-scanner

.PHONY: run
run: build
	./$(BUILD_DIR)/$(BINARY_NAME)

.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build          - Build the binary"
	@echo "  clean          - Clean build artifacts"
	@echo "  deps           - Download and tidy dependencies"
	@echo "  test           - Run tests (skips integration)"
	@echo "  bench          - Run benchmarks (parsing, no network)"
	@echo "  bench-integ    - Run integration benchmarks (requires testssl.sh)"
	@echo "  vet            - Run go vet"
	@echo "  fmt-check      - Verify gofmt formatting"
	@echo "  lint           - Run golangci-lint"
	@echo "  lint-fix            - Auto-fix lint and formatting issues"
	@echo "  govulncheck    - Run govulncheck for known vulnerabilities"
	@echo "  coverage       - Run tests with coverage report"
	@echo "  check          - Run all checks (fmt, vet, lint, vulncheck, test)"
	@echo "  tools          - Install golangci-lint and govulncheck"
	@echo "  install        - Install binary to GOPATH/bin"
	@echo "  run            - Build and run with default parameters"
	@echo "  help           - Show this help message"
