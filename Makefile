BINARY := rig
BUILD_DIR := bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
PREFIX := /usr/local
GO := $(shell command -v go 2>/dev/null || echo "$(HOME)/go-sdk/go/bin/go")

.PHONY: all build run test race clean fmt vet check install uninstall user-install

all: check build

build:
	$(GO) build -ldflags "-s -w -X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY) ./cmd/rig

run: build
	./$(BUILD_DIR)/$(BINARY)

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

# What CI runs.
check: vet test

clean:
	rm -rf $(BUILD_DIR)

install: build
	@echo "Installing rig to $(PREFIX)/bin..."
	@sudo install -m 755 $(BUILD_DIR)/$(BINARY) $(PREFIX)/bin/$(BINARY)
	@echo "rig installed. Run 'rig' from anywhere to get started."

uninstall:
	@echo "Removing rig from $(PREFIX)/bin..."
	@sudo rm -f $(PREFIX)/bin/$(BINARY)
	@echo "rig uninstalled."

user-install: build
	@mkdir -p $(HOME)/.local/bin
	@install -m 755 $(BUILD_DIR)/$(BINARY) $(HOME)/.local/bin/$(BINARY)
	@echo "rig installed to ~/.local/bin/rig"
	@echo "Make sure ~/.local/bin is in your PATH."
