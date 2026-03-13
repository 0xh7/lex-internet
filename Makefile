GO ?= go
GOFMT ?= gofmt
GOOS ?=
GOARCH ?= amd64
BIN_DIR ?= bin
CMDS := $(notdir $(wildcard cmd/*))
GOFILES := $(shell find cmd pkg -name '*.go')
BIN_EXT := $(if $(filter windows,$(GOOS)),.exe,)
BIN_SUBDIR := $(if $(GOOS),$(GOOS)-$(GOARCH),host)
BIN_OUT := $(BIN_DIR)/$(BIN_SUBDIR)

.PHONY: all build build-linux build-windows c c-linux c-windows fmt test vet clean verify verify-linux verify-windows

all: verify

build:
	mkdir -p $(BIN_OUT)
	for cmd in $(CMDS); do GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build -o $(BIN_OUT)/$$cmd$(BIN_EXT) ./cmd/$$cmd || exit 1; done

build-linux:
	$(MAKE) build GOOS=linux GOARCH=amd64

build-windows:
	$(MAKE) build GOOS=windows GOARCH=amd64

c:
	$(MAKE) -C c

c-linux:
	$(MAKE) -C c clean
	$(MAKE) -B -C c CC=gcc AR=ar

c-windows:
	$(MAKE) -C c clean
	$(MAKE) -B -C c CC=x86_64-w64-mingw32-gcc AR=x86_64-w64-mingw32-ar

fmt:
	$(GOFMT) -w $(GOFILES)

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

clean:
	find $(BIN_DIR) -type f -delete 2>/dev/null || true
	find $(BIN_DIR) -depth -type d -empty -delete 2>/dev/null || true
	$(MAKE) -C c clean

verify: test vet build c

verify-linux:
	$(MAKE) build-linux
	$(MAKE) c-linux

verify-windows:
	$(MAKE) build-windows
	$(MAKE) c-windows
