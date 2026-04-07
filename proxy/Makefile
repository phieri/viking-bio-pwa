.PHONY: all build run test clean configure

BINARY ?= viking-bio-proxy
GO = go

all: build

build:
	$(GO) build -o $(BINARY) ./cmd/proxy

run:
	$(GO) run ./cmd/proxy

configure:
	$(GO) run ./cmd/proxy -- --configure

test:
	$(GO) test ./...

clean:
	rm -f $(BINARY)
