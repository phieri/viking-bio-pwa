.PHONY: all build run test clean

BINARY ?= viking-bio-proxy
GO = go

all: build

build:
	$(GO) build -o $(BINARY) ./cmd/proxy

run:
	$(GO) run ./cmd/proxy

test:
	$(GO) test ./...

clean:
	rm -f $(BINARY)
