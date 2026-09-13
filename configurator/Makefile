.PHONY: all build build-headless run test clean

BINARY ?= viking-bio-configurator
GO = go
CGO_ENABLED ?= 1

all: build

build:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build -o $(BINARY) ./cmd/configurator

build-headless:
	CGO_ENABLED=0 $(GO) build -o $(BINARY)-headless ./cmd/configurator

run:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) run ./cmd/configurator

test:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test ./...

clean:
	rm -f $(BINARY) $(BINARY)-headless
