.PHONY: all build run test clean

BINARY ?= viking-bio-configurator
GO = go

all: build

build:
	$(GO) build -o $(BINARY) ./cmd/configurator

run:
	$(GO) run ./cmd/configurator

test:
	$(GO) test ./...

clean:
	rm -f $(BINARY)
