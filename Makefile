.PHONY: all build test lint

gopath=$(shell go env GOPATH)

all: build test lint

build:
	go build ./...

test:
	go test -v ./...

lint: $(gopath)/bin/gobin
	$(gopath)/bin/gobin -m -run github.com/golangci/golangci-lint/cmd/golangci-lint run ./...

$(gopath)/bin/gobin:
	(cd /tmp && GO111MODULE=on go get -u github.com/myitcv/gobin@latest)
