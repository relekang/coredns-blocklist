GO_FILES=$(shell find . -name '*.go')

default: coredns

install: go.sum go.mod
	go get

test: $(GO_FILES)
	go test -test.v

linux/arm: $(GO_FILES)
	mkdir -p linux/arm
	GOOS=linux GOARCH=arm go build -o linux/arm/coredns ./example/main.go

linux/arm64: $(GO_FILES)
	mkdir -p linux/arm64
	GOOS=linux GOARCH=arm64 go build -o linux/arm64/coredns ./example/main.go

linux/amd64: $(GO_FILES)
	mkdir -p linux/amd64
	GOOS=linux GOARCH=amd64 go build -o linux/amd64/coredns ./example/main.go

linux/386: $(GO_FILES)
	mkdir -p linux/386
	GOOS=linux GOARCH=386 go build -o linux/386/coredns ./example/main.go

coredns: $(GO_FILES)
	go build -o coredns ./example/main.go

run: coredns
	cd example && ../coredns -conf ./Corefile

clean:
	rm -rf coredns linux

dist: linux/arm linux/arm64 linux/amd64 linux/386

.PHONY: dist clean
