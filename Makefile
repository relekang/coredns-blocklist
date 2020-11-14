GO_FILES=$(shell find . -name '*.go')

default: coredns

install: go.sum go.mod
	go get

test: $(GO_FILES)
	go test -test.v

coredns: $(GO_FILES)
	go build -o coredns ./example/main.go

run: coredns
	cd example && ../coredns -conf ./Corefile

clean:
	rm -rf coredns
