VER ?= dev
LDFLAGS := -s -w -X main.version=$(VER)

.PHONY: build test test-race lint vet tidy clean release xbuild

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/veil ./cmd/veil

test:
	CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test -tags testkeystore ./... -timeout 120s

test-race:
	CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test -tags testkeystore ./... -race -timeout 180s

lint:
	golangci-lint run

vet:
	CGO_ENABLED=0 go vet ./...

tidy:
	go mod tidy

clean:
	rm -rf bin dist

xbuild:
	CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/veil-darwin-amd64  ./cmd/veil
	CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/veil-darwin-arm64  ./cmd/veil
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/veil-linux-amd64   ./cmd/veil
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/veil-linux-arm64   ./cmd/veil

release:
	CGO_ENABLED=0 goreleaser release --clean
