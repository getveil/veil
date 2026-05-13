VER ?= dev
LDFLAGS := -s -w -X main.version=$(VER)

.PHONY: build test test-race test-integration lint vet tidy clean release release-snapshot xbuild

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/veil ./cmd/veil

test:
	CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test -tags testkeystore ./... -timeout 120s

test-race:
	CGO_ENABLED=1 VEIL_TEST_KEYSTORE=mem go test -tags testkeystore ./... -race -timeout 180s

# test-integration exercises the production AutoKeystore path against a real
# OS keystore: macOS Keychain on darwin, gnome-keyring (Secret Service) on
# linux, with the age-encrypted file keystore as a documented fallback.
# Requires a real keystore to be present and unlocked on the host. Does NOT
# set VEIL_TEST_KEYSTORE=mem and does NOT pass -tags testkeystore, so the
# production code path is selected.
#
# Scope: only ./internal/vault/... — that package owns the realkeystore-
# tagged tests in keystore_integration_test.go. The rest of the codebase's
# tests assume the mem keystore (they t.Setenv VEIL_TEST_KEYSTORE=mem in
# their helpers) and would hammer the real keyring with redundant probes if
# run here, which has wedged dbus on hosted Linux CI runners. Their
# production-keystore behavior is already covered by `make test` (no keyring
# present → file-fallback path) plus this target's vault round-trip.
test-integration:
	@echo "test-integration: requires a real keystore (Keychain on darwin, gnome-keyring on linux)."
	CGO_ENABLED=1 go test -tags realkeystore ./internal/vault/... -timeout 60s

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

release-snapshot:
	CGO_ENABLED=0 goreleaser release --snapshot --clean --skip=publish,sign
