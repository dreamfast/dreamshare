# One target, make ci, is the whole local gate. the ci-checks subset is
# what the remote workflow runs: same linters and tests, no e2e, because
# the runner has no browser binaries and the browser install is not
# worth the minutes on every push.

GO ?= go
BIN := $(shell $(GO) env GOBIN 2>/dev/null)
ifeq ($(BIN),)
BIN := $(shell $(GO) env GOPATH)/bin
endif

# pinned so three machines never disagree via three lint opinions
GOFUMPT_VERSION     := v0.12.0
STATICCHECK_VERSION := v0.8.2
GOVULNCHECK_VERSION := v1.9.0
GOLANGCI_VERSION    := v2.15.0
GOSEC_VERSION       := v2.30.0
GOIMPORTS_VERSION   := v0.49.0

.PHONY: tools ci ci-checks fmt-check vet staticcheck golangci gosec vuln test tidy-diff build web-build web-test web-e2e run

tools:
	GOBIN=$(BIN) $(GO) install mvdan.cc/gofumpt@$(GOFUMPT_VERSION)
	GOBIN=$(BIN) $(GO) install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION)
	GOBIN=$(BIN) $(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	GOBIN=$(BIN) $(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)
	GOBIN=$(BIN) $(GO) install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)
	GOBIN=$(BIN) $(GO) install golang.org/x/tools/cmd/goimports@$(GOIMPORTS_VERSION)

ci: ci-checks web-e2e

ci-checks: fmt-check vet staticcheck golangci gosec test tidy-diff vuln web-build build

fmt-check:
	@out="$$($(BIN)/gofumpt -l .)"; if [ -n "$$out" ]; then \
		echo "gofumpt would reformat:"; echo "$$out"; exit 1; fi
	@out="$$($(BIN)/goimports -l .)"; if [ -n "$$out" ]; then \
		echo "goimports would reformat:"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet ./cmd/... ./internal/... ./scripts/...

staticcheck:
	$(BIN)/staticcheck -checks=all ./cmd/... ./internal/... ./scripts/...

golangci:
	$(BIN)/golangci-lint run ./cmd/... ./internal/... ./scripts/...

gosec:
	$(BIN)/gosec -quiet ./cmd/... ./internal/... ./scripts/...

vuln:
	$(BIN)/govulncheck ./...

test:
	$(GO) test -race -shuffle=on -count=1 ./cmd/... ./internal/... ./scripts/...

tidy-diff:
	$(GO) mod tidy -diff

build:
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/dreamshare ./cmd/dreamshare

web-build:
	cd web && npm ci --no-audit --no-fund >/dev/null
	cd web && npx vue-tsc --noEmit
	cd web && npx eslint .
	cd web && npx prettier --check .
	cd web && npx vitest run
	cd web && npm run build >/dev/null
	cd web && npx size-limit
	rm -rf internal/webdist/dist && cp -r web/dist internal/webdist/dist

web-e2e:
	rm -f /tmp/dreamshare-e2e.db
	cd web && npx playwright test
	rm -f /tmp/dreamshare-e2e-turnstile.db
	cd web && npx playwright test --config playwright.turnstile.config.ts

run: build
	./bin/dreamshare
