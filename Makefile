goimports := golang.org/x/tools/cmd/goimports@v0.1.5
golangci_lint := github.com/golangci/golangci-lint/cmd/golangci-lint@v1.42.0

.PHONY: test
test:
	@go test ./...

.PHONY: build
build:
	@mkdir -p out/
	@go build -o out/scanner ./cmd/main.go

.PHONY: clean
clean:
	rm -rf out/


golangci_lint_path := $(shell go env GOPATH)/bin/golangci-lint

$(golangci_lint_path):
	@go install $(golangci_lint)

golangci_lint_goarch ?= $(shell go env GOARCH)


.PHONY: lint
lint:
	@GOARCH=$(golangci_lint_goarch) $(golangci_lint_path) run --timeout 5m


.PHONY: format
format:
	@go run $(goimports) -w -local github.com/incfly/gotmpl `find . -name '*.go'`


.PHONY: check
check:
	@echo "TODO: make check."
