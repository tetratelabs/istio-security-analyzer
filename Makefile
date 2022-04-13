# Copyright 2022 Tetrate
# Licensed under the Apache License, Version 2.0 (the "License")

include Tools.mk

name := scanner

# VERSION is used in release artifacts names. This should be in <major>.<minor>.<patch> (without v
# prefix). When generating actual release assets this can be resolved using "git describe --tags --long".
VERSION ?= dev

# Root dir returns absolute path of current directory. It has a trailing "/".
root_dir := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Currently we resolve it using which. But more sophisticated approach is to use infer GOROOT.
go     := $(shell which go)
goarch := $(shell $(go) env GOARCH)
goexe  := $(shell $(go) env GOEXE)
goos   := $(shell $(go) env GOOS)

# Local cache directory.
CACHE_DIR ?= $(root_dir).cache

all_go_sources  := $(wildcard cmd/*.go pkg/*/*.go)
main_go_sources := $(wildcard $(filter-out %_test.go,$(all_go_sources)))

# Go tools directory holds the binaries of Go-based tools.
go_tools_dir := $(CACHE_DIR)/tools/go

export PATH := $(go_tools_dir):$(PATH)

current_binary_path := build/$(name)_$(goos)_$(goarch)
current_binary      := $(current_binary_path)/$(name)$(goexe)

# Go-based tools.
addlicense    := $(go_tools_dir)/addlicense
goimports     := $(go_tools_dir)/goimports
golangci-lint := $(go_tools_dir)/golangci-lint

# This is adopted from https://github.com/tetratelabs/func-e/blob/3df66c9593e827d67b330b7355d577f91cdcb722/Makefile#L60-L76.
# ANSI escape codes. f_ means foreground, b_ background.
# See https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_(Select_Graphic_Rendition)_parameters.
f_black            := $(shell printf "\33[30m")
b_black            := $(shell printf "\33[40m")
f_white            := $(shell printf "\33[97m")
f_gray             := $(shell printf "\33[37m")
f_dark_gray        := $(shell printf "\33[90m")
f_bright_cyan      := $(shell printf "\33[96m")
b_bright_cyan      := $(shell printf "\33[106m")
ansi_reset         := $(shell printf "\33[0m")
ansi_$(name)       := $(b_black)$(f_black)$(b_bright_cyan)$(name)$(ansi_reset)
ansi_format_dark   := $(f_gray)$(f_bright_cyan)%-10s$(ansi_reset) $(f_dark_gray)%s$(ansi_reset)\n
ansi_format_bright := $(f_white)$(f_bright_cyan)%-10s$(ansi_reset) $(f_black)$(b_bright_cyan)%s$(ansi_reset)\n

# This formats help statements in ANSI colors. To hide a target from help, don't comment it with a trailing '##'.
help: ## Describe how to use each target
	@printf "$(ansi_$(name))$(f_white)\n"
	@awk 'BEGIN {FS = ":.*?## "} /^[0-9a-zA-Z_-]+:.*?## / {sub("\\\\n",sprintf("\n%22c"," "), $$2);printf "$(ansi_format_dark)", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: test
test: ## Run all unit tests
	@go test ./...

.PHONY: build
build: $(current_binary) $(current_server_binary) ## Build the binary

license_files := cmd pkg
license: $(addlicense) ## Add license to files
	@$(addlicense) -c "Tetrate" $(license_files) 1>/dev/null 2>&1

clean: ## Ensure a clean build
	@printf "$(ansi_format_dark)" $@ "deleting temporary files"
	@rm -rf coverage.txt
	@rm -rf build
	@rm -rf dist
	@$(go) clean -testcache
	@printf "$(ansi_format_bright)" $@ "ok"

build/$(name)_%/$(name): $(main_go_sources)
	$(call go-build,$@,$<)

build/$(name)_%/$(name).exe: $(main_go_sources)
	$(call go-build,$@,$<)

# Override lint cache directory so we can cache it on CI. Reference: https://golangci-lint.run/usage/configuration/#cache.
# TODO(dio): we need to have .golangci.yml so we can control how linter lints our code.
export GOLANGCI_LINT_CACHE=$(CACHE_DIR)/golangci-lint
lint: $(all_go_sources) $(golangci-lint) ## Lint all Go sources
	@printf "$(ansi_format_dark)" $@ "linting files"
	@$(golangci-lint) run --timeout 5m
	@printf "$(ansi_format_bright)" $@ "ok"

format: go.mod $(all_go_sources) $(goimports) ## Format all Go sources
	@printf "$(ansi_format_dark)" $@ "formatting files"
	@$(go) mod tidy
	@$(go)fmt -s -w $(all_go_sources)
# Workaround inconsistent goimports grouping with awk until golang/go#20818 or incu6us/goimports-reviser#50
	@for f in $(all_go_sources); do \
			awk '/^import \($$/,/^\)$$/{if($$0=="")next}{print}' $$f > /tmp/fmt; \
	    mv /tmp/fmt $$f; \
	done
	@$(goimports) -local $$(sed -ne 's/^module //gp' go.mod) -w $(all_go_sources)
	@printf "$(ansi_format_bright)" $@ "ok"

check: ## Verify contents of last commit
	$(MAKE) format
	$(MAKE) lint
	@if [ ! -z "`git status -s`" ]; then \
		echo "The following differences will fail CI until committed:"; \
		git diff --exit-code; \
	fi

go_link := -X main.version=$(VERSION) -X main.commit=$(shell git rev-parse --short HEAD) -X main.date=$(shell date '+%Y-%m-%d')
go-arch  = $(if $(findstring amd64,$1),amd64,arm64)
go-os    = $(if $(findstring .exe,$1),windows,$(if $(findstring linux,$1),linux,darwin))
define go-build
	@printf "$(ansi_format_dark)" build "building $1"
	@CGO_ENABLED=0 GOOS=$(call go-os,$1) GOARCH=$(call go-arch,$1) $(go) build \
		-ldflags "-s -w $(go_link)" \
		-o $1 $2
	@printf "$(ansi_format_bright)" build "ok"
endef

# Catch all rules for Go-based tools.
$(go_tools_dir)/%:
	@printf "$(ansi_format_dark)" tools "installing $($(notdir $@)@v)..."
	@GOBIN=$(go_tools_dir) go install $($(notdir $@)@v)
	@printf "$(ansi_format_bright)" tools "ok"
