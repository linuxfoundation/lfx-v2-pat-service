# Copyright The Linux Foundation and each contributor to LFX.
# SPDX-License-Identifier: MIT

APP_NAME := lfx-v2-pat-service
VERSION := $(shell git describe --tags --always 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GIT_COMMIT := $(shell git rev-parse HEAD 2>/dev/null || echo "unknown")

# Docker
DOCKER_REGISTRY := ghcr.io/linuxfoundation
DOCKER_IMAGE := $(DOCKER_REGISTRY)/$(APP_NAME)/pat-api
DOCKER_TAG := $(VERSION)

# Helm variables
HELM_CHART_PATH=./charts/lfx-v2-pat-service
HELM_RELEASE_NAME=lfx-v2-pat-service
HELM_NAMESPACE=lfx
HELM_VALUES_FILE=$(HELM_CHART_PATH)/values.local.yaml

# Go
GO_VERSION := 1.24.2
GOOS := linux
GOARCH := amd64
GOA_VERSION := v3.25.3
GO_FILES=$(shell find . -name '*.go' -not -path './gen/*' -not -path './vendor/*')

# Linting
GOLANGCI_LINT_VERSION := v2.13.2
LINT_TIMEOUT := 10m
LINT_TOOL=$(shell go env GOPATH)/bin/golangci-lint

##@ Development

.PHONY: setup-dev
setup-dev: ## Setup development tools
	@echo "Installing development tools..."
	@echo "Installing golangci-lint $(GOLANGCI_LINT_VERSION)..."
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

.PHONY: setup
setup: ## Setup development environment
	@echo "Setting up development environment..."
	go mod download
	go mod tidy

.PHONY: deps
deps: ## Install dependencies
	@echo "Installing dependencies..."
	go install goa.design/goa/v3/cmd/goa@$(GOA_VERSION)

.PHONY: apigen
apigen: deps ## Generate API code using Goa
	goa gen github.com/linuxfoundation/lfx-v2-pat-service/design

.PHONY: fmt
fmt: ## Format Go source (generated code excluded)
	@echo "==> Formatting code..."
	@gofmt -s -w $(GO_FILES)

.PHONY: lint
lint: ## Run golangci-lint (local Go linting)
	@echo "Running golangci-lint..."
	@which golangci-lint >/dev/null 2>&1 || (echo "Installing golangci-lint $(GOLANGCI_LINT_VERSION)..." && go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION))
	@golangci-lint run ./... && echo "==> Lint OK"

.PHONY: test
test: ## Run tests
	@echo "Running tests..."
	go test -v -race -coverprofile=coverage.out ./...

# Local database for running the service with STORE=postgres.
DB_CONTAINER := pat-pg
DB_PORT ?= 5433
DB_URL := postgres://pat:pat@localhost:$(DB_PORT)/pat?sslmode=disable

.PHONY: db-up
db-up: ## Start a disposable Postgres 16 in Docker (DB_PORT overrides the host port; a container on another port is recreated)
	@if [ "$$(docker inspect -f '{{(index (index .HostConfig.PortBindings "5432/tcp") 0).HostPort}}' $(DB_CONTAINER) 2>/dev/null)" = "$(DB_PORT)" ]; then \
		docker start $(DB_CONTAINER) >/dev/null; \
	else \
		docker rm -f $(DB_CONTAINER) >/dev/null 2>&1 || true; \
		docker run -d --name $(DB_CONTAINER) \
			-e POSTGRES_USER=pat -e POSTGRES_PASSWORD=pat -e POSTGRES_DB=pat \
			-p 127.0.0.1:$(DB_PORT):5432 postgres:16 >/dev/null; \
	fi
	@for i in $$(seq 1 30); do docker exec $(DB_CONTAINER) pg_isready -U pat -q 2>/dev/null && break; sleep 1; done
	@docker exec $(DB_CONTAINER) pg_isready -U pat -q || { echo "Postgres did not become ready"; exit 1; }
	@echo "==> Postgres at $(DB_URL)"

.PHONY: db-down
db-down: ## Stop and remove the disposable Postgres
	@docker rm -f $(DB_CONTAINER) >/dev/null 2>&1 || true

.PHONY: build
build: ## Build the application for local OS
	@echo "Building application for local development..."
	go build \
		-ldflags "-X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -X main.gitCommit=$(GIT_COMMIT)" \
		-o bin/$(APP_NAME) ./cmd/pat-api/

.PHONY: run
run: build ## Run the application for local development
	@echo "Running application for local development..."
	./bin/$(APP_NAME)

##@ Docker

.PHONY: docker-build
docker-build: ## Build Docker image
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	docker tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_IMAGE):latest

.PHONY: docker-run
docker-run: ## Run Docker container locally against the db-up database
	@echo "Running Docker container..."
	docker run \
		--name $(APP_NAME) \
		-p 8080:8080 \
		-e PGHOST=host.docker.internal -e PGPORT=$(DB_PORT) -e PGUSER=pat -e PGPASSWORD=pat -e PGDATABASE=pat -e PGSSLMODE=disable -e PG_ALLOW_INSECURE_SSLMODE=true \
		-e JWT_AUTH_DISABLED_MOCK_LOCAL_PRINCIPAL=alice \
		$(DOCKER_IMAGE):$(DOCKER_TAG)

##@ Helm/Kubernetes

.PHONY: helm-lint
helm-lint: ## Lint the chart and render it with the default and the local example values
	helm lint $(HELM_CHART_PATH)
	helm template $(HELM_RELEASE_NAME) $(HELM_CHART_PATH) --namespace $(HELM_NAMESPACE) >/dev/null
	helm template $(HELM_RELEASE_NAME) $(HELM_CHART_PATH) --namespace $(HELM_NAMESPACE) \
		--values $(HELM_CHART_PATH)/values.local.example.yaml >/dev/null
	@echo "==> Helm chart OK"

# Install Helm chart
.PHONY: helm-install
helm-install:
	@echo "==> Installing Helm chart..."
	helm upgrade --install $(HELM_RELEASE_NAME) $(HELM_CHART_PATH) --namespace $(HELM_NAMESPACE) --set image.tag=$(DOCKER_TAG)
	@echo "==> Helm chart installed: $(HELM_RELEASE_NAME)"

.PHONY: helm-install-local
helm-install-local: ## Install Helm chart with local values file
	@echo "==> Installing Helm chart with local values..."
	helm upgrade --force --install $(HELM_RELEASE_NAME) $(HELM_CHART_PATH) \
		--namespace $(HELM_NAMESPACE) --create-namespace \
		--values $(HELM_VALUES_FILE)
	@echo "==> Helm chart installed: $(HELM_RELEASE_NAME)"


# Print templates for Helm chart
.PHONY: helm-templates
helm-templates:
	@echo "==> Printing templates for Helm chart..."
	helm template $(HELM_RELEASE_NAME) $(HELM_CHART_PATH) --namespace $(HELM_NAMESPACE) --set image.tag=$(DOCKER_TAG)
	@echo "==> Templates printed for Helm chart: $(HELM_RELEASE_NAME)"

# Uninstall Helm chart
.PHONY: helm-uninstall
helm-uninstall:
	@echo "==> Uninstalling Helm chart..."
	helm uninstall $(HELM_RELEASE_NAME) --namespace $(HELM_NAMESPACE)
	@echo "==> Helm chart uninstalled: $(HELM_RELEASE_NAME)"
