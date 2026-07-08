.PHONY: dev dev-console dev-portal dev-web dev-docker-up dev-docker-up-d dev-docker-down dev-docker-logs dev-docker-ps dev-docker-restart dev-docker-reload dev-docker-watch dev-docker-clean \
       build run test lint migrate-up migrate-down migrate-create clean deps \
       verify verify-mod verify-vet verify-build verify-lint verify-web verify-exports smoke install-hooks \
       docker-build prod-up prod-down prod-logs standalone-up standalone-down standalone-logs

# Variables
APP_NAME := mxid
MAIN_PATH := cmd/server/main.go
BUILD_DIR := bin
CONFIG_PATH := configs
MIGRATE_DIR := migrations
DB_DSN ?= "postgres://postgres:12345@host.docker.internal:5432/mxid?sslmode=disable"

# Build identity (stamped into the binary / image). VERSION falls back to the
# git tag (v1.2.3) or short sha; CI passes an explicit tag.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
IMAGE := ghcr.io/imkerbos/$(APP_NAME)

# Development — Go backend (air hot reload)
dev:
	air -c .air.toml

# Development — Frontend
dev-console:
	cd web && pnpm dev:console

dev-portal:
	cd web && pnpm dev:portal

dev-web:
	cd web && pnpm dev

# Development — Docker (air hot reload + external pg/redis)
DEV_COMPOSE := docker compose --env-file .env -f deploy/compose/docker-compose.dev.yml

# Dev-EE: same stack, but the backend is built from the Enterprise entrypoint
# (mxid-ee/cmd/server → external-IdP / Lark, SCIM, …). Requires the private
# mxid-ee repo checked out as ../mxid-ee. See docker-compose.dev-ee.yml.
DEV_COMPOSE_EE := $(DEV_COMPOSE) -f deploy/compose/docker-compose.dev-ee.yml

dev-docker-up:
	$(DEV_COMPOSE) up

dev-docker-up-d:
	$(DEV_COMPOSE) up -d

dev-docker-up-ee:
	$(DEV_COMPOSE_EE) up

dev-docker-up-ee-d:
	$(DEV_COMPOSE_EE) up -d

dev-docker-down-ee:
	$(DEV_COMPOSE_EE) down

dev-docker-logs-ee:
	$(DEV_COMPOSE_EE) logs -f mxid

dev-docker-down:
	$(DEV_COMPOSE) down

dev-docker-logs:
	$(DEV_COMPOSE) logs -f

dev-docker-ps:
	$(DEV_COMPOSE) ps

dev-docker-restart:
	$(DEV_COMPOSE) restart

dev-docker-reload:
	$(DEV_COMPOSE) down && $(DEV_COMPOSE) up -d

dev-docker-watch:
	./scripts/dev-watch.sh

dev-docker-clean:
	$(DEV_COMPOSE) down -v

# Build
build: build-backend

build-backend:
	CGO_ENABLED=0 go build -o $(BUILD_DIR)/$(APP_NAME) ./cmd/server

build-frontend:
	cd web && pnpm install && pnpm build

build-all: build-frontend build-backend

# Run
run:
	go run $(MAIN_PATH) -config $(CONFIG_PATH)

# Test
test:
	go test ./... -v -count=1

test-cover:
	go test ./... -v -count=1 -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html

# Lint
lint:
	golangci-lint run ./...

lint-fix:
	golangci-lint run --fix ./...

# Dependencies
deps:
	go mod tidy
	go mod verify

# Database migrations
migrate-up:
	migrate -path $(MIGRATE_DIR) -database $(DB_DSN) up

migrate-down:
	migrate -path $(MIGRATE_DIR) -database $(DB_DSN) down 1

migrate-create:
	@read -p "Enter migration name: " name; \
	migrate create -ext sql -dir $(MIGRATE_DIR) -seq $$name

migrate-force:
	@read -p "Enter version: " version; \
	migrate -path $(MIGRATE_DIR) -database $(DB_DSN) force $$version

migrate-version:
	migrate -path $(MIGRATE_DIR) -database $(DB_DSN) version

# Docker — Production build (version stamped via build args). Builds BOTH the
# backend and the web (nginx + baked SPAs) images, mirroring CI. No `latest`
# tag — CI doesn't publish one, so neither do local builds.
docker-build:
	docker build -f deploy/dockerfile/Dockerfile \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		-t $(IMAGE):$(VERSION) .
	docker build -f deploy/dockerfile/Dockerfile.web \
		-t $(IMAGE)-web:$(VERSION) .

# Prod stack — external DB (host.docker.internal). MXID_TAG defaults to the
# local VERSION so `make prod-up` builds + runs without a separate .env tag.
prod-up:
	MXID_TAG=$(VERSION) docker compose -f deploy/compose/docker-compose.yml up -d --build
prod-down:
	docker compose -f deploy/compose/docker-compose.yml down
prod-logs:
	docker compose -f deploy/compose/docker-compose.yml logs -f

# Prod stack — self-contained (containerized Postgres + Redis + volumes).
standalone-up:
	MXID_TAG=$(VERSION) docker compose -f deploy/compose/docker-compose.yml -f deploy/compose/docker-compose.standalone.yml up -d --build
standalone-down:
	docker compose -f deploy/compose/docker-compose.yml -f deploy/compose/docker-compose.standalone.yml down
standalone-logs:
	docker compose -f deploy/compose/docker-compose.yml -f deploy/compose/docker-compose.standalone.yml logs -f

# Prod via docker compose — single entrypoint; everything comes from
# deploy/compose/.env.prod: COMPOSE_FILE picks the mode (external DB vs bundled
# standalone PG/Redis), MXID_TAG pins the released image, plus secrets / origins
# / cert filenames. Copy deploy/compose/.env.prod.example -> .env.prod first.
prod-docker-up:
	docker compose --env-file deploy/compose/.env.prod up -d
prod-docker-down:
	docker compose --env-file deploy/compose/.env.prod down
prod-docker-logs:
	docker compose --env-file deploy/compose/.env.prod logs -f

# Clean
clean:
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

# Verify — invariant gates. Run before commit / in CI.
# Each sub-target is independently runnable to localize failures.
verify: verify-mod verify-vet verify-build verify-lint verify-exports verify-web
	@echo "✓ verify OK"

# go.mod / go.sum must match the import graph. Catches indirect-vs-direct drift.
verify-mod:
	@echo "==> verify-mod (go mod tidy diff)"
	@cp go.mod go.mod.bak && cp go.sum go.sum.bak
	@go mod tidy
	@if ! diff -q go.mod go.mod.bak >/dev/null || ! diff -q go.sum go.sum.bak >/dev/null; then \
		mv go.mod.bak go.mod; mv go.sum.bak go.sum; \
		echo "✗ go.mod / go.sum out of sync — run 'go mod tidy' and commit"; exit 1; \
	fi
	@rm -f go.mod.bak go.sum.bak

# Catches nil-pointer flow + unreachable code via standard analyzers.
verify-vet:
	@echo "==> verify-vet"
	go vet ./...

# Builds every Go package, not just main.go. Catches single-file build skew.
verify-build:
	@echo "==> verify-build (./...)"
	go build ./...

# golangci-lint — exhaustruct on cmd/server/adapters_*, nilness, errcheck, staticcheck.
verify-lint:
	@echo "==> verify-lint"
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not installed: https://golangci-lint.run/welcome/install/"; exit 1; }
	golangci-lint run ./...

# package.json `exports` map paths must exist on disk.
verify-exports:
	@echo "==> verify-exports"
	node scripts/verify-exports.mjs

# Frontend production build — strict mode catches what vite dev permits.
verify-web:
	@echo "==> verify-web (pnpm -r build)"
	cd web && pnpm install --prefer-offline --frozen-lockfile && pnpm -r build

# Boot compose + curl every console module endpoint as admin.
smoke:
	@echo "==> smoke"
	./scripts/smoke-test.sh

# Idempotent: link .git/hooks/pre-commit -> scripts/pre-commit.sh
install-hooks:
	@echo "==> install-hooks"
	./scripts/install-hooks.sh
