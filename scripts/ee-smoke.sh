#!/usr/bin/env bash
# EE garble smoke — the local gate that stands in for the CI the mxid-ee repo
# does not have. It compiles the reflection-sensitive code paths UNDER GARBLE
# (the same obfuscator the EE image ships) and asserts they still return real
# values. This catches the class of bug where an untagged GORM/JSON scan struct
# reads EMPTY only in the garbled binary — invisible to `go build`, `go test`,
# and dev, but live in prod (the access-policy "(未知)" incident).
#
# Runs `garble test -tags eesmoke ./app/...` inside a golang:1.26 container
# (garble requires go >= 1.26; the host toolchain may lag), pointed at a
# Postgres that already has the schema. By default it reuses the dev database
# on the host (host-mapped :5432, password from .env).
#
# Usage:
#   make ee-smoke                     # reuse dev DB
#   MXID_REPRO_DSN='host=... ' scripts/ee-smoke.sh   # explicit DSN
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

GO_IMAGE="${MXID_EE_SMOKE_IMAGE:-golang:1.26-alpine}"
GARBLE_VER="${MXID_GARBLE_VERSION:-v0.16.0}"

# Build the DSN the test uses. From inside the container the host DB is reached
# via host.docker.internal. Password comes from .env (same source as dev).
if [[ -z "${MXID_REPRO_DSN:-}" ]]; then
  PW="$(grep -E '^POSTGRES_PASSWORD=' .env 2>/dev/null | cut -d= -f2- || true)"
  DB="${POSTGRES_DB:-mxid}"
  [[ -n "$PW" ]] || { echo "✗ POSTGRES_PASSWORD not found in .env; set MXID_REPRO_DSN"; exit 1; }
  DSN="host=host.docker.internal port=5432 user=postgres password=${PW} dbname=${DB} sslmode=disable"
else
  DSN="$MXID_REPRO_DSN"
fi

echo "==> ee-smoke: garble test -tags eesmoke ./app/... (image: $GO_IMAGE)"
docker run --rm \
  -v "$ROOT":/src -w /src \
  -e MXID_REPRO_DSN="$DSN" \
  -e GOFLAGS=-mod=mod \
  -e HOME=/tmp -e GOCACHE=/tmp/gocache -e GOPATH=/tmp/gopath -e GARBLE_CACHE=/tmp/garble \
  "$GO_IMAGE" sh -euc '
    apk add --no-cache git >/dev/null 2>&1
    go install mvdan.cc/garble@'"$GARBLE_VER"' >/dev/null 2>&1
    export PATH=$PATH:$(go env GOPATH)/bin
    CGO_ENABLED=0 garble -tiny test -tags eesmoke -count=1 -run TestEESmoke -v ./app/...
  '
echo "✓ ee-smoke OK (garble build maps GORM columns correctly)"
