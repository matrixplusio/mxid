# Build stage — pin the patch version to satisfy go.mod's `go 1.25.11` directive
# (the floating 1.25-alpine tag can lag behind by a patch release).
FROM golang:1.25.11-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build identity stamped into the binary via -ldflags. Passed by CI (release.yml)
# from the git tag / sha / build timestamp; defaults keep local builds at "dev".
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_TIME=unknown

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w \
      -X github.com/imkerbos/mxid/pkg/version.Version=${VERSION} \
      -X github.com/imkerbos/mxid/pkg/version.Commit=${COMMIT} \
      -X github.com/imkerbos/mxid/pkg/version.BuildTime=${BUILD_TIME}" \
    -o /app/bin/mxid ./cmd/server

# Runtime stage
FROM alpine:3.22

# apk upgrade first pulls the latest patched packages (closes any base-image lag
# CVEs), then install the runtime deps.
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates tzdata wget

WORKDIR /app

COPY --from=builder /app/bin/mxid .
# configs baked in as a fallback. Prod mounts configs/ read-only over this so
# config changes don't require an image rebuild (see deploy/compose/*.yml).
COPY --from=builder /app/configs ./configs
COPY --from=builder /app/migrations ./migrations

EXPOSE 8080

ENTRYPOINT ["./mxid"]
CMD ["-config", "configs"]
