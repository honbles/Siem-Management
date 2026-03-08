# ── Build stage ──────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /build
COPY go.mod ./
# Download dependencies (regenerates go.sum inside container)
RUN go mod download 2>/dev/null || true

COPY . .
RUN go mod tidy && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o management-server ./cmd/server

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata wget

WORKDIR /app
COPY --from=builder /build/management-server .
COPY configs/server.yaml .

RUN mkdir -p certs

EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --retries=3 \
  CMD wget -qO- http://localhost:8080/health || exit 1

ENTRYPOINT ["./management-server", "-config", "server.yaml"]
