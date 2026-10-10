# Base images are pinned to multi-arch index digests (tag kept for readability).
# To update, resolve the new index digest (e.g. `docker buildx imagetools inspect <image:tag>`).

# Stage 1: Build
FROM golang:1.26-alpine@sha256:3082400e369fa24d5fc60bca20edab3f6d604e0c5a690ec66b295eff4dd87ade AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /gosqlx-mcp ./cmd/gosqlx-mcp

# Stage 2: Runtime
FROM gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=builder /gosqlx-mcp /gosqlx-mcp
USER nonroot:nonroot
EXPOSE 8080
# The distroless runtime has no shell, curl, or wget, and the gosqlx-mcp binary
# has no self-probe flag, so an in-image exec-form HEALTHCHECK is not possible.
# Liveness is checked by the orchestrator (e.g. Kubernetes/Render/Fly HTTP probe)
# against GET /health on port 8080 instead.
HEALTHCHECK NONE
ENTRYPOINT ["/gosqlx-mcp"]
