# Stage 1: Build
FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /gosqlx-mcp ./cmd/gosqlx-mcp

# Stage 2: Runtime
FROM gcr.io/distroless/static:nonroot
COPY --from=builder /gosqlx-mcp /gosqlx-mcp
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/gosqlx-mcp"]
