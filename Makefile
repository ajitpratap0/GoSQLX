.PHONY: build test clean lint fmt vet coverage help

# Default target
all: build

# Build the application
build:
	@echo "Building..."
	@go build -v ./...

# Run all tests
test:
	@echo "Running tests..."
	@go test -v ./...

# Run tests with coverage
coverage:
	@echo "Running tests with coverage..."
	@go test -cover -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated at coverage.html"

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -f coverage.out coverage.html
	@go clean

# Run go fmt
fmt:
	@echo "Formatting code..."
	@go fmt ./...

# Run go vet
vet:
	@echo "Vetting code..."
	@go vet ./...

# Run golint if installed
lint:
	@echo "Linting code..."
	@if command -v golint > /dev/null; then \
		golint ./...; \
	else \
		echo "golint not installed. Run: go install golang.org/x/lint/golint@latest"; \
	fi

# Run all quality checks
quality: fmt vet lint

# Show help
help:
	@echo "Available targets:"
	@echo "  all       - Build the application (default)"
	@echo "  build     - Build the application"
	@echo "  test      - Run tests"
	@echo "  coverage  - Run tests with coverage report"
	@echo "  clean     - Clean build artifacts"
	@echo "  fmt       - Run go fmt"
	@echo "  vet       - Run go vet"
	@echo "  lint      - Run golint (if installed)"
	@echo "  quality   - Run all quality checks (fmt, vet, lint)"
	@echo "  help      - Show this help message"
