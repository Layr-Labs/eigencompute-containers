.PHONY: build clean test lint help

# Binary output directory and name
BIN_DIR := bin
BINARY_NAME := kms-client

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BIN_DIR)
	@go build -o $(BIN_DIR)/$(BINARY_NAME) ./cmd/kms-client
	@echo "Binary built at $(BIN_DIR)/$(BINARY_NAME)"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BIN_DIR)
	@echo "Clean complete"

# Run tests
test:
	@echo "Running tests..."
	@go test ./...

# Run linter
lint:
	@echo "Running linter..."
	@golangci-lint run

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	@go mod download
	@go mod tidy

# Help
help:
	@echo "Available targets:"
	@echo "  build  - Build the binary to $(BIN_DIR)/$(BINARY_NAME)"
	@echo "  clean  - Remove build artifacts"
	@echo "  test   - Run unit tests"
	@echo "  lint   - Run golangci-lint"
	@echo "  deps   - Download and tidy dependencies"
	@echo "  help   - Show this help message"
