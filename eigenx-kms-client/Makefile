.PHONY: build clean test lint help

# Binary output directory and name
BIN_DIR := bin
BINARY_NAME := eigenx-kms-client

GO_FLAGS_STATIC=-ldflags="-s -w -extldflags '-static'"

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BIN_DIR)
	@go build -o $(BIN_DIR)/$(BINARY_NAME) ./cmd/kms-client
	@echo "Binary built at $(BIN_DIR)/$(BINARY_NAME)"

.PHONY: build/static
build/static:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
		$(GO_FLAGS_STATIC) \
		-trimpath -buildvcs=false \
		-o $(BIN_DIR)/$(BINARY_NAME) ./cmd/kms-client

build/amd64:
	GOARCH=amd64 GOOS=linux go build $(GO_FLAGS_STATIC) -o $(BIN_DIR)/eigenx-kms-client-linux-amd64 ./cmd/kms-client

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
