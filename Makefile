# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOMODTIDY=$(GOCMD) mod tidy
GORUN=$(GOCMD) run

# Binary name
BINARY_NAME=ssflow
BINARY_UNIX=$(BINARY_NAME)
BINARY_WINDOWS=$(BINARY_NAME).exe

# Default target
all: build

# Build the binary for the current OS
build:
	@echo "Building for $(GOOS)/$(GOARCH)..."
	$(GOBUILD) -o $(BINARY_UNIX) .

# Run the application
run:
	$(GORUN) .

# Run tests
test:
	$(GOTEST) -v ./...

# Clean build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -f $(BINARY_UNIX)
	rm -f $(BINARY_WINDOWS)

# Tidy dependencies
tidy:
	@echo "Tidying dependencies..."
	$(GOMODTIDY)

# Cross-compile for Windows
build-windows:
	@echo "Building for Windows (amd64)..."
	GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(BINARY_WINDOWS) -v .

# Build without CGO (will fail for this project)
build-nocgo:
	@echo "Attempting to build without CGO..."
	CGO_ENABLED=0 $(GOBUILD) -o $(BINARY_UNIX)-nocgo -v .

.PHONY: all build run test clean tidy build-windows build-nocgo
