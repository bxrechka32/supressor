.PHONY: all build clean test install uninstall docker release

BINARY_NAME=supressor
VERSION=1.0.0
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags="-X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -w -s"

all: build

build:
	@echo "🚀 Building ${BINARY_NAME} v${VERSION}..."
	@CGO_ENABLED=1 go build ${LDFLAGS} -o bin/${BINARY_NAME} ./cmd/supressor
	@CGO_ENABLED=1 go build ${LDFLAGS} -o bin/${BINARY_NAME}-cli ./cmd/supressor-cli
	@chmod +x bin/*
	@echo "✅ Build complete!"

build-release:
	@echo "📦 Building release binaries..."
	@mkdir -p dist/{linux/amd64,linux/arm64,darwin/amd64,darwin/arm64,windows/amd64}
	
	# Linux
	@GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build ${LDFLAGS} -o dist/linux/amd64/${BINARY_NAME} ./cmd/supressor
	@GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build ${LDFLAGS} -o dist/linux/amd64/${BINARY_NAME}-cli ./cmd/supressor-cli
	@GOOS=linux GOARCH=arm64 CGO_ENABLED=1 go build ${LDFLAGS} -o dist/linux/arm64/${BINARY_NAME} ./cmd/supressor
	@GOOS=linux GOARCH=arm64 CGO_ENABLED=1 go build ${LDFLAGS} -o dist/linux/arm64/${BINARY_NAME}-cli ./cmd/supressor-cli
	
	# macOS
	@GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 go build ${LDFLAGS} -o dist/darwin/amd64/${BINARY_NAME} ./cmd/supressor
	@GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 go build ${LDFLAGS} -o dist/darwin/amd64/${BINARY_NAME}-cli ./cmd/supressor-cli
	@GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 go build ${LDFLAGS} -o dist/darwin/arm64/${BINARY_NAME} ./cmd/supressor
	@GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 go build ${LDFLAGS} -o dist/darwin/arm64/${BINARY_NAME}-cli ./cmd/supressor-cli
	
	# Windows
	@GOOS=windows GOARCH=amd64 CGO_ENABLED=1 go build ${LDFLAGS} -o dist/windows/amd64/${BINARY_NAME}.exe ./cmd/supressor
	@GOOS=windows GOARCH=amd64 CGO_ENABLED=1 go build ${LDFLAGS} -o dist/windows/amd64/${BINARY_NAME}-cli.exe ./cmd/supressor-cli
	
	@echo "✅ Release binaries built!"

install:
	@echo "📥 Installing ${BINARY_NAME}..."
	@sudo cp bin/${BINARY_NAME} /usr/local/bin/
	@sudo cp bin/${BINARY_NAME}-cli /usr/local/bin/
	@sudo mkdir -p /etc/supressor /var/lib/supressor /var/log/supressor
	@sudo cp configs/default.toml /etc/supressor/config.toml 2>/dev/null || true
	@sudo chmod 755 /usr/local/bin/${BINARY_NAME} /usr/local/bin/${BINARY_NAME}-cli
	@sudo chown -R root:root /etc/supressor /var/lib/supressor /var/log/supressor
	@echo "✅ Installation complete!"

uninstall:
	@echo "🗑️ Uninstalling ${BINARY_NAME}..."
	@sudo rm -f /usr/local/bin/${BINARY_NAME}
	@sudo rm -f /usr/local/bin/${BINARY_NAME}-cli
	@sudo rm -rf /etc/supressor
	@echo "✅ Uninstallation complete!"

clean:
	@echo "🧹 Cleaning..."
	@rm -rf bin/ dist/ coverage.out
	@go clean
	@echo "✅ Clean complete!"

test:
	@echo "🧪 Running tests..."
	@go test ./... -v -coverprofile=coverage.out
	@go tool cover -func=coverage.out

test-race:
	@echo "🏎️ Running race detector tests..."
	@go test ./... -race

docker:
	@echo "🐳 Building Docker image..."
	@docker build -t supressor:${VERSION} .
	@docker tag supressor:${VERSION} supressor:latest
	@echo "✅ Docker image built!"

docker-run:
	@echo "🏃 Running in Docker..."
	@docker run --rm -it \
		--cap-add=NET_ADMIN \
		--device=/dev/net/tun \
		-v $(PWD)/data:/etc/supressor \
		-p 51820:51820/udp \
		supressor:latest

compose-up:
	@echo "🚀 Starting Supressor cluster..."
	@docker-compose up -d

compose-down:
	@echo "🛑 Stopping Supressor cluster..."
	@docker-compose down

lint:
	@echo "🔍 Running linters..."
	@golangci-lint run

security-check:
	@echo "🔒 Running security checks..."
	@which gosec >/dev/null 2>&1 || go install github.com/securego/gosec/v2/cmd/gosec@latest
	@which trivy >/dev/null 2>&1 || echo "Install trivy: https://aquasecurity.github.io/trivy"
	@gosec ./... 2>/dev/null || echo "Gosec not installed, skipping..."
	@trivy config . 2>/dev/null || echo "Trivy not installed, skipping..."

generate:
	@echo "⚙️ Generating code..."
	@go generate ./...

update-deps:
	@echo "📦 Updating dependencies..."
	@go get -u ./...
	@go mod tidy

release: clean test build-release
	@echo "🎉 Creating release v${VERSION}..."
	@cd dist/linux/amd64 && tar -czf ../../supressor-${VERSION}-linux-amd64.tar.gz *
	@cd dist/linux/arm64 && tar -czf ../../supressor-${VERSION}-linux-arm64.tar.gz *
	@cd dist/darwin/amd64 && tar -czf ../../supressor-${VERSION}-darwin-amd64.tar.gz *
	@cd dist/darwin/arm64 && tar -czf ../../supressor-${VERSION}-darwin-arm64.tar.gz *
	@cd dist/windows/amd64 && zip -9 ../../supressor-${VERSION}-windows-amd64.zip *.exe
	@echo "✅ Release packages created in dist/"

dev:
	@echo "👨‍💻 Starting development mode..."
	@go run ./cmd/supressor

help:
	@echo "📖 Available targets:"
	@echo "  build          - Build binaries"
	@echo "  build-release  - Build release binaries for all platforms"
	@echo "  install        - Install system-wide"
	@echo "  uninstall      - Uninstall"
	@echo "  test           - Run tests"
	@echo "  docker         - Build Docker image"
	@echo "  compose-up     - Start Docker Compose cluster"
	@echo "  release        - Create release packages"
	@echo "  clean          - Clean build artifacts"
	@echo "  lint           - Run linters"
	@echo "  security-check - Run security checks"
	@echo "  dev            - Run in development mode"
