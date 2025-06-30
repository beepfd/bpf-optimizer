# BPF Optimizer Makefile

# 项目信息
PROJECT_NAME = bpf-optimizer
VERSION = 1.0.0
BUILD_DIR = build
BINARY_NAME = bpf-optimizer

# Go 相关配置
GO = go
GOFLAGS = -tags=netgo,osusergo -gcflags "all=-N -l" -v
GOBUILD = $(GO) build $(GOFLAGS)
GOCLEAN = $(GO) clean
GOTEST = $(GO) test
GOGET = $(GO) get

# 目标架构
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

.PHONY: all build clean test help install deps fmt vet

# 默认目标
all: clean build

# 构建二进制文件
build:
	@echo "🔨 构建 $(PROJECT_NAME) v$(VERSION) for $(GOOS)/$(GOARCH)..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=$(GOOS) GOARCH=$(GOARCH) $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/optimizer
	@echo "✅ 构建完成: $(BUILD_DIR)/$(BINARY_NAME)"

# 交叉编译所有平台
build-all: clean
	@echo "🔨 交叉编译所有平台..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/optimizer
	@GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/optimizer
	@GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/optimizer
	@GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/optimizer
	@GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/optimizer
	@echo "✅ 交叉编译完成"

# 安装依赖
deps:
	@echo "📦 安装依赖..."
	@$(GO) mod tidy
	@$(GO) mod download
	@echo "✅ 依赖安装完成"

# 运行测试
test:
	@echo "🧪 运行测试..."
	@$(GOTEST) -v ./...

# 运行基准测试
benchmark:
	@echo "⚡ 运行基准测试..."
	@$(GOTEST) -bench=. -benchmem ./...

# 代码格式化
fmt:
	@echo "🎨 格式化代码..."
	@$(GO) fmt ./...

# 代码检查
vet:
	@echo "🔍 代码静态检查..."
	@$(GO) vet ./...

# 代码质量检查（需要 golangci-lint）
lint:
	@echo "🔍 代码质量检查..."
	@which golangci-lint > /dev/null || (echo "请安装 golangci-lint" && exit 1)
	@golangci-lint run

# 安装到系统
install: build
	@echo "📦 安装到系统..."
	@cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@echo "✅ 安装完成: /usr/local/bin/$(BINARY_NAME)"

# 清理构建文件
clean:
	@echo "🧹 清理构建文件..."
	@$(GOCLEAN)
	@rm -rf $(BUILD_DIR)
	@echo "✅ 清理完成"

# 构建调试版本
debug: 
	@echo "🔧 构建调试版本..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build -gcflags="all=-N -l" -o $(BUILD_DIR)/$(BINARY_NAME)-debug ./cmd/optimizer
	@echo "✅ 调试版本构建完成: $(BUILD_DIR)/$(BINARY_NAME)-debug"
	@echo "使用方法:"
	@echo "  1. VS Code调试: 按F5选择调试配置"
	@echo "  2. 命令行调试: dlv exec ./$(BUILD_DIR)/$(BINARY_NAME)-debug"
	@echo "  3. 远程调试: dlv --listen=:2345 --headless=true --api-version=2 exec ./$(BUILD_DIR)/$(BINARY_NAME)-debug"

# 使用race检测器构建
debug-race:
	@echo "🔧 构建竞态检测版本..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build -race -gcflags="all=-N -l" -o $(BUILD_DIR)/$(BINARY_NAME)-race ./cmd/optimizer
	@echo "✅ 竞态检测版本构建完成: $(BUILD_DIR)/$(BINARY_NAME)-race"

# 启动调试服务器
debug-server: debug
	@echo "🔧 启动调试服务器..."
	@echo "调试服务器将在 :2345 端口启动"
	@echo "可以在另一个终端或VS Code中连接到此服务器"
	dlv --listen=:2345 --headless=true --api-version=2 --accept-multiclient exec ./$(BUILD_DIR)/$(BINARY_NAME)-debug \
	-- -input /workload/tetragon/bpf/objs/bpf_generic_uprobe_v61.o -output test_optimized.o

# 交互式调试
debug-interactive: debug
	@echo "🔧 启动交互式调试..."
	dlv exec ./$(BUILD_DIR)/$(BINARY_NAME)-debug

# 调试测试
debug-test:
	@echo "🔧 调试测试..."
	@echo "调试包: $(shell pwd)/pkg/bpf"
	dlv test ./pkg/bpf

# 调试指定测试
debug-test-specific:
	@echo "🔧 调试指定测试..."
	@read -p "输入测试函数名: " test_name; \
	read -p "输入包路径 (默认: ./pkg/bpf): " pkg_path; \
	pkg_path=$${pkg_path:-./pkg/bpf}; \
	echo "调试测试: $$test_name 在包: $$pkg_path"; \
	dlv test $$pkg_path -- -test.run "^$$test_name$$" -test.v

# 调试所有测试
debug-test-all:
	@echo "🔧 调试所有测试..."
	dlv test ./...

# 调试基准测试
debug-benchmark:
	@echo "🔧 调试基准测试..."
	@read -p "输入基准测试模式 (默认: .): " bench_pattern; \
	read -p "输入包路径 (默认: ./pkg/bpf): " pkg_path; \
	bench_pattern=$${bench_pattern:-.}; \
	pkg_path=$${pkg_path:-./pkg/bpf}; \
	echo "调试基准测试: $$bench_pattern 在包: $$pkg_path"; \
	dlv test $$pkg_path -- -test.bench "$$bench_pattern" -test.benchmem -test.v

# 调试测试覆盖率
debug-test-coverage:
	@echo "🔧 调试测试覆盖率..."
	@read -p "输入包路径 (默认: ./pkg/bpf): " pkg_path; \
	pkg_path=$${pkg_path:-./pkg/bpf}; \
	echo "调试测试覆盖率在包: $$pkg_path"; \
	dlv test $$pkg_path -- -test.cover -test.v

# 显示项目信息
info:
	@echo "📋 项目信息:"
	@echo "  名称: $(PROJECT_NAME)"
	@echo "  版本: $(VERSION)"
	@echo "  Go版本: $(shell go version)"
	@echo "  目标平台: $(GOOS)/$(GOARCH)"
	@echo "  Delve版本: $(shell dlv version 2>/dev/null | head -1 || echo '未安装')"

# 运行示例
demo: build
	@echo "🚀 运行演示..."
	@echo "请提供一个 BPF .o 文件来测试"
	@echo "使用方法: ./$(BUILD_DIR)/$(BINARY_NAME) -input your_program.o -stats"

# 开发模式运行
dev:
	@echo "🔧 开发模式运行..."
	@$(GO) run ./cmd/optimizer -help

# 生产环境构建
release: clean lint test build-all
	@echo "🚀 生产环境构建完成"
	@ls -la $(BUILD_DIR)/


# 显示帮助
help:
	@echo "📖 BPF Optimizer 构建系统"
	@echo ""
	@echo "🔨 构建目标:"
	@echo "  build        构建二进制文件"
	@echo "  build-all    交叉编译所有平台"
	@echo "  debug        构建调试版本"
	@echo "  debug-race   构建竞态检测版本"
	@echo "  release      生产环境构建"
	@echo ""
	@echo "🧪 测试目标:"
	@echo "  test                运行测试"
	@echo "  benchmark           运行基准测试"
	@echo "  debug-test          调试BPF包测试"
	@echo "  debug-test-specific 调试指定测试函数"
	@echo "  debug-test-all      调试所有测试"
	@echo "  debug-benchmark     调试基准测试"
	@echo "  debug-test-coverage 调试测试覆盖率"
	@echo ""
	@echo "🔍 代码质量:"
	@echo "  fmt          格式化代码"
	@echo "  vet          代码静态检查"
	@echo "  lint         代码质量检查"
	@echo ""
	@echo "🐛 调试工具:"
	@echo "  debug-interactive  交互式调试"
	@echo "  debug-server       启动调试服务器(:2345)"
	@echo ""
	@echo "🛠️  其他:"
	@echo "  deps         安装依赖"
	@echo "  install      安装到系统"
	@echo "  clean        清理构建文件"
	@echo "  info         显示项目信息"
	@echo "  demo         运行演示"
	@echo "  dev          开发模式运行"
	@echo "  help         显示此帮助信息"
	@echo ""
	@echo "环境变量:"
	@echo "  GOOS         目标操作系统 (linux, darwin, windows)"
	@echo "  GOARCH       目标架构 (amd64, arm64)"
	@echo ""
	@echo "示例:"
	@echo "  make                    # 构建当前平台"
	@echo "  make GOOS=linux build   # 构建 Linux 版本"
	@echo "  make release            # 生产环境构建" 