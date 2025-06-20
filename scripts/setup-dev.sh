#!/bin/bash

# BPF Optimizer 开发环境设置脚本
# 适用于 macOS

set -e

echo "🚀 设置 BPF Optimizer 开发环境..."

# 检查 Go 版本
echo "📋 检查 Go 版本..."
go version

# 安装 Go 工具
echo "🛠️  安装 Go 开发工具..."

# 安装 delve 调试器
if ! command -v dlv &> /dev/null; then
    echo "安装 delve 调试器..."
    go install github.com/go-delve/delve/cmd/dlv@latest
else
    echo "✅ delve 已安装"
fi

# 安装 goimports
if ! command -v goimports &> /dev/null; then
    echo "安装 goimports..."
    go install golang.org/x/tools/cmd/goimports@latest
else
    echo "✅ goimports 已安装"
fi

# 安装 golangci-lint
if ! command -v golangci-lint &> /dev/null; then
    echo "安装 golangci-lint..."
    curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.55.2
else
    echo "✅ golangci-lint 已安装"
fi

# 安装 gopls (Go 语言服务器)
if ! command -v gopls &> /dev/null; then
    echo "安装 gopls..."
    go install golang.org/x/tools/gopls@latest
else
    echo "✅ gopls 已安装"
fi

# 安装 go-outline
echo "安装 go-outline..."
go install github.com/ramya-rao-a/go-outline@latest

# 安装 gocode-gomod
echo "安装 gocode-gomod..."
go install github.com/stamblerre/gocode@latest

# 安装 gotests
echo "安装 gotests..."
go install github.com/cweill/gotests/gotests@latest

# 检查项目依赖
echo "📦 检查项目依赖..."
cd "$(dirname "$0")/.."
go mod tidy
go mod download

# 运行测试确保环境正常
echo "🧪 运行测试..."
make test

# 构建项目
echo "🔨 构建项目..."
make build

echo ""
echo "✅ 开发环境设置完成！"
echo ""
echo "📖 使用说明："
echo "  - 使用 'make help' 查看所有可用命令"
echo "  - 使用 'make dev' 在开发模式下运行"
echo "  - 使用 'make test' 运行测试"
echo "  - 使用 'make debug' 启动调试服务器"
echo "  - 在 VS Code 中按 F5 开始调试"
echo ""
echo "🔧 VS Code 配置："
echo "  - 已创建 .vscode/settings.json - Go 开发配置"
echo "  - 已创建 .vscode/launch.json - 调试配置"
echo "  - 已创建 .vscode/tasks.json - 任务配置"
echo ""
echo "建议安装的 VS Code 扩展："
echo "  - Go (golang.go)"
echo "  - Go Test Explorer (premparihar.gotestexplorer)"
echo "  - Better Comments (aaron-bond.better-comments)"
echo "  - Error Lens (usernamehw.errorlens)" 