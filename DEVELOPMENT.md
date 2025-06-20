# BPF Optimizer 开发环境配置

## 环境要求

- **Go 版本**: 1.23.0 或更高版本
- **操作系统**: macOS, Linux, Windows
- **推荐编辑器**: VS Code with Go extension

## 快速开始

### 1. 基本设置

```bash
# 克隆项目
git clone https://github.com/beepfd/bpf-optimizer.git
cd bpf-optimizer

# 安装依赖
make deps

# 运行测试
make test

# 构建项目
make build
```

### 2. 开发工具安装

```bash
# 安装必要的 Go 工具
go install github.com/go-delve/delve/cmd/dlv@latest
go install golang.org/x/tools/cmd/goimports@latest
go install golang.org/x/tools/gopls@latest

# 安装代码质量检查工具
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.55.2
```

### 3. VS Code 配置

项目已经包含了完整的 VS Code 配置：

- **`.vscode/settings.json`** - Go 开发配置
- **`.vscode/launch.json`** - 调试配置
- **`.vscode/tasks.json`** - 构建任务配置

推荐安装的 VS Code 扩展：
- Go (golang.go)
- Go Test Explorer (premparihar.gotestexplorer)
- Better Comments (aaron-bond.better-comments)
- Error Lens (usernamehw.errorlens)

## 开发工作流

### 常用命令

```bash
# 开发模式运行
make dev

# 运行测试
make test

# 代码格式化
make fmt

# 代码静态检查
make vet

# 代码质量检查
make lint

# 构建项目
make build

# 交叉编译
make build-all

# 清理构建文件
make clean

# 查看所有可用命令
make help
```

### 调试

#### 使用 VS Code 调试

1. 在 VS Code 中打开项目
2. 按 `F5` 或点击调试按钮
3. 选择适当的调试配置：
   - **Launch BPF Optimizer** - 启动程序
   - **Debug with BPF file** - 使用 BPF 文件调试
   - **Debug Current Test** - 调试当前测试

#### 使用命令行调试

```bash
# 启动调试服务器
make debug

# 在另一个终端连接调试器
dlv connect :2345
```

### 测试

```bash
# 运行所有测试
make test

# 运行特定包的测试
go test -v ./pkg/bpf

# 运行基准测试
make benchmark

# 生成测试覆盖率报告
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## 项目结构

```
bpf-optimizer/
├── cmd/
│   └── optimizer/          # 主程序入口
├── pkg/
│   ├── bpf/               # BPF 相关功能
│   └── optimizer/         # 优化器核心逻辑
├── scripts/               # 开发脚本
├── build/                 # 构建输出目录
├── .vscode/              # VS Code 配置
├── .golangci.yml         # 代码质量检查配置
├── Makefile              # 构建配置
└── go.mod                # Go 模块配置
```

## 代码规范

### 格式化

使用 `goimports` 进行代码格式化：

```bash
make fmt
```

### 代码质量检查

使用 `golangci-lint` 进行代码质量检查：

```bash
make lint
```

### 提交规范

- 提交消息使用英文
- 遵循 [Conventional Commits](https://www.conventionalcommits.org/) 规范
- 每次提交前运行 `make lint` 和 `make test`

### 示例提交消息

```
feat: add BPF instruction optimization
fix: resolve parsing error for complex instructions
docs: update development setup guide
test: add unit tests for instruction parser
```

## 性能分析

### CPU 性能分析

```bash
# 构建带性能分析的版本
go build -o build/bpf-optimizer-prof ./cmd/optimizer

# 运行性能分析
./build/bpf-optimizer-prof -cpuprofile=cpu.prof -input=test.o

# 分析结果
go tool pprof cpu.prof
```

### 内存分析

```bash
# 运行内存分析
./build/bpf-optimizer-prof -memprofile=mem.prof -input=test.o

# 分析结果
go tool pprof mem.prof
```

## 故障排除

### 常见问题

1. **Go 版本不匹配**
   ```bash
   go version  # 检查当前版本
   # 确保版本 >= 1.23.0
   ```

2. **依赖下载失败**
   ```bash
   go env GOPROXY  # 检查代理设置
   go mod tidy     # 重新整理依赖
   ```

3. **构建失败**
   ```bash
   make clean      # 清理构建缓存
   make build      # 重新构建
   ```

4. **测试失败**
   ```bash
   go test -v ./... # 查看详细测试输出
   ```

### 获取帮助

- 查看 Makefile: `make help`
- 查看程序帮助: `./build/bpf-optimizer -help`
- 项目 Issues: [GitHub Issues](https://github.com/beepfd/bpf-optimizer/issues)

## 贡献指南

1. Fork 项目
2. 创建功能分支: `git checkout -b feature/amazing-feature`
3. 提交更改: `git commit -m 'feat: add amazing feature'`
4. 推送分支: `git push origin feature/amazing-feature`
5. 创建 Pull Request

确保在提交前：
- [ ] 运行 `make test` 通过所有测试
- [ ] 运行 `make lint` 通过代码质量检查
- [ ] 运行 `make fmt` 格式化代码
- [ ] 添加必要的测试用例
- [ ] 更新相关文档 