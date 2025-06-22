# BPF Optimizer 测试调试指南

## 🎯 概述

本指南介绍如何调试 BPF Optimizer 项目中的单元测试。支持多种调试方式：VS Code 图形化调试、命令行调试、以及各种测试类型的调试。

## 🛠️ 调试环境配置

### 已配置的组件

1. **VS Code 调试配置** - `.vscode/launch.json`
2. **Makefile 调试目标** - 多种测试调试命令
3. **调试辅助脚本** - `scripts/debug-helper.sh`
4. **Delve 调试器** - Go 官方调试工具

### 环境检查

```bash
# 检查调试环境
./scripts/debug-helper.sh check
```

## 🧪 VS Code 调试测试

### 可用的调试配置

1. **Debug Current Test File** - 调试当前文件的所有测试
2. **Debug Specific Test** - 调试指定的测试函数
3. **Debug All Tests** - 调试整个项目的所有测试
4. **Debug BPF Package Tests** - 调试 BPF 包测试
5. **Debug Optimizer Package Tests** - 调试优化器包测试
6. **Debug Test with Coverage** - 带覆盖率的测试调试
7. **Debug Benchmark Tests** - 调试基准测试
8. **Debug Test with Race Detection** - 带竞态检测的测试调试

### 使用方法

1. 在 VS Code 中打开项目
2. 打开要调试的测试文件（如 `pkg/bpf/instruction_test.go`）
3. 在测试函数中设置断点
4. 按 `F5` 或点击调试按钮
5. 选择适当的调试配置
6. 输入测试函数名（如果需要）

### 示例：调试指定测试

1. 打开 `pkg/bpf/instruction_test.go`
2. 在 `TestNewInstruction` 函数中设置断点
3. 按 `F5`，选择 "Debug Specific Test"
4. 输入测试名：`TestNewInstruction`
5. 开始调试

## 🔧 命令行调试测试

### 使用调试辅助脚本

#### 基本测试调试

```bash
# 调试 BPF 包的所有测试
./scripts/debug-helper.sh test

# 调试指定包的测试
./scripts/debug-helper.sh test ./pkg/optimizer
```

#### 调试指定测试函数

```bash
# 调试指定测试函数
./scripts/debug-helper.sh test-specific TestNewInstruction

# 调试指定包中的测试函数
./scripts/debug-helper.sh test-specific TestParse ./pkg/bpf
```

#### 调试所有测试

```bash
# 调试项目中的所有测试
./scripts/debug-helper.sh test-all
```

#### 调试基准测试

```bash
# 调试所有基准测试
./scripts/debug-helper.sh benchmark

# 调试指定的基准测试
./scripts/debug-helper.sh benchmark BenchmarkParse

# 调试指定包的基准测试
./scripts/debug-helper.sh benchmark . ./pkg/bpf
```

#### 调试测试覆盖率

```bash
# 调试带覆盖率的测试
./scripts/debug-helper.sh test-coverage

# 调试指定包的测试覆盖率
./scripts/debug-helper.sh test-coverage ./pkg/optimizer
```

### 使用 Makefile

```bash
# 调试 BPF 包测试
make debug-test

# 调试指定测试（交互式输入）
make debug-test-specific

# 调试所有测试
make debug-test-all

# 调试基准测试（交互式输入）
make debug-benchmark

# 调试测试覆盖率（交互式输入）
make debug-test-coverage
```

## 🐛 调试器命令

### 基本命令

```bash
# 设置断点
b <function_name>          # 在函数设置断点
b <file>:<line>           # 在文件的指定行设置断点
b TestNewInstruction      # 在测试函数设置断点

# 执行控制
c                         # 继续执行
n                         # 下一行（不进入函数）
s                         # 步入函数
finish                    # 执行完当前函数

# 查看变量
p <variable>              # 打印变量值
locals                    # 显示所有本地变量
args                      # 显示函数参数
vars                      # 显示包级变量

# 调用栈
bt                        # 显示调用栈
up                        # 向上移动栈帧
down                      # 向下移动栈帧

# 其他
l                         # 列出当前代码
help                      # 显示帮助
q                         # 退出调试器
```

### 测试特定命令

```bash
# 查看测试结果
p t.Failed()              # 检查测试是否失败
p t.Name()                # 获取测试名称

# 查看测试数据
p testCases               # 查看测试用例数据
p got                     # 查看实际结果
p want                    # 查看期望结果
```

## 📝 调试示例

### 示例1：调试失败的测试

```bash
# 1. 启动指定测试的调试
./scripts/debug-helper.sh test-specific TestNewInstruction

# 2. 在调试器中设置断点
(dlv) b TestNewInstruction

# 3. 继续执行到断点
(dlv) c

# 4. 查看测试数据
(dlv) p testCases
(dlv) locals

# 5. 步进执行
(dlv) n
(dlv) n

# 6. 查看变量值
(dlv) p result
(dlv) p expected
```

### 示例2：调试基准测试

```bash
# 1. 启动基准测试调试
./scripts/debug-helper.sh benchmark BenchmarkParse

# 2. 在基准测试函数设置断点
(dlv) b BenchmarkParse

# 3. 查看基准测试执行
(dlv) c
(dlv) p b.N
(dlv) locals
```

### 示例3：调试竞态条件

```bash
# 使用 VS Code "Debug Test with Race Detection" 配置
# 或使用命令行
go test -race -v ./pkg/bpf
```

## 🔍 故障排除

### 常见问题

1. **调试器无法启动**
   ```bash
   # 检查 Delve 是否正确安装
   dlv version
   
   # 重新安装 Delve
   go install github.com/go-delve/delve/cmd/dlv@latest
   ```

2. **无法设置断点**
   ```bash
   # 确保使用调试构建
   go build -gcflags="all=-N -l" -o debug-binary ./cmd/optimizer
   
   # 检查函数名是否正确
   (dlv) funcs TestNew*
   ```

3. **变量无法查看**
   ```bash
   # 变量可能被优化掉，使用调试构建
   # 或查看是否在正确的作用域
   (dlv) locals
   (dlv) args
   ```

4. **测试超时**
   ```bash
   # 增加测试超时时间
   go test -timeout=30s -v ./pkg/bpf
   ```

### 性能注意事项

- 调试模式会显著降低执行速度
- 基准测试在调试模式下结果不准确
- 大量测试的调试可能需要较长时间

## 📚 最佳实践

### 调试策略

1. **逐步缩小范围**
   - 先运行所有测试确定失败的测试
   - 然后只调试失败的测试

2. **使用合适的调试配置**
   - 单个测试：使用 "Debug Specific Test"
   - 包测试：使用 "Debug BPF Package Tests"
   - 性能问题：使用 "Debug Benchmark Tests"

3. **设置有效断点**
   - 在测试函数入口设置断点
   - 在关键逻辑处设置断点
   - 在断言前设置断点

4. **充分利用变量查看**
   - 查看测试输入数据
   - 查看中间处理结果
   - 查看期望vs实际结果

### 测试编写建议

```go
func TestExample(t *testing.T) {
    testCases := []struct {
        name     string
        input    string
        expected string
    }{
        {"case1", "input1", "output1"},
        {"case2", "input2", "output2"},
    }
    
    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            // 在这里设置断点便于调试
            result := YourFunction(tc.input)
            
            if result != tc.expected {
                t.Errorf("got %v, want %v", result, tc.expected)
            }
        })
    }
}
```

## 🎯 总结

现在你可以使用多种方式调试测试：

- ✅ **VS Code 图形化调试** - 最直观的调试方式
- ✅ **命令行调试** - 灵活的调试选项
- ✅ **多种测试类型** - 单元测试、基准测试、覆盖率测试
- ✅ **便捷脚本** - 一键启动各种调试模式
- ✅ **Makefile 集成** - 与构建系统集成

选择最适合你的调试方式，开始高效的测试调试吧！ 