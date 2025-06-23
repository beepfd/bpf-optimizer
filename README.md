# BPF Optimizer - Go 版本

![Go Version](https://img.shields.io/badge/Go-1.23+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

这是一个高性能的 BPF 字节码优化器，用 Go 重写了原始的 Python 版本。它实现了多种先进的优化技术来提高 BPF 程序的性能和代码紧凑性。本项目将 [Merlin](https://github.com/4ar0nma0/Merlin) 的 Python 版本移植到了 Go 版本。

## 🚀 功能特点

### 四种核心优化算法

1. **常量传播 (Constant Propagation)**
   - 将常量值直接传播到使用点
   - 消除不必要的寄存器加载操作
   - 减少指令数量和执行时间

2. **代码紧凑化 (Code Compaction)**
   - 识别并合并冗余的位操作序列
   - 将多个简单操作合并为单个复杂操作
   - 特别优化位移和掩码操作

3. **窥孔优化 (Peephole Optimization)**
   - 分析小范围指令序列的优化机会
   - 识别并替换低效的指令模式
   - 优化掩码和位操作组合

4. **超字合并 (Superword-level Merge)**
   - 合并相邻的内存操作
   - 提高内存访问效率
   - 减少内存访问次数


## 📦 安装

### 从源码编译

```bash
git clone https://github.com/beepfd/bpf-optimizer.git
cd bpf-optimizer
go build -o bpf-optimizer ./cmd/optimizer
```

### 使用 Go Install

```bash
go install github.com/beepfd/bpf-optimizer/cmd/optimizer@latest
```

## 🔧 使用方法

### 基本用法

```bash
# 基本优化
./bpf-optimizer -input program.o -output program_optimized.o

# 显示优化统计信息
./bpf-optimizer -input program.o -stats

# 详细输出模式
./bpf-optimizer -input program.o -verbose
```

### 命令行选项

```
选项:
  -input string
        输入 BPF 目标文件 (.o)
  -output string
        输出优化后的 BPF 目标文件 (.o)
  -stats
        显示优化统计信息
  -verbose
        详细输出模式
  -help
        显示帮助信息
  -version
        显示版本信息
```

### 使用示例

```bash
# 示例 1: 基本优化
./bpf-optimizer -input test.o -output test_opt.o

# 示例 2: 查看优化效果
./bpf-optimizer -input test.o -stats
# 输出:
# === 优化统计 ===
# 段 .text:
#   总指令数: 45
#   活动指令: 38
#   NOP指令: 7
#   优化率: 15.6%

# 示例 3: 详细分析
./bpf-optimizer -input test.o -verbose -stats
```