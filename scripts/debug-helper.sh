#!/bin/bash

# BPF Optimizer 调试辅助脚本

set -e

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build"
DEBUG_BINARY="${BUILD_DIR}/bpf-optimizer-debug"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

function print_usage() {
    echo "BPF Optimizer 调试辅助工具"
    echo ""
    echo "用法: $0 <command> [options]"
    echo ""
    echo "🔨 基本命令:"
    echo "  build                构建调试版本"
    echo "  run [args]           运行调试版本"
    echo "  debug [args]         启动交互式调试"
    echo "  server               启动调试服务器"
    echo "  attach <pid>         附加到进程"
    echo "  check                检查调试环境"
    echo "  clean                清理调试文件"
    echo ""
    echo "🧪 测试调试命令:"
    echo "  test [pkg]           调试包测试"
    echo "  test-specific <name> [pkg]  调试指定测试函数"
    echo "  test-all             调试所有测试"
    echo "  benchmark [pattern] [pkg]   调试基准测试"
    echo "  test-coverage [pkg]  调试测试覆盖率"
    echo ""
    echo "📝 基本示例:"
    echo "  $0 build                        # 构建调试版本"
    echo "  $0 run -help                   # 运行程序"
    echo "  $0 debug -input test.o         # 调试程序"
    echo "  $0 server                      # 启动调试服务器"
    echo ""
    echo "🧪 测试调试示例:"
    echo "  $0 test                        # 调试BPF包测试"
    echo "  $0 test ./pkg/optimizer        # 调试optimizer包测试"
    echo "  $0 test-specific TestParse     # 调试TestParse函数"
    echo "  $0 test-specific TestParse ./pkg/bpf  # 调试指定包中的测试"
    echo "  $0 benchmark                   # 调试所有基准测试"
    echo "  $0 benchmark BenchmarkParse    # 调试指定基准测试"
    echo "  $0 test-coverage               # 调试测试覆盖率"
}

function check_delve() {
    if ! command -v dlv &> /dev/null; then
        echo -e "${RED}❌ Delve调试器未安装${NC}"
        echo "请运行: go install github.com/go-delve/delve/cmd/dlv@latest"
        exit 1
    fi
    echo -e "${GREEN}✅ Delve版本: $(dlv version | head -1)${NC}"
}

function build_debug() {
    echo -e "${BLUE}🔧 构建调试版本...${NC}"
    cd "$PROJECT_ROOT"
    mkdir -p "$BUILD_DIR"
    go build -gcflags="all=-N -l" -o "$DEBUG_BINARY" ./cmd/optimizer
    echo -e "${GREEN}✅ 调试版本构建完成: $DEBUG_BINARY${NC}"
}

function run_debug() {
    if [ ! -f "$DEBUG_BINARY" ]; then
        echo -e "${YELLOW}⚠️  调试版本不存在，正在构建...${NC}"
        build_debug
    fi
    
    echo -e "${BLUE}🚀 运行调试版本...${NC}"
    echo "命令: $DEBUG_BINARY $@"
    "$DEBUG_BINARY" "$@"
}

function start_interactive_debug() {
    if [ ! -f "$DEBUG_BINARY" ]; then
        echo -e "${YELLOW}⚠️  调试版本不存在，正在构建...${NC}"
        build_debug
    fi
    
    echo -e "${BLUE}🐛 启动交互式调试...${NC}"
    echo "调试器命令提示:"
    echo "  b main.main     # 在main函数设置断点"
    echo "  c               # 继续执行"
    echo "  n               # 下一行"
    echo "  s               # 步入"
    echo "  p <var>         # 打印变量"
    echo "  q               # 退出"
    echo ""
    
    if [ $# -gt 0 ]; then
        dlv exec "$DEBUG_BINARY" -- "$@"
    else
        dlv exec "$DEBUG_BINARY"
    fi
}

function start_debug_server() {
    if [ ! -f "$DEBUG_BINARY" ]; then
        echo -e "${YELLOW}⚠️  调试版本不存在，正在构建...${NC}"
        build_debug
    fi
    
    echo -e "${BLUE}🌐 启动调试服务器...${NC}"
    echo "服务器地址: localhost:2345"
    echo "VS Code可以连接到此服务器进行远程调试"
    echo "按 Ctrl+C 停止服务器"
    echo ""
    
    dlv --listen=:2345 --headless=true --api-version=2 --accept-multiclient exec "$DEBUG_BINARY"
}

function debug_test() {
    local test_pkg="${1:-./pkg/bpf}"
    echo -e "${BLUE}🧪 调试测试: $test_pkg${NC}"
    
    cd "$PROJECT_ROOT"
    dlv test "$test_pkg"
}

function debug_specific_test() {
    local test_name="$1"
    local test_pkg="${2:-./pkg/bpf}"
    
    if [ -z "$test_name" ]; then
        echo -e "${RED}❌ 请提供测试函数名${NC}"
        echo "用法: $0 test-specific <test_name> [package]"
        echo "示例: $0 test-specific TestParse ./pkg/bpf"
        exit 1
    fi
    
    echo -e "${BLUE}🧪 调试指定测试: $test_name 在 $test_pkg${NC}"
    echo "调试器命令提示:"
    echo "  b $test_name     # 在测试函数设置断点"
    echo "  c               # 继续执行"
    echo "  n               # 下一行"
    echo "  s               # 步入"
    echo "  p <var>         # 打印变量"
    echo "  q               # 退出"
    echo ""
    
    cd "$PROJECT_ROOT"
    dlv test "$test_pkg" -- -test.run "^${test_name}$" -test.v
}

function debug_all_tests() {
    echo -e "${BLUE}🧪 调试所有测试...${NC}"
    
    cd "$PROJECT_ROOT"
    dlv test ./...
}

function debug_benchmark() {
    local bench_pattern="${1:-.}"
    local test_pkg="${2:-./pkg/bpf}"
    
    echo -e "${BLUE}⚡ 调试基准测试: $bench_pattern 在 $test_pkg${NC}"
    echo "调试器命令提示:"
    echo "  b Benchmark*    # 在基准测试函数设置断点"
    echo "  c               # 继续执行"
    echo "  n               # 下一行"
    echo "  s               # 步入"
    echo "  q               # 退出"
    echo ""
    
    cd "$PROJECT_ROOT"
    dlv test "$test_pkg" -- -test.bench "$bench_pattern" -test.benchmem -test.v
}

function debug_test_coverage() {
    local test_pkg="${1:-./pkg/bpf}"
    
    echo -e "${BLUE}📊 调试测试覆盖率: $test_pkg${NC}"
    
    cd "$PROJECT_ROOT"
    dlv test "$test_pkg" -- -test.cover -test.v
}

function attach_to_process() {
    local pid="$1"
    if [ -z "$pid" ]; then
        echo -e "${RED}❌ 请提供进程ID${NC}"
        echo "用法: $0 attach <pid>"
        exit 1
    fi
    
    echo -e "${BLUE}🔗 附加到进程 $pid...${NC}"
    dlv attach "$pid"
}

function check_environment() {
    echo -e "${BLUE}🔍 检查调试环境...${NC}"
    echo ""
    
    # 检查Go版本
    echo "Go版本: $(go version)"
    
    # 检查Delve
    check_delve
    
    # 检查调试版本
    if [ -f "$DEBUG_BINARY" ]; then
        echo -e "${GREEN}✅ 调试版本: $DEBUG_BINARY${NC}"
        echo "   大小: $(du -h "$DEBUG_BINARY" | cut -f1)"
        echo "   修改时间: $(stat -f "%Sm" "$DEBUG_BINARY")"
    else
        echo -e "${YELLOW}⚠️  调试版本不存在${NC}"
    fi
    
    # 检查VS Code配置
    if [ -f "$PROJECT_ROOT/.vscode/launch.json" ]; then
        echo -e "${GREEN}✅ VS Code调试配置存在${NC}"
    else
        echo -e "${YELLOW}⚠️  VS Code调试配置不存在${NC}"
    fi
    
    # 检查端口
    if lsof -i :2345 &> /dev/null; then
        echo -e "${YELLOW}⚠️  端口2345已被占用${NC}"
    else
        echo -e "${GREEN}✅ 调试端口2345可用${NC}"
    fi
}

function clean_debug() {
    echo -e "${BLUE}🧹 清理调试文件...${NC}"
    
    if [ -f "$DEBUG_BINARY" ]; then
        rm -f "$DEBUG_BINARY"
        echo -e "${GREEN}✅ 已删除调试版本${NC}"
    fi
    
    # 清理调试符号文件
    find "$BUILD_DIR" -name "*.debug" -delete 2>/dev/null || true
    
    echo -e "${GREEN}✅ 调试文件清理完成${NC}"
}

# 主程序
case "$1" in
    build)
        check_delve
        build_debug
        ;;
    run)
        check_delve
        shift
        run_debug "$@"
        ;;
    debug)
        check_delve
        shift
        start_interactive_debug "$@"
        ;;
    server)
        check_delve
        start_debug_server
        ;;
    test)
        check_delve
        shift
        debug_test "$@"
        ;;
    test-specific)
        check_delve
        shift
        debug_specific_test "$@"
        ;;
    test-all)
        check_delve
        debug_all_tests
        ;;
    benchmark)
        check_delve
        shift
        debug_benchmark "$@"
        ;;
    test-coverage)
        check_delve
        shift
        debug_test_coverage "$@"
        ;;
    attach)
        check_delve
        shift
        attach_to_process "$@"
        ;;
    check)
        check_environment
        ;;
    clean)
        clean_debug
        ;;
    help|--help|-h)
        print_usage
        ;;
    *)
        echo -e "${RED}❌ 未知命令: $1${NC}"
        echo ""
        print_usage
        exit 1
        ;;
esac 