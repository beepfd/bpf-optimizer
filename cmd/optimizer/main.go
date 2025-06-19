package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"net/http"
	_ "net/http/pprof"

	"github.com/beepfd/bpf-optimizer/pkg/optimizer"
)

var (
	inputFile  = flag.String("input", "", "Input BPF object file (.o)")
	outputFile = flag.String("output", "", "Output optimized BPF object file (.o)")
	verbose    = flag.Bool("verbose", false, "Verbose output")
	stats      = flag.Bool("stats", false, "Show optimization statistics")
	help       = flag.Bool("help", false, "Show help message")
	version    = flag.Bool("version", false, "Show version information")
)

const (
	VERSION     = "1.0.0"
	DESCRIPTION = "BPF字节码优化器 - Go版本"
)

func main() {
	flag.Parse()

	// Show help
	if *help {
		showHelp()
		return
	}

	// Show version
	if *version {
		fmt.Printf("BPF Optimizer %s\n", VERSION)
		fmt.Printf("%s\n", DESCRIPTION)
		fmt.Printf("移植自 Merlin Python 版本\n")
		return
	}

	// Validate arguments
	if *inputFile == "" {
		fmt.Fprintf(os.Stderr, "错误: 必须指定输入文件\n")
		showUsage()
		os.Exit(1)
	}

	if *outputFile == "" {
		// Default output file
		*outputFile = *inputFile + ".optimized"
	}

	// Check if input file exists
	if _, err := os.Stat(*inputFile); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "错误: 输入文件 '%s' 不存在\n", *inputFile)
		os.Exit(1)
	}

	// add pprof
	go func() {
		http.ListenAndServe("0.0.0.0:6060", nil)
	}()

	// Perform optimization
	if err := optimizeBPF(*inputFile, *outputFile); err != nil {
		fmt.Fprintf(os.Stderr, "优化失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ 优化完成: %s -> %s\n", *inputFile, *outputFile)
}

func optimizeBPF(inputPath, outputPath string) error {
	startTime := time.Now()

	if *verbose {
		fmt.Printf("正在加载 BPF 程序: %s\n", inputPath)
	}

	// Load BPF program
	prog, err := optimizer.NewBPFProgram(inputPath)
	if err != nil {
		return fmt.Errorf("加载 BPF 程序失败: %v", err)
	}
	defer prog.Close()

	if *verbose {
		fmt.Printf("找到 %d 个代码段\n", len(prog.Sections))
		for sectionName, section := range prog.Sections {
			fmt.Printf("  - %s: %d 条指令\n", sectionName, len(section.Instructions))
		}
	}

	// Save optimized program
	if *verbose {
		fmt.Printf("正在保存优化后的程序: %s\n", outputPath)
	}

	if err := prog.Save(outputPath); err != nil {
		return fmt.Errorf("保存优化程序失败: %v", err)
	}

	duration := time.Since(startTime)

	// Show statistics
	if *stats || *verbose {
		showStatistics(prog, duration)
	}

	return nil
}

func showStatistics(prog *optimizer.BPFProgram, duration time.Duration) {
	stats := prog.GetOptimizationStats()

	fmt.Println("\n=== 优化统计 ===")

	// Show per-section stats
	for sectionName, sectionStats := range stats {
		if sectionName == "summary" {
			continue
		}

		if sStats, ok := sectionStats.(map[string]int); ok {
			fmt.Printf("段 %s:\n", sectionName)
			fmt.Printf("  总指令数: %d\n", sStats["total"])
			fmt.Printf("  活动指令: %d\n", sStats["active"])
			fmt.Printf("  NOP指令: %d\n", sStats["nops"])
			if sStats["total"] > 0 {
				optimizationRatio := float64(sStats["nops"]) / float64(sStats["total"]) * 100
				fmt.Printf("  优化率: %.1f%%\n", optimizationRatio)
			}
			fmt.Println()
		}
	}

	// Show summary
	if summary, ok := stats["summary"].(map[string]interface{}); ok {
		fmt.Println("=== 总体统计 ===")
		fmt.Printf("总指令数: %v\n", summary["total_instructions"])
		fmt.Printf("优化指令数: %v\n", summary["optimized_instructions"])
		fmt.Printf("NOP指令数: %v\n", summary["nop_instructions"])
		if ratio, ok := summary["optimization_ratio"].(float64); ok {
			fmt.Printf("总体优化率: %.1f%%\n", ratio*100)
		}
		fmt.Printf("处理耗时: %v\n", duration)

		if *verbose {
			fmt.Println("\n详细统计 (JSON):")
			jsonData, _ := json.MarshalIndent(stats, "", "  ")
			fmt.Println(string(jsonData))
		}
	}
}

func showHelp() {
	fmt.Printf("%s %s\n\n", DESCRIPTION, VERSION)

	fmt.Println("这是一个 BPF 字节码优化器，实现了以下优化技术：")
	fmt.Println("  • 常量传播 (Constant Propagation)")
	fmt.Println("  • 代码紧凑化 (Code Compaction)")
	fmt.Println("  • 窥孔优化 (Peephole Optimization)")
	fmt.Println("  • 超字合并 (Superword-level Merge)")
	fmt.Println()

	showUsage()

	fmt.Println("示例:")
	fmt.Println("  # 基本优化")
	fmt.Println("  bpf-optimizer -input program.o -output program_opt.o")
	fmt.Println()
	fmt.Println("  # 显示优化统计")
	fmt.Println("  bpf-optimizer -input program.o -stats")
	fmt.Println()
	fmt.Println("  # 详细输出")
	fmt.Println("  bpf-optimizer -input program.o -verbose")
	fmt.Println()
	fmt.Println("功能特点:")
	fmt.Println("  ✓ 与 Merlin Python 版本功能兼容")
	fmt.Println("  ✓ 更高的性能和更低的内存使用")
	fmt.Println("  ✓ 支持所有 BPF 指令集")
	fmt.Println("  ✓ 保持 ELF 文件格式完整性")
}

func showUsage() {
	fmt.Println("用法:")
	fmt.Printf("  %s -input <file.o> [选项]\n\n", os.Args[0])

	fmt.Println("选项:")
	flag.PrintDefaults()
}
