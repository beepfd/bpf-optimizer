package optimizer

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestSection_ProcessUsedRegisters(t *testing.T) {
	insns, _ := loadAnalysisFromFile("../../testdata/analyz_result.csv")

	cfgs, err := parseControlFlowGraphFromFiles(
		"../../testdata/dep_nodes",
		"../../testdata/dep_nodes_rev",
		"../../testdata/dep_nodes_len",
	)
	if err != nil {
		t.Fatalf("Failed to parse control flow graphs: %v", err)
	}

	for _, cfg := range cfgs {
		nodesDone := make(map[int]bool)
		nodeLen, exists := cfg.NodesLen[0]
		if !exists {
			t.Fatalf("Failed to get node length: %v", err)
		}

		insns := insns[0:2257]
		section := &Section{
			Instructions: insns,
			Dependencies: make([]DependencyInfo, 0),
		}
		for i := 0; i < len(insns); i++ {
			section.Dependencies = append(section.Dependencies, DependencyInfo{
				Dependencies: make([]int, 0),
				DependedBy:   make([]int, 0),
			})
		}

		section.BuildRegisterDependencies(cfg, nodeLen, 0, NewRegisterState(), nodesDone)

		deps := buildFakeDependencies("../../testdata/section_deps")
		for i := 0; i < len(deps); i++ {
			if !equalIntSlice(section.Dependencies[i].Dependencies, deps[i].Dependencies) ||
				!equalIntSlice(section.Dependencies[i].DependedBy, deps[i].DependedBy) {
				t.Errorf("Expected %dth element to be %v, got %v", i, deps[i], section.Dependencies[i])
			}
		}

		break
	}
}

func buildFakeDependencies(path string) []DependencyInfo {
	// 读取文件内容
	data, err := os.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("Failed to read file %s: %v", path, err))
	}

	content := strings.TrimSpace(string(data))

	// 这是一个Python列表，格式为：[[set(), set()], [{-1}, {2}], [{1}, set()], ...]
	// 移除最外层的方括号
	content = strings.TrimPrefix(content, "[")
	content = strings.TrimSuffix(content, "]")

	// 解析每个指令的依赖信息
	dependencies := make([]DependencyInfo, 0)

	// 手动解析嵌套的列表结构
	i := 0
	for i < len(content) {
		// 跳过空白字符和逗号
		for i < len(content) && (content[i] == ' ' || content[i] == ',' || content[i] == '\n' || content[i] == '\t') {
			i++
		}

		if i >= len(content) {
			break
		}

		// 期望找到一个 [deps, dependedBy] 对
		if content[i] == '[' {
			// 找到这个对的结束位置
			start := i
			bracketCount := 0

			for i < len(content) {
				if content[i] == '[' {
					bracketCount++
				} else if content[i] == ']' {
					bracketCount--
					if bracketCount == 0 {
						i++
						break
					}
				}
				i++
			}

			// 提取这一对的内容
			pairContent := content[start+1 : i-1] // 去掉外层括号

			// 解析这一对中的两个set
			sets := parseSetPair(pairContent)
			if len(sets) >= 2 {
				depInfo := DependencyInfo{
					Dependencies: parseSetContent(sets[0]),
					DependedBy:   parseSetContent(sets[1]),
				}
				dependencies = append(dependencies, depInfo)
			}
		} else {
			i++
		}
	}

	return dependencies
}

// parseSetPair 解析一对set，例如 "set(), {2}" 或 "{-1}, set()"
func parseSetPair(pairContent string) []string {
	sets := make([]string, 0)

	i := 0
	for i < len(pairContent) {
		// 跳过空白字符和逗号
		for i < len(pairContent) && (pairContent[i] == ' ' || pairContent[i] == ',' || pairContent[i] == '\n' || pairContent[i] == '\t') {
			i++
		}

		if i >= len(pairContent) {
			break
		}

		// 检查是否是 set() 格式
		if i+5 <= len(pairContent) && pairContent[i:i+5] == "set()" {
			sets = append(sets, "set()")
			i += 5
		} else if pairContent[i] == '{' {
			// 解析 {content} 格式
			start := i
			braceCount := 0

			for i < len(pairContent) {
				if pairContent[i] == '{' {
					braceCount++
				} else if pairContent[i] == '}' {
					braceCount--
					if braceCount == 0 {
						i++
						break
					}
				}
				i++
			}

			setContent := pairContent[start:i]
			sets = append(sets, setContent)
		} else {
			i++
		}
	}

	return sets
}

// parseSetContent 解析set内容，支持 set() 和 {1, 2, 3} 格式
func parseSetContent(setStr string) []int {
	result := make([]int, 0)

	setStr = strings.TrimSpace(setStr)

	// 处理空集合
	if setStr == "set()" {
		return result
	}

	// 处理 {content} 格式
	if strings.HasPrefix(setStr, "{") && strings.HasSuffix(setStr, "}") {
		content := setStr[1 : len(setStr)-1] // 去掉大括号
		content = strings.TrimSpace(content)

		if content == "" {
			return result
		}

		// 分割数字
		parts := strings.Split(content, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" {
				if num, err := strconv.Atoi(part); err == nil {
					result = append(result, num)
				}
			}
		}
	}

	return result
}

func TestBuildFakeDependencies(t *testing.T) {
	// 测试 buildFakeDependencies 函数
	dependencies := buildFakeDependencies("../../testdata/section_deps")

	// 验证数据解析是否正确
	if len(dependencies) == 0 {
		t.Fatalf("Expected non-empty dependencies, got empty slice")
	}

	// 验证第一个元素（应该是 [set(), set()]，即空集合）
	if len(dependencies[0].Dependencies) != 0 || len(dependencies[0].DependedBy) != 0 {
		t.Errorf("Expected first element to have empty dependencies and dependedBy, got %v", dependencies[0])
	}

	// 验证第二个元素（应该有 [{-1}, {2}]）
	if len(dependencies) > 1 {
		expected := DependencyInfo{
			Dependencies: []int{-1},
			DependedBy:   []int{2},
		}
		if !equalIntSlice(dependencies[1].Dependencies, expected.Dependencies) ||
			!equalIntSlice(dependencies[1].DependedBy, expected.DependedBy) {
			t.Errorf("Expected second element to be %v, got %v", expected, dependencies[1])
		}
	}

	// 验证第三个元素（应该有 [{1}, set()]）
	if len(dependencies) > 2 {
		expected := DependencyInfo{
			Dependencies: []int{1},
			DependedBy:   []int{},
		}
		if !equalIntSlice(dependencies[2].Dependencies, expected.Dependencies) ||
			!equalIntSlice(dependencies[2].DependedBy, expected.DependedBy) {
			t.Errorf("Expected third element to be %v, got %v", expected, dependencies[2])
		}
	}

	// 验证最后一个元素（应该有 [set(), {1}]）
	if len(dependencies) > 0 {
		lastIdx := len(dependencies) - 1
		expected := DependencyInfo{
			Dependencies: []int{},
			DependedBy:   []int{1},
		}
		if !equalIntSlice(dependencies[lastIdx].Dependencies, expected.Dependencies) ||
			!equalIntSlice(dependencies[lastIdx].DependedBy, expected.DependedBy) {
			t.Errorf("Expected last element to be %v, got %v", expected, dependencies[lastIdx])
		}
	}

	fmt.Printf("Successfully parsed %d dependency entries\n", len(dependencies))

	// 打印前几个元素以便调试
	for i := 0; i < 5 && i < len(dependencies); i++ {
		fmt.Printf("Element %d: Dependencies=%v, DependedBy=%v\n", i, dependencies[i].Dependencies, dependencies[i].DependedBy)
	}
}

// equalIntSlice 比较两个int切片是否相等
func equalIntSlice(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestCalculateActualIndex(t *testing.T) {
	tests := []struct {
		name        string
		index       int
		arrayLength int
		expected    int
	}{
		{
			name:        "特殊值 -1 保持不变",
			index:       -1,
			arrayLength: 10,
			expected:    -1,
		},
		{
			name:        "正数索引在范围内",
			index:       5,
			arrayLength: 10,
			expected:    5,
		},
		{
			name:        "正数索引超出范围",
			index:       15,
			arrayLength: 10,
			expected:    -1,
		},
		{
			name:        "负数索引 -2 转换为 n-2",
			index:       -2,
			arrayLength: 10,
			expected:    8, // 10 + (-2) = 8
		},
		{
			name:        "负数索引 -10 转换为 0",
			index:       -10,
			arrayLength: 10,
			expected:    0, // 10 + (-10) = 0
		},
		{
			name:        "负数索引超出范围",
			index:       -15,
			arrayLength: 10,
			expected:    -1, // 10 + (-15) = -5 < 0
		},
		{
			name:        "数组长度为 0",
			index:       5,
			arrayLength: 0,
			expected:    -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateActualIndex(tt.index, tt.arrayLength)
			if result != tt.expected {
				t.Errorf("calculateActualIndex(%d, %d) = %d, expected %d",
					tt.index, tt.arrayLength, result, tt.expected)
			}
		})
	}
}
