package optimizer

import (
	"bufio"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/beepfd/bpf-optimizer/pkg/bpf"
)

func TestSection_buildControlFlowGraph(t *testing.T) {
	tests := []struct {
		name    string
		elfFile string
		want    *ControlFlowGraph
		wantErr bool
	}{
		{
			name:    "test1",
			elfFile: "../../testdata/bpf_generic_uprobe_v61.o",
			want:    &ControlFlowGraph{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			index := 0
			cfgs, err := parseControlFlowGraphFromFiles(
				"../../testdata/dep_nodes",
				"../../testdata/dep_nodes_rev",
				"../../testdata/dep_nodes_len",
			)
			if err != nil {
				t.Fatalf("Failed to parse control flow graphs: %v", err)
			}

			elfFile, err := elf.Open(tt.elfFile)
			if err != nil {
				t.Errorf("elf.Open() error = %v", err)
			}

			// Get symbol table
			symbols, err := elfFile.Symbols()
			if err != nil {
				t.Errorf("failed to read symbols: %v", err)
			}

			// Process each function symbol
			for _, symbol := range symbols {
				if elf.ST_TYPE(symbol.Info) == elf.STT_FUNC {
					index++
					section := elfFile.Sections[symbol.Section]
					if section == nil {
						continue
					}

					// Read section data
					data, err := section.Data()
					if err != nil {
						continue
					}

					// Skip empty sections
					if len(data) == 0 {
						continue
					}

					// Convert to hex string and create optimized section
					hexData := hex.EncodeToString(data)
					if len(hexData)%16 != 0 {
						t.Errorf("bytecode section length must be a multiple of 16")
					}

					optimizedSection := &Section{
						Name:         section.Name,
						Instructions: make([]*bpf.Instruction, 0),
						Dependencies: make([]DependencyInfo, 0),
					}

					// Parse instructions (16 hex chars each)
					for i := 0; i < len(hexData); i += 16 {
						inst, err := bpf.NewInstruction(hexData[i : i+16])
						if err != nil {
							t.Errorf("failed to parse instruction at %d: %v", i/16, err)
						}
						optimizedSection.Instructions = append(optimizedSection.Instructions, inst)
						optimizedSection.Dependencies = append(optimizedSection.Dependencies, DependencyInfo{
							Dependencies: make([]int, 0),
							DependedBy:   make([]int, 0),
						})
					}

					got := optimizedSection.buildControlFlowGraph()
					want := cfgs[index-1]

					errors := compareControlFlowGraphs(got, want)
					if len(errors) > 0 {
						t.Errorf("ControlFlowGraph comparison failed: %v", errors)
					}
				}
			}
		})
	}
}

// parseControlFlowGraphFromFiles 从测试数据文件解析 ControlFlowGraph
func parseControlFlowGraphFromFiles(nodesFile, revFile, lenFile string) ([]*ControlFlowGraph, error) {
	// 解析节点依赖关系
	nodes, err := parsePythonDict(nodesFile)
	if err != nil {
		return nil, err
	}

	// 解析反向依赖关系
	reverseNodes, err := parsePythonDict(revFile)
	if err != nil {
		return nil, err
	}

	// 解析节点长度信息
	lengths, err := parseNodeLengths(lenFile)
	if err != nil {
		return nil, err
	}

	// 构建 ControlFlowGraph
	cfgs := make([]*ControlFlowGraph, 0)
	for i := range nodes {
		cfg := &ControlFlowGraph{
			Nodes:    nodes[i],
			NodesRev: reverseNodes[i],
			NodesLen: lengths[i],
		}
		cfgs = append(cfgs, cfg)
	}

	return cfgs, nil
}

// parsePythonDict 解析 Python 字典格式的文件
func parsePythonDict(filename string) ([]map[int][]int, error) {
	result := make([]map[int][]int, 0)

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// 为每行创建一个 map
		lineMap := make(map[int][]int)

		// 移除外层的大括号 {}
		line = strings.Trim(line, "{}")
		if line == "" {
			result = append(result, lineMap)
			continue
		}

		// 需要智能分割，考虑数组中的逗号
		pairs := make([]string, 0)
		current := ""
		bracketDepth := 0

		for _, char := range line {
			if char == '[' {
				bracketDepth++
			} else if char == ']' {
				bracketDepth--
			} else if char == ',' && bracketDepth == 0 {
				pairs = append(pairs, strings.TrimSpace(current))
				current = ""
				continue
			}
			current += string(char)
		}
		if current != "" {
			pairs = append(pairs, strings.TrimSpace(current))
		}

		// 解析每个键值对
		for _, pair := range pairs {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}

			// 查找 ': [' 分隔符
			colonIndex := strings.Index(pair, ":")
			if colonIndex == -1 {
				continue
			}

			// 解析键
			keyStr := strings.TrimSpace(pair[:colonIndex])
			key, err := strconv.Atoi(keyStr)
			if err != nil {
				continue
			}

			// 解析值数组
			valueStr := strings.TrimSpace(pair[colonIndex+1:])
			valueStr = strings.TrimSpace(valueStr)

			// 处理数组格式
			if !strings.HasPrefix(valueStr, "[") || !strings.HasSuffix(valueStr, "]") {
				continue
			}

			arrayContent := strings.TrimSpace(valueStr[1 : len(valueStr)-1])
			var values []int
			if arrayContent != "" {
				valueStrs := strings.Split(arrayContent, ",")
				for _, vStr := range valueStrs {
					vStr = strings.TrimSpace(vStr)
					if vStr != "" {
						value, err := strconv.Atoi(vStr)
						if err == nil {
							values = append(values, value)
						}
					}
				}
			}

			lineMap[key] = values
		}

		result = append(result, lineMap)
	}

	return result, scanner.Err()
}

// parseNodeLengths 解析节点长度信息文件 (Python字典格式)
func parseNodeLengths(filename string) ([]map[int]int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	result := make([]map[int]int, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		subResult := make(map[int]int)
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// 移除外层的大括号 {}
		line = strings.Trim(line, "{}")
		if line == "" {
			continue
		}

		// 按逗号分割键值对
		pairs := strings.Split(line, ",")
		for _, pair := range pairs {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}

			// 分割键值对 "key: value"
			parts := strings.Split(pair, ":")
			if len(parts) != 2 {
				continue
			}

			// 解析键和值
			keyStr := strings.TrimSpace(parts[0])
			valueStr := strings.TrimSpace(parts[1])

			key, err := strconv.Atoi(keyStr)
			if err != nil {
				continue
			}

			value, err := strconv.Atoi(valueStr)
			if err != nil {
				continue
			}

			subResult[key] = value
		}
		result = append(result, subResult)
	}

	return result, scanner.Err()
}

// TestParseControlFlowGraph 测试解析函数
func TestParseControlFlowGraph(t *testing.T) {
	cfgs, err := parseControlFlowGraphFromFiles(
		"../../testdata/dep_nodes",
		"../../testdata/dep_nodes_rev",
		"../../testdata/dep_nodes_len",
	)
	if err != nil {
		t.Fatalf("Failed to parse control flow graphs: %v", err)
	}

	if len(cfgs) == 0 {
		t.Fatal("No control flow graphs parsed")
	}

	if cfgs[0].Nodes == nil {
		t.Error("Nodes map is nil")
	}
	if cfgs[0].NodesRev == nil {
		t.Error("NodesRev map is nil")
	}
	if cfgs[0].NodesLen == nil {
		t.Error("NodesLen map is nil")
	}

	// 验证解析结果的正确性
	firstGraph := cfgs[0]
	t.Logf("First graph has %d nodes", len(firstGraph.Nodes))

	// 显示前几个节点作为样例
	sampleCount := 0
	for nodeID, deps := range firstGraph.Nodes {
		if sampleCount >= 3 {
			break
		}
		t.Logf("Node %d depends on: %v", nodeID, deps)
		if revDeps, exists := firstGraph.NodesRev[nodeID]; exists {
			t.Logf("Node %d is depended by: %v", nodeID, revDeps)
		}
		if length, exists := firstGraph.NodesLen[nodeID]; exists {
			t.Logf("Node %d length: %d", nodeID, length)
		}
		sampleCount++
	}

	t.Logf("Successfully parsed ControlFlowGraph with %d nodes, %d reverse nodes, %d lengths",
		len(cfgs[0].Nodes), len(cfgs[0].NodesRev), len(cfgs[0].NodesLen))
}

// compareControlFlowGraphs 比较两个 ControlFlowGraph 是否相等
func compareControlFlowGraphs(got, want *ControlFlowGraph) []string {
	var errors []string

	// 只对比实际填充的字段，忽略 NodeStats
	// 比较 Nodes map
	if !compareIntSliceMap(got.Nodes, want.Nodes) {
		errors = append(errors, "Nodes maps differ")
		errors = append(errors, formatMapDifference("Nodes", got.Nodes, want.Nodes))
	}

	// 比较 NodesRev map
	if !compareIntSliceMap(got.NodesRev, want.NodesRev) {
		errors = append(errors, "NodesRev maps differ")
		errors = append(errors, formatMapDifference("NodesRev", got.NodesRev, want.NodesRev))
	}

	// 比较 NodesLen map
	if !compareIntIntMap(got.NodesLen, want.NodesLen) {
		errors = append(errors, "NodesLen maps differ")
		errors = append(errors, formatIntMapDifference("NodesLen", got.NodesLen, want.NodesLen))
	}

	return errors
}

// formatMapDifference 格式化 map[int][]int 的差异信息
func formatMapDifference(name string, got, want map[int][]int) string {
	var diff strings.Builder
	diff.WriteString(fmt.Sprintf("%s differences:\n", name))

	// 找出所有涉及的键
	allKeys := make(map[int]bool)
	for k := range got {
		allKeys[k] = true
	}
	for k := range want {
		allKeys[k] = true
	}

	keys := make([]int, 0, len(allKeys))
	for k := range allKeys {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	diffCount := 0
	for _, k := range keys {
		gotVal, gotExists := got[k]
		wantVal, wantExists := want[k]

		if !gotExists && wantExists {
			diff.WriteString(fmt.Sprintf("  Missing key %d: want %v\n", k, wantVal))
			diffCount++
		} else if gotExists && !wantExists {
			diff.WriteString(fmt.Sprintf("  Extra key %d: got %v\n", k, gotVal))
			diffCount++
		} else if !compareIntSlices(gotVal, wantVal) {
			diff.WriteString(fmt.Sprintf("  Key %d: got %v, want %v\n", k, gotVal, wantVal))
			diffCount++
		}

		// 限制显示的差异数量，避免输出过长
		if diffCount >= 10 {
			diff.WriteString("  ... (more differences exist)\n")
			break
		}
	}

	return diff.String()
}

// formatIntMapDifference 格式化 map[int]int 的差异信息
func formatIntMapDifference(name string, got, want map[int]int) string {
	var diff strings.Builder
	diff.WriteString(fmt.Sprintf("%s differences:\n", name))

	// 找出所有涉及的键
	allKeys := make(map[int]bool)
	for k := range got {
		allKeys[k] = true
	}
	for k := range want {
		allKeys[k] = true
	}

	keys := make([]int, 0, len(allKeys))
	for k := range allKeys {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	diffCount := 0
	for _, k := range keys {
		gotVal, gotExists := got[k]
		wantVal, wantExists := want[k]

		if !gotExists && wantExists {
			diff.WriteString(fmt.Sprintf("  Missing key %d: want %d\n", k, wantVal))
			diffCount++
		} else if gotExists && !wantExists {
			diff.WriteString(fmt.Sprintf("  Extra key %d: got %d\n", k, gotVal))
			diffCount++
		} else if gotVal != wantVal {
			diff.WriteString(fmt.Sprintf("  Key %d: got %d, want %d\n", k, gotVal, wantVal))
			diffCount++
		}

		// 限制显示的差异数量
		if diffCount >= 10 {
			diff.WriteString("  ... (more differences exist)\n")
			break
		}
	}

	return diff.String()
}

// compareIntSliceMap 比较两个 map[int][]int 是否相等
func compareIntSliceMap(got, want map[int][]int) bool {
	if len(got) != len(want) {
		return false
	}

	for key, gotSlice := range got {
		wantSlice, exists := want[key]
		if !exists {
			return false
		}

		if !compareIntSlices(gotSlice, wantSlice) {
			return false
		}
	}

	return true
}

// compareIntIntMap 比较两个 map[int]int 是否相等
func compareIntIntMap(got, want map[int]int) bool {
	if len(got) != len(want) {
		return false
	}

	for key, gotValue := range got {
		wantValue, exists := want[key]
		if !exists || gotValue != wantValue {
			return false
		}
	}

	return true
}

// compareIntSlices 比较两个 []int 是否相等（顺序敏感）
func compareIntSlices(got, want []int) bool {
	if len(got) != len(want) {
		return false
	}

	for i, gotValue := range got {
		if gotValue != want[i] {
			return false
		}
	}

	return true
}
