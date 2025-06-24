package optimizer

import (
	"debug/elf"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/beepfd/bpf-optimizer/pkg/bpf"
	"github.com/beepfd/bpf-optimizer/tool"
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
			cfgs, err := parseControlFlowGraphFromFiles(
				"../../testdata/dep_nodes",
				"../../testdata/dep_nodes_rev",
				"../../testdata/dep_nodes_len",
			)
			if err != nil {
				t.Fatalf("Failed to parse control flow graphs: %v", err)
			}

			index := 0
			sections, err := buildInstruction(tt.elfFile)
			if err != nil {
				t.Fatalf("Failed to build instruction: %v", err)
			}

			for _, section := range sections {
				got := section.buildControlFlowGraph()
				want := cfgs[index]
				index++

				errors := compareControlFlowGraphs(got, want)
				if len(errors) > 0 {
					t.Errorf("ControlFlowGraph comparison failed: %v", errors)
				}
			}
		})
	}
}

func buildInstruction(elfPath string) ([]*Section, error) {
	elfFile, err := elf.Open(elfPath)
	if err != nil {
		return nil, fmt.Errorf("elf.Open() error = %v", err)
	}
	defer elfFile.Close()

	// Get symbol table
	symbols, err := elfFile.Symbols()
	if err != nil {
		return nil, fmt.Errorf("failed to read symbols: %v", err)
	}

	// Process each function symbol
	sections := make([]*Section, 0)
	for _, symbol := range symbols {
		if elf.ST_TYPE(symbol.Info) == elf.STT_FUNC {
			section := elfFile.Sections[symbol.Section]
			if section == nil {
				continue
			}

			// Read section data
			sectionData, err := section.Data()
			if err != nil {
				continue
			}

			// Convert to hex string and create optimized section
			hexData := hex.EncodeToString(sectionData)
			if len(hexData)%16 != 0 {
				return nil, fmt.Errorf("bytecode section length must be a multiple of 16")
			}

			// 使用符号名称而不是 section 名称
			symbolName := getSymbolName(elfFile, symbol)

			optimizedSection := &Section{
				Name:         symbolName, // 使用函数名而不是 section 名
				Instructions: make([]*bpf.Instruction, 0),
				Dependencies: make([]DependencyInfo, 0),
			}

			// Parse instructions (16 hex chars each)
			for i := 0; i < len(hexData); i += 16 {
				inst, err := bpf.NewInstruction(hexData[i : i+16])
				if err != nil {
					return nil, fmt.Errorf("failed to parse instruction at %d: %v", i/16, err)
				}
				optimizedSection.Instructions = append(optimizedSection.Instructions, inst)
				optimizedSection.Dependencies = append(optimizedSection.Dependencies, DependencyInfo{
					Dependencies: make([]int, 0),
					DependedBy:   make([]int, 0),
				})
			}
			sections = append(sections, optimizedSection)
		}
	}

	return sections, nil
}

// 辅助函数：获取符号名称
func getSymbolName(elfFile *elf.File, symbol elf.Symbol) string {
	// 如果符号有名称，返回名称
	if symbol.Name != "" {
		return symbol.Name
	}
	// 否则返回默认名称
	return fmt.Sprintf("func_%x", symbol.Value)
}

// parseControlFlowGraphFromFiles 从测试数据文件解析 ControlFlowGraph
func parseControlFlowGraphFromFiles(nodesFile, revFile, lenFile string) ([]*ControlFlowGraph, error) {
	// 解析节点依赖关系
	nodes, err := tool.ParsePythonDictIntSlice(nodesFile)
	if err != nil {
		return nil, err
	}

	// 解析反向依赖关系
	reverseNodes, err := tool.ParsePythonDictIntSlice(revFile)
	if err != nil {
		return nil, err
	}

	// 解析节点长度信息
	lengths, err := tool.ParsePythonDictInt(lenFile)
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
	if !tool.CompareIntSliceMap(got.Nodes, want.Nodes) {
		errors = append(errors, "Nodes maps differ")
		errors = append(errors, tool.FormatMapDifference("Nodes", got.Nodes, want.Nodes))
	}

	// 比较 NodesRev map
	if !tool.CompareIntSliceMap(got.NodesRev, want.NodesRev) {
		errors = append(errors, "NodesRev maps differ")
		errors = append(errors, tool.FormatMapDifference("NodesRev", got.NodesRev, want.NodesRev))
	}

	// 比较 NodesLen map
	if !tool.CompareIntIntMap(got.NodesLen, want.NodesLen) {
		errors = append(errors, "NodesLen maps differ")
		errors = append(errors, tool.FormatIntMapDifference("NodesLen", got.NodesLen, want.NodesLen))
	}

	return errors
}
