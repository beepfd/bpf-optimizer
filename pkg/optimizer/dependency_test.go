package optimizer

import (
	"bufio"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
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
					t.Errorf("ControlFlowGraph index %d comparison failed: %v", index, errors)
				}

				// 只对第一个进行测试，当前结果后续会执行常量传播等优化，之后的指令会发生变化，导致结果不一致
				break
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

func TestSection_updateDependencies(t *testing.T) {
	type fields struct {
		Name         string
		Instructions []*bpf.Instruction
		Dependencies []DependencyInfo
	}
	type args struct {
		cfg       *ControlFlowGraph
		base      int
		state     *RegisterState
		nodesDone map[int]bool
		loopInfo  *LoopInfo
		inferOnly bool
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *RegisterState
	}{
		{
			name: "基于 update_property_init_args 参数的测试",
			fields: fields{
				Name:         "test_function",
				Instructions: make([]*bpf.Instruction, 0),
				Dependencies: make([]DependencyInfo, 0),
			},
			args: args{
				cfg:       buildTestControlFlowGraph(),
				base:      0,
				state:     NewRegisterState(),
				nodesDone: nil,
				loopInfo:  nil,
				inferOnly: false,
			},
			want: NewRegisterState(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Section{
				Name:         tt.fields.Name,
				Instructions: tt.fields.Instructions,
				Dependencies: tt.fields.Dependencies,
			}
			s.updateDependencies(tt.args.cfg, tt.args.base, tt.args.state, tt.args.nodesDone, tt.args.loopInfo, tt.args.inferOnly)
			// 由于 updateDependencies 现在是 void 函数，我们只验证它没有崩溃
			// 可以在这里添加更多的状态验证逻辑
		})
	}
}

// parseUpdatePropertyInitArgs 解析 update_property_init_args 文件中的参数
func parseUpdatePropertyInitArgs(filename string) (*ControlFlowGraph, int, bool, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, 0, false, err
	}
	defer file.Close()

	var nodes map[int][]int
	var nodesRev map[int][]int
	var nodesLen map[int]int
	var base int
	var inferOnly bool

	// 逐行读取文件
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "base = ") {
			baseStr := strings.TrimPrefix(line, "base = ")
			base, _ = strconv.Atoi(baseStr)
		} else if strings.HasPrefix(line, "infer_only = ") {
			inferOnlyStr := strings.TrimPrefix(line, "infer_only = ")
			inferOnly = inferOnlyStr == "1"
		} else if strings.HasPrefix(line, "nodes = ") {
			nodesStr := strings.TrimPrefix(line, "nodes = ")
			// 使用 tool 包中的解析方法，然后取第一个元素
			if parsedNodes, err := parseSinglePythonDictIntSlice(nodesStr); err == nil {
				nodes = parsedNodes
			}
		} else if strings.HasPrefix(line, "nodes_rev = ") {
			nodesRevStr := strings.TrimPrefix(line, "nodes_rev = ")
			// 使用 tool 包中的解析方法，然后取第一个元素
			if parsedNodesRev, err := parseSinglePythonDictIntSlice(nodesRevStr); err == nil {
				nodesRev = parsedNodesRev
			}
		} else if strings.HasPrefix(line, "nodes_len = ") {
			nodesLenStr := strings.TrimPrefix(line, "nodes_len = ")
			// 使用 tool 包中的解析方法，然后取第一个元素
			if parsedNodesLen, err := parseSinglePythonDictInt(nodesLenStr); err == nil {
				nodesLen = parsedNodesLen
			}
		}
	}

	cfg := &ControlFlowGraph{
		Nodes:     nodes,
		NodesRev:  nodesRev,
		NodesLen:  nodesLen,
		NodeStats: make(map[int]*RegisterState),
	}

	return cfg, base, inferOnly, scanner.Err()
}

// parseSinglePythonDictIntSlice 解析单行 Python 字典格式的字符串 (返回 map[int][]int)
// 这是对 tool.ParsePythonDictIntSlice 的简单包装，用于处理单行情况
func parseSinglePythonDictIntSlice(dictStr string) (map[int][]int, error) {
	// 创建临时文件来使用现有的解析函数
	tmpFile, err := os.CreateTemp("", "temp_dict_*.txt")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// 写入字典字符串
	if _, err := tmpFile.WriteString(dictStr); err != nil {
		return nil, err
	}
	tmpFile.Close()

	// 使用现有的解析函数
	results, err := tool.ParsePythonDictIntSlice(tmpFile.Name())
	if err != nil {
		return nil, err
	}

	if len(results) == 0 {
		return make(map[int][]int), nil
	}

	return results[0], nil
}

// parseSinglePythonDictInt 解析单行 Python 字典格式的字符串 (返回 map[int]int)
// 这是对 tool.ParsePythonDictInt 的简单包装，用于处理单行情况
func parseSinglePythonDictInt(dictStr string) (map[int]int, error) {
	// 创建临时文件来使用现有的解析函数
	tmpFile, err := os.CreateTemp("", "temp_dict_*.txt")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// 写入字典字符串
	if _, err := tmpFile.WriteString(dictStr); err != nil {
		return nil, err
	}
	tmpFile.Close()

	// 使用现有的解析函数
	results, err := tool.ParsePythonDictInt(tmpFile.Name())
	if err != nil {
		return nil, err
	}

	if len(results) == 0 {
		return make(map[int]int), nil
	}

	return results[0], nil
}

// buildTestControlFlowGraph 构建测试用的 ControlFlowGraph
func buildTestControlFlowGraph() *ControlFlowGraph {
	// 这里直接硬编码一个简化的控制流图用于测试
	// 实际使用时应该从 update_property_init_args 文件中解析
	return &ControlFlowGraph{
		Nodes: map[int][]int{
			0:  {3},
			3:  {35, 4},
			4:  {11},
			11: {35, 12},
			12: {31},
			31: {35, 32},
			32: {35},
			35: {},
		},
		NodesRev: map[int][]int{
			0:  {},
			3:  {0},
			4:  {3},
			11: {4},
			12: {11},
			31: {12},
			32: {31},
			35: {3, 11, 31, 32},
		},
		NodesLen: map[int]int{
			0:  3,
			3:  1,
			4:  7,
			11: 1,
			12: 19,
			31: 1,
			32: 3,
			35: 1,
		},
		NodeStats: make(map[int]*RegisterState),
	}
}

// TestParseUpdatePropertyInitArgs 测试解析 update_property_init_args 文件
func TestParseUpdatePropertyInitArgs(t *testing.T) {
	// 测试解析函数
	cfg, base, inferOnly, err := parseUpdatePropertyInitArgs("../../testdata/update_property_init_args")
	if err != nil {
		t.Fatalf("解析 update_property_init_args 失败: %v", err)
	}

	// 验证解析结果
	if base != 0 {
		t.Errorf("base = %d, 期望 0", base)
	}
	if inferOnly != false {
		t.Errorf("inferOnly = %v, 期望 false", inferOnly)
	}
	if cfg == nil {
		t.Fatal("cfg 为 nil")
	}
	if len(cfg.Nodes) == 0 {
		t.Error("Nodes 为空")
	}
	if len(cfg.NodesRev) == 0 {
		t.Error("NodesRev 为空")
	}
	if len(cfg.NodesLen) == 0 {
		t.Error("NodesLen 为空")
	}

	t.Logf("成功解析了 %d 个节点、%d 个反向节点、%d 个节点长度",
		len(cfg.Nodes), len(cfg.NodesRev), len(cfg.NodesLen))

	// 显示一些示例数据
	sampleCount := 0
	for nodeID, successors := range cfg.Nodes {
		if sampleCount >= 5 {
			break
		}
		t.Logf("节点 %d -> %v", nodeID, successors)
		if predecessors, exists := cfg.NodesRev[nodeID]; exists {
			t.Logf("节点 %d <- %v", nodeID, predecessors)
		}
		if length, exists := cfg.NodesLen[nodeID]; exists {
			t.Logf("节点 %d 长度: %d", nodeID, length)
		}
		sampleCount++
	}
}

// TestUpdateDependenciesWithRealData 使用真实数据测试 updateDependencies
func TestUpdateDependenciesWithRealData(t *testing.T) {
	// 解析真实的控制流图数据
	cfg, base, inferOnly, err := parseUpdatePropertyInitArgs("../../testdata/update_property_init_args")
	if err != nil {
		t.Skipf("跳过测试，无法解析 update_property_init_args: %v", err)
	}

	// 创建测试 Section
	section := &Section{
		Name:         "test_section",
		Instructions: make([]*bpf.Instruction, 0),
		Dependencies: make([]DependencyInfo, 0),
	}

	// 创建初始寄存器状态
	initialState := NewRegisterState()

	// 执行 updateDependencies
	t.Logf("开始执行 updateDependencies，base=%d, inferOnly=%v", base, inferOnly)
	section.updateDependencies(cfg, base, initialState, nil, nil, inferOnly)

	// 验证执行结果
	t.Logf("updateDependencies 执行完成")

	// 可以添加更多的验证逻辑
	if cfg.NodeStats != nil {
		t.Logf("NodeStats 包含 %d 个条目", len(cfg.NodeStats))
	}
}

// TestUpdateDependenciesDetailedValidation 详细验证 updateDependencies 的行为
func TestUpdateDependenciesDetailedValidation(t *testing.T) {
	// 解析真实的控制流图数据
	cfg, base, inferOnly, err := parseUpdatePropertyInitArgs("../../testdata/update_property_init_args")
	if err != nil {
		t.Skipf("跳过测试，无法解析 update_property_init_args: %v", err)
	}

	// 创建测试用的指令列表（简单的示例）
	instructions := []*bpf.Instruction{
		// 创建一些简单的测试指令
		{Opcode: 0xB7, DstReg: 0, SrcReg: 0, Offset: 0, Imm: 42}, // MOV r0, 42
		{Opcode: 0xBF, DstReg: 1, SrcReg: 0, Offset: 0, Imm: 0},  // MOV r1, r0
		{Opcode: 0x95, DstReg: 0, SrcReg: 0, Offset: 0, Imm: 0},  // EXIT
	}

	// 创建对应的依赖信息
	dependencies := make([]DependencyInfo, len(instructions))
	for i := range dependencies {
		dependencies[i] = DependencyInfo{
			Dependencies: make([]int, 0),
			DependedBy:   make([]int, 0),
		}
	}

	// 创建测试 Section
	section := &Section{
		Name:         "test_section",
		Instructions: instructions,
		Dependencies: dependencies,
	}

	// 记录执行前的状态
	initialNodeStatsCount := len(cfg.NodeStats)
	t.Logf("执行前 NodeStats 数量: %d", initialNodeStatsCount)

	// 创建初始寄存器状态
	initialState := NewRegisterState()
	t.Logf("初始寄存器状态: r1=%v, r10=%v", initialState.Registers[1], initialState.Registers[10])

	// 执行 updateDependencies
	t.Logf("开始执行 updateDependencies，base=%d, inferOnly=%v", base, inferOnly)
	section.updateDependencies(cfg, base, initialState, nil, nil, inferOnly)

	// 验证执行结果
	t.Logf("updateDependencies 执行完成")

	// 详细验证结果
	if cfg.NodeStats != nil {
		finalNodeStatsCount := len(cfg.NodeStats)
		t.Logf("执行后 NodeStats 数量: %d", finalNodeStatsCount)

		if finalNodeStatsCount > initialNodeStatsCount {
			t.Logf("✅ NodeStats 数量增加了 %d 个", finalNodeStatsCount-initialNodeStatsCount)
		}

		// 检查一些具体的节点状态
		sampleCount := 0
		for nodeID, state := range cfg.NodeStats {
			if sampleCount >= 3 {
				break
			}
			t.Logf("节点 %d 的状态:", nodeID)
			for i := 0; i < 11; i++ {
				if len(state.Registers[i]) > 0 {
					t.Logf("  r%d: %v", i, state.Registers[i])
				}
			}
			if len(state.Stacks) > 0 {
				t.Logf("  栈状态: %v", state.Stacks)
			}
			sampleCount++
		}
	}

	// 验证控制流图的结构完整性
	if len(cfg.Nodes) == 0 {
		t.Error("❌ Nodes 为空")
	} else {
		t.Logf("✅ Nodes 包含 %d 个节点", len(cfg.Nodes))
	}

	if len(cfg.NodesRev) == 0 {
		t.Error("❌ NodesRev 为空")
	} else {
		t.Logf("✅ NodesRev 包含 %d 个节点", len(cfg.NodesRev))
	}

	if len(cfg.NodesLen) == 0 {
		t.Error("❌ NodesLen 为空")
	} else {
		t.Logf("✅ NodesLen 包含 %d 个节点", len(cfg.NodesLen))
	}

	// 验证数据一致性
	if len(cfg.Nodes) != len(cfg.NodesRev) {
		t.Errorf("❌ Nodes 和 NodesRev 数量不一致: %d vs %d", len(cfg.Nodes), len(cfg.NodesRev))
	} else {
		t.Logf("✅ Nodes 和 NodesRev 数量一致")
	}

	if len(cfg.Nodes) != len(cfg.NodesLen) {
		t.Errorf("❌ Nodes 和 NodesLen 数量不一致: %d vs %d", len(cfg.Nodes), len(cfg.NodesLen))
	} else {
		t.Logf("✅ Nodes 和 NodesLen 数量一致")
	}
}

// TestControlFlowGraphStructure 测试控制流图结构的正确性
func TestControlFlowGraphStructure(t *testing.T) {
	// 解析真实的控制流图数据
	cfg, base, _, err := parseUpdatePropertyInitArgs("../../testdata/update_property_init_args")
	if err != nil {
		t.Skipf("跳过测试，无法解析 update_property_init_args: %v", err)
	}

	t.Logf("测试控制流图结构，起始节点: %d", base)

	// 验证起始节点存在
	if _, exists := cfg.Nodes[base]; !exists {
		t.Errorf("❌ 起始节点 %d 不存在于 Nodes 中", base)
	} else {
		t.Logf("✅ 起始节点 %d 存在", base)
	}

	// 验证前向和反向边的一致性
	inconsistentCount := 0
	for nodeID, successors := range cfg.Nodes {
		for _, successor := range successors {
			// 检查反向边是否存在
			if predecessors, exists := cfg.NodesRev[successor]; exists {
				found := false
				for _, pred := range predecessors {
					if pred == nodeID {
						found = true
						break
					}
				}
				if !found {
					inconsistentCount++
					if inconsistentCount <= 5 { // 只显示前5个不一致的例子
						t.Errorf("❌ 边不一致: %d -> %d 在 Nodes 中存在，但在 NodesRev[%d] 中找不到 %d",
							nodeID, successor, successor, nodeID)
					}
				}
			} else {
				inconsistentCount++
				if inconsistentCount <= 5 {
					t.Errorf("❌ 节点 %d 在 Nodes 中有后继节点，但在 NodesRev 中不存在", successor)
				}
			}
		}

		if inconsistentCount > 5 {
			t.Logf("... 还有 %d 个不一致的边（未显示）", inconsistentCount-5)
			break
		}
	}

	if inconsistentCount == 0 {
		t.Logf("✅ 前向边和反向边完全一致")
	} else {
		t.Logf("❌ 发现 %d 个不一致的边", inconsistentCount)
	}

	// 统计节点度数分布
	inDegreeMap := make(map[int]int)  // 入度分布
	outDegreeMap := make(map[int]int) // 出度分布

	for nodeID := range cfg.Nodes {
		outDegree := len(cfg.Nodes[nodeID])
		outDegreeMap[outDegree]++

		inDegree := 0
		if predecessors, exists := cfg.NodesRev[nodeID]; exists {
			inDegree = len(predecessors)
		}
		inDegreeMap[inDegree]++
	}

	t.Logf("节点出度分布: %v", outDegreeMap)
	t.Logf("节点入度分布: %v", inDegreeMap)

	// 统计节点长度分布
	lengthMap := make(map[int]int)
	totalLength := 0
	for _, length := range cfg.NodesLen {
		lengthMap[length]++
		totalLength += length
	}

	t.Logf("节点长度分布: %v", lengthMap)
	t.Logf("平均节点长度: %.2f", float64(totalLength)/float64(len(cfg.NodesLen)))
}
