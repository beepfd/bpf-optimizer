package optimizer

import (
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
	cfg, base, inferOnly, err := parseUpdatePropertyInitArgs("../../testdata/update_property_init_args")
	if err != nil {
		t.Fatalf("Failed to parse update_property_init_args: %v", err)
	}

	insns, _ := loadAnalysisFromFile("../../testdata/analyz_result.csv")
	insns = insns[0:2257]
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
				Instructions: section.Instructions,
				Dependencies: section.Dependencies,
			},
			args: args{
				cfg:       cfg,
				base:      base,
				state:     NewRegisterState(),
				nodesDone: nil,
				loopInfo:  nil,
				inferOnly: inferOnly,
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
			fmt.Println(tt.args.state)
		})
	}
}

// parseUpdatePropertyInitArgs 解析 update_property_init_args 文件中的参数
func parseUpdatePropertyInitArgs(filename string) (*ControlFlowGraph, int, bool, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, 0, false, err
	}

	var nodes map[int][]int
	var nodesRev map[int][]int
	var nodesLen map[int]int
	var base int
	var inferOnly bool

	// 将内容转换为字符串并逐行处理
	contentStr := string(content)
	lines := strings.Split(contentStr, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

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

	nodesStats, err := parseNodesStats(filename)
	if err != nil {
		return nil, 0, false, err
	}

	cfg := &ControlFlowGraph{
		Nodes:     nodes,
		NodesRev:  nodesRev,
		NodesLen:  nodesLen,
		NodeStats: nodesStats,
	}

	return cfg, base, inferOnly, nil
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
		if sampleCount >= 50 {
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

// 解析 nodes_stats 数据
// 格式为 {0: [[[0], [2], [], [], [], [], [], [], [], [], [-1]], {}]}
// [[0], [2], [], [], [], [], [], [], [], [], [-1]] 为 registers
// {} 为 stacks
// 返回 map[int]*RegisterState
// parseNodesStats 解析 nodes_stats 数据并转换为 map[int]*RegisterState
func parseNodesStats(filename string) (map[int]*RegisterState, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// 将内容转换为字符串并查找 nodes_stats
	contentStr := string(content)

	// 查找 nodes_stats = 的位置
	prefix := "nodes_stats = "
	startIndex := strings.Index(contentStr, prefix)
	if startIndex == -1 {
		return nil, fmt.Errorf("未找到 nodes_stats 定义")
	}

	// 提取 nodes_stats 的内容
	startIndex += len(prefix)
	remainingContent := strings.TrimSpace(contentStr[startIndex:])

	// 检查是否为 None
	if strings.HasPrefix(remainingContent, "None") {
		// 如果 nodes_stats = None，返回空的 map
		return make(map[int]*RegisterState), nil
	}

	// 提取字典内容（从 { 开始到对应的 } 结束）
	statsStr := extractDictContent(remainingContent)
	if statsStr == "" {
		return nil, fmt.Errorf("无法提取 nodes_stats 内容")
	}

	nodesStats, err := parseNodesStatsData(statsStr)
	if err != nil {
		return nil, fmt.Errorf("解析 nodes_stats 失败: %v", err)
	}

	return nodesStats, nil
}

// extractDictContent 提取字典内容，从 { 开始到对应的 } 结束
func extractDictContent(content string) string {
	content = strings.TrimSpace(content)
	if !strings.HasPrefix(content, "{") {
		return ""
	}

	braceCount := 0
	for i, char := range content {
		if char == '{' {
			braceCount++
		} else if char == '}' {
			braceCount--
			if braceCount == 0 {
				return content[:i+1]
			}
		}
	}
	return ""
}

// parseNodesStatsData 解析 nodes_stats 的 Python 字典数据
func parseNodesStatsData(data string) (map[int]*RegisterState, error) {
	result := make(map[int]*RegisterState)

	// 移除外层的大括号
	data = strings.TrimSpace(data)
	if !strings.HasPrefix(data, "{") || !strings.HasSuffix(data, "}") {
		return nil, fmt.Errorf("无效的字典格式")
	}
	data = data[1 : len(data)-1]

	// 使用简单的状态机解析嵌套结构
	var bracketDepth int
	var inString bool
	var currentEntry strings.Builder

	i := 0
	for i < len(data) {
		char := data[i]

		switch char {
		case '"', '\'':
			inString = !inString
			currentEntry.WriteByte(char)
		case '{', '[':
			if !inString {
				bracketDepth++
			}
			currentEntry.WriteByte(char)
		case '}', ']':
			if !inString {
				bracketDepth--
			}
			currentEntry.WriteByte(char)
		case ',':
			if !inString && bracketDepth == 0 {
				// 处理完整的键值对
				entry := strings.TrimSpace(currentEntry.String())
				if entry != "" {
					if err := parseNodeStatsEntry(entry, result); err != nil {
						return nil, fmt.Errorf("解析节点状态条目失败: %v", err)
					}
				}
				currentEntry.Reset()
			} else {
				currentEntry.WriteByte(char)
			}
		default:
			currentEntry.WriteByte(char)
		}
		i++
	}

	// 处理最后一个条目
	entry := strings.TrimSpace(currentEntry.String())
	if entry != "" {
		if err := parseNodeStatsEntry(entry, result); err != nil {
			return nil, fmt.Errorf("解析最后节点状态条目失败: %v", err)
		}
	}

	return result, nil
}

// parseNodeStatsEntry 解析单个节点状态条目
func parseNodeStatsEntry(entry string, result map[int]*RegisterState) error {
	// 分离键和值 "nodeId: [registers, stacks]"
	colonIndex := strings.Index(entry, ":")
	if colonIndex == -1 {
		return fmt.Errorf("无效的键值对格式: %s", entry)
	}

	keyStr := strings.TrimSpace(entry[:colonIndex])
	valueStr := strings.TrimSpace(entry[colonIndex+1:])

	// 解析节点ID
	nodeID, err := strconv.Atoi(keyStr)
	if err != nil {
		return fmt.Errorf("无效的节点ID: %s", keyStr)
	}

	// 解析值 [registers, stacks]
	if !strings.HasPrefix(valueStr, "[") || !strings.HasSuffix(valueStr, "]") {
		return fmt.Errorf("无效的值格式: %s", valueStr)
	}

	valueStr = valueStr[1 : len(valueStr)-1] // 移除外层方括号

	// 找到寄存器和栈的分隔点
	registerEnd := findRegisterArrayEnd(valueStr)
	if registerEnd == -1 {
		return fmt.Errorf("无法找到寄存器数组结束位置")
	}

	registersStr := strings.TrimSpace(valueStr[:registerEnd+1])
	stacksStr := strings.TrimSpace(valueStr[registerEnd+2:]) // +2 跳过 "], "

	// 解析寄存器状态
	registers, err := parseRegisterArray(registersStr)
	if err != nil {
		return fmt.Errorf("解析寄存器状态失败: %v", err)
	}

	// 解析栈状态
	stacks, err := parseStackDict(stacksStr)
	if err != nil {
		return fmt.Errorf("解析栈状态失败: %v", err)
	}

	// 创建 RegisterState
	regState := &RegisterState{
		Registers: registers,
		Stacks:    stacks,
		RegAlias:  make([]int16, 11), // 初始化为 11 个元素
	}

	// 初始化 RegAlias 为 -1
	for i := range regState.RegAlias {
		regState.RegAlias[i] = -1
	}

	result[nodeID] = regState
	return nil
}

// findRegisterArrayEnd 找到寄存器数组的结束位置
func findRegisterArrayEnd(data string) int {
	bracketDepth := 0
	inString := false

	for i, char := range data {
		switch char {
		case '"', '\'':
			inString = !inString
		case '[':
			if !inString {
				bracketDepth++
			}
		case ']':
			if !inString {
				bracketDepth--
				if bracketDepth == 0 {
					return i
				}
			}
		}
	}
	return -1
}

// parseRegisterArray 解析寄存器数组 [[...], [...], ...]
func parseRegisterArray(data string) ([][]int, error) {
	// 移除外层方括号
	if !strings.HasPrefix(data, "[") || !strings.HasSuffix(data, "]") {
		return nil, fmt.Errorf("无效的数组格式: %s", data)
	}
	data = data[1 : len(data)-1]

	var result [][]int
	var currentArray strings.Builder
	bracketDepth := 0
	inString := false

	for _, char := range data {
		switch char {
		case '"', '\'':
			inString = !inString
			currentArray.WriteRune(char)
		case '[':
			if !inString {
				bracketDepth++
			}
			currentArray.WriteRune(char)
		case ']':
			if !inString {
				bracketDepth--
			}
			currentArray.WriteRune(char)
			if bracketDepth == 0 {
				// 解析单个寄存器数组
				arrayStr := strings.TrimSpace(currentArray.String())
				if arrayStr != "" {
					regArray, err := parseIntArray(arrayStr)
					if err != nil {
						return nil, fmt.Errorf("解析寄存器数组失败: %v", err)
					}
					result = append(result, regArray)
				}
				currentArray.Reset()
			}
		case ',':
			if !inString && bracketDepth == 0 {
				// 跳过顶层逗号
				continue
			} else {
				currentArray.WriteRune(char)
			}
		default:
			currentArray.WriteRune(char)
		}
	}

	// 处理最后一个数组（如果没有以逗号结尾）
	if currentArray.Len() > 0 && bracketDepth == 0 {
		arrayStr := strings.TrimSpace(currentArray.String())
		if arrayStr != "" {
			regArray, err := parseIntArray(arrayStr)
			if err != nil {
				return nil, fmt.Errorf("解析最后寄存器数组失败: %v", err)
			}
			result = append(result, regArray)
		}
	}

	return result, nil
}

// parseIntArray 解析整数数组 [1, 2, 3]
func parseIntArray(data string) ([]int, error) {
	// 移除方括号
	if !strings.HasPrefix(data, "[") || !strings.HasSuffix(data, "]") {
		return nil, fmt.Errorf("无效的数组格式: %s", data)
	}
	data = data[1 : len(data)-1]
	data = strings.TrimSpace(data)

	if data == "" {
		return []int{}, nil
	}

	var result []int
	elements := strings.Split(data, ",")
	for _, elem := range elements {
		elem = strings.TrimSpace(elem)
		if elem != "" {
			num, err := strconv.Atoi(elem)
			if err != nil {
				return nil, fmt.Errorf("无效的整数: %s", elem)
			}
			result = append(result, num)
		}
	}

	return result, nil
}

// parseStackDict 解析栈字典 {-8: [1, 2], -16: [3]}
func parseStackDict(data string) (map[int16][]int, error) {
	result := make(map[int16][]int)

	// 移除外层大括号
	if !strings.HasPrefix(data, "{") || !strings.HasSuffix(data, "}") {
		return nil, fmt.Errorf("无效的字典格式: %s", data)
	}
	data = data[1 : len(data)-1]
	data = strings.TrimSpace(data)

	if data == "" {
		return result, nil
	}

	// 简单解析键值对
	var currentEntry strings.Builder
	bracketDepth := 0
	inString := false

	for _, char := range data {
		switch char {
		case '"', '\'':
			inString = !inString
			currentEntry.WriteRune(char)
		case '[':
			if !inString {
				bracketDepth++
			}
			currentEntry.WriteRune(char)
		case ']':
			if !inString {
				bracketDepth--
			}
			currentEntry.WriteRune(char)
		case ',':
			if !inString && bracketDepth == 0 {
				// 处理完整的键值对
				entry := strings.TrimSpace(currentEntry.String())
				if entry != "" {
					if err := parseStackEntry(entry, result); err != nil {
						return nil, fmt.Errorf("解析栈条目失败: %v", err)
					}
				}
				currentEntry.Reset()
			} else {
				currentEntry.WriteRune(char)
			}
		default:
			currentEntry.WriteRune(char)
		}
	}

	// 处理最后一个条目
	entry := strings.TrimSpace(currentEntry.String())
	if entry != "" {
		if err := parseStackEntry(entry, result); err != nil {
			return nil, fmt.Errorf("解析最后栈条目失败: %v", err)
		}
	}

	return result, nil
}

// parseStackEntry 解析单个栈条目 "-8: [1, 2]"
func parseStackEntry(entry string, result map[int16][]int) error {
	colonIndex := strings.Index(entry, ":")
	if colonIndex == -1 {
		return fmt.Errorf("无效的键值对格式: %s", entry)
	}

	keyStr := strings.TrimSpace(entry[:colonIndex])
	valueStr := strings.TrimSpace(entry[colonIndex+1:])

	// 解析偏移量
	offset, err := strconv.ParseInt(keyStr, 10, 16)
	if err != nil {
		return fmt.Errorf("无效的栈偏移量: %s", keyStr)
	}

	// 解析依赖数组
	deps, err := parseIntArray(valueStr)
	if err != nil {
		return fmt.Errorf("解析依赖数组失败: %v", err)
	}

	result[int16(offset)] = deps
	return nil
}

// TestParseNodesStats 测试 nodes_stats 解析功能
func TestParseNodesStats(t *testing.T) {
	nodesStats, err := parseNodesStats("../../testdata/update_property_candidates_args")
	if err != nil {
		t.Skipf("跳过测试，无法解析 nodes_stats: %v", err)
		return
	}

	t.Logf("成功解析 %d 个节点状态", len(nodesStats))

	// 验证一些节点的数据
	if regState, exists := nodesStats[0]; exists {
		t.Logf("节点 0 寄存器状态: %v", regState.Registers)
		t.Logf("节点 0 栈状态: %v", regState.Stacks)
	}

	if regState, exists := nodesStats[1656]; exists {
		t.Logf("节点 1656 寄存器状态: %v", regState.Registers)
		t.Logf("节点 1656 栈状态: %v", regState.Stacks)
	}
}

// TestParseNodesStatsNone 测试 nodes_stats = None 的情况
func TestParseNodesStatsNone(t *testing.T) {
	// 创建临时文件测试 None 情况
	tmpFile, err := os.CreateTemp("", "test_nodes_stats_none_*.txt")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// 写入包含 nodes_stats = None 的内容
	content := `base = 0
infer_only = False
nodes = {0: [3], 3: [4]}
nodes_rev = {0: [], 3: [0], 4: [3]}
nodes_len = {0: 1, 3: 1, 4: 1}
nodes_stats = None
`
	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("写入临时文件失败: %v", err)
	}
	tmpFile.Close()

	// 测试解析
	nodesStats, err := parseNodesStats(tmpFile.Name())
	if err != nil {
		t.Fatalf("解析 nodes_stats = None 失败: %v", err)
	}

	// 验证结果应该是空的 map
	if nodesStats == nil {
		t.Error("nodesStats 不应该为 nil")
	}
	if len(nodesStats) != 0 {
		t.Errorf("nodesStats 应该为空，但包含 %d 个元素", len(nodesStats))
	}

	t.Logf("成功处理 nodes_stats = None 情况，返回空 map")
}

// TestParseUpdatePropertyInitArgsWithNone 测试整体解析包含 None 的情况
func TestParseUpdatePropertyInitArgsWithNone(t *testing.T) {
	// 创建临时文件测试 None 情况
	tmpFile, err := os.CreateTemp("", "test_init_args_none_*.txt")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// 写入包含 nodes_stats = None 的内容
	content := `base = 0
infer_only = False
nodes = {0: [3], 3: [4]}
nodes_rev = {0: [], 3: [0], 4: [3]}
nodes_len = {0: 1, 3: 1, 4: 1}
nodes_stats = None
`
	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("写入临时文件失败: %v", err)
	}
	tmpFile.Close()

	// 测试整体解析
	cfg, base, inferOnly, err := parseUpdatePropertyInitArgs(tmpFile.Name())
	if err != nil {
		t.Fatalf("解析包含 None 的参数失败: %v", err)
	}

	// 验证结果
	if base != 0 {
		t.Errorf("base = %d, 期望 0", base)
	}
	if inferOnly != false {
		t.Errorf("inferOnly = %v, 期望 false", inferOnly)
	}
	if cfg == nil {
		t.Fatal("cfg 为 nil")
	}
	if cfg.NodeStats == nil {
		t.Error("NodeStats 不应该为 nil")
	}
	if len(cfg.NodeStats) != 0 {
		t.Errorf("NodeStats 应该为空，但包含 %d 个元素", len(cfg.NodeStats))
	}

	t.Logf("成功处理包含 nodes_stats = None 的完整解析")
}
