package optimizer

import (
	"sort"

	"github.com/beepfd/bpf-optimizer/pkg/bpf"
)

// RegisterState tracks register states for dependency analysis
type RegisterState struct {
	Registers [][]int         // 11 registers (r0-r10), each holding instruction indices that last modified it
	Stacks    map[int16][]int // stack memory mapping: offset -> instruction indices
	RegAlias  []int16         // alias tracking for registers (r0-r10)
}

// InstructionAnalysis represents the analysis result of a single instruction
type InstructionAnalysis struct {
	UpdatedReg   int     // register that gets updated (-1 if none)
	UpdatedStack []int16 // stack update [offset, size]
	UsedReg      []int   // registers that are used
	UsedStack    []int16 // stack usage [offset, size]
	Offset       int16   // jump offset (for control flow)
	IsCall       bool    // is this a function call
	IsExit       bool    // is this an exit instruction
}

// ControlFlowGraph represents the program's control flow structure
type ControlFlowGraph struct {
	Nodes     map[int][]int          // node -> successor nodes
	NodesRev  map[int][]int          // node -> predecessor nodes
	NodesLen  map[int]int            // node -> length of basic block
	NodeStats map[int]*RegisterState // node -> register/stack state
}

// NewRegisterState creates a new register state
func NewRegisterState() *RegisterState {
	rs := &RegisterState{
		Registers: make([][]int, 11), // r0-r10
		Stacks:    make(map[int16][]int),
		RegAlias:  make([]int16, 11),
	}

	// Initialize register arrays
	for i := range rs.Registers {
		rs.Registers[i] = make([]int, 0)
	}

	// r1 and r10 are initialized with -1 (entry state)
	rs.Registers[1] = []int{-1}
	rs.Registers[10] = []int{-1}

	// Initialize alias tracking
	for i := range rs.RegAlias {
		rs.RegAlias[i] = -1 // -1 means no alias
	}

	return rs
}

// Clone creates a deep copy of register state
func (rs *RegisterState) Clone() *RegisterState {
	newRs := &RegisterState{
		Registers: make([][]int, 11),
		Stacks:    make(map[int16][]int),
		RegAlias:  make([]int16, 11),
	}

	// Copy registers
	for i, reg := range rs.Registers {
		newRs.Registers[i] = make([]int, len(reg))
		copy(newRs.Registers[i], reg)
	}

	// Copy stacks
	for offset, instList := range rs.Stacks {
		newRs.Stacks[offset] = make([]int, len(instList))
		copy(newRs.Stacks[offset], instList)
	}

	// Copy aliases
	copy(newRs.RegAlias, rs.RegAlias)

	return newRs
}

// toSigned converts unsigned value to signed
func toSigned(value uint32, bits int) int32 {
	if bits <= 0 || bits > 32 {
		bits = 32
	}
	if value&(1<<(bits-1)) != 0 {
		return int32(value) - (1 << bits)
	}
	return int32(value)
}

// analyzeInstruction analyzes a single BPF instruction
// This corresponds to Python's analyse_insn method
func analyzeInstruction(inst *bpf.Instruction) *InstructionAnalysis {
	analysis := &InstructionAnalysis{
		UpdatedReg:   -1,
		UpdatedStack: make([]int16, 0),
		UsedReg:      make([]int, 0),
		UsedStack:    make([]int16, 0),
		Offset:       0,
		IsCall:       false,
		IsExit:       false,
	}

	opcode := inst.Opcode
	src := int(inst.SrcReg)
	dst := int(inst.DstReg)
	off := inst.Offset
	imm := inst.Imm

	lsb := opcode & 0x07

	switch lsb {
	case bpf.BPF_ALU64, bpf.BPF_ALU:
		analysis.ALU(opcode, dst, src)
	case bpf.BPF_JMP32, bpf.BPF_JMP:
		analysis.JMP(opcode, dst, src, off, imm)
	case bpf.BPF_STX: // store register to memory
		analysis.STX(opcode, dst, src, off, imm)
	case bpf.BPF_ST: // store immediate to memory
		analysis.ST(opcode, dst, src, off, imm)
	case bpf.BPF_LDX: // load from memory to register
		analysis.LDX(opcode, dst, src, off, imm)
	case bpf.BPF_LD: // load immediate to register
		analysis.LD(opcode, dst, src, off, imm)
	}

	return analysis
}

// buildControlFlowGraph builds the control flow graph
// This corresponds to the first part of Python's build_dependency method
func (s *Section) buildControlFlowGraph() *ControlFlowGraph {
	cfg := &ControlFlowGraph{
		Nodes:     make(map[int][]int),
		NodesRev:  make(map[int][]int),
		NodesLen:  make(map[int]int),
		NodeStats: make(map[int]*RegisterState),
	}

	buildInstructionNode(s.Instructions, cfg)

	// Build reverse mapping
	for key, successors := range cfg.Nodes {
		if key != 0 {
			if _, exists := cfg.NodesRev[key]; !exists {
				cfg.NodesRev[key] = make([]int, 0)
			}
		}
		for _, succ := range successors {
			if _, exists := cfg.NodesRev[succ]; exists {
				cfg.NodesRev[succ] = append(cfg.NodesRev[succ], key)
			} else {
				cfg.NodesRev[succ] = []int{key}
			}
		}
	}

	// Calculate node lengths
	allNodes := make([]int, 0)
	for node := range cfg.NodesRev {
		allNodes = append(allNodes, node)
	}
	allNodes = append(allNodes, 0, len(s.Instructions))

	// Sort nodes efficiently using Go's built-in sort
	sort.Ints(allNodes)

	for i := 0; i < len(allNodes)-1; i++ {
		cfg.NodesLen[allNodes[i]] = allNodes[i+1] - allNodes[i]
	}

	// Build detailed reverse mapping by analyzing each instruction in each basic block
	// This corresponds to Python's detailed nodes_rev construction (lines 512-533)
	cfg.NodesRev = make(map[int][]int)
	for _, node := range allNodes[:len(allNodes)-1] { // exclude the last virtual node
		cfg.NodesRev[node] = make([]int, 0)
	}

	// Remove the virtual end node if it exists
	delete(cfg.NodesRev, len(s.Instructions))

	// Analyze each instruction in each basic block
	for node, nodeLen := range cfg.NodesLen {
		for i := 0; i < nodeLen; i++ {
			instIdx := node + i
			if instIdx >= len(s.Instructions) {
				break
			}

			inst := s.Instructions[instIdx]
			opcode := inst.Opcode
			off := inst.Offset
			msb := opcode & 0xF0

			// Handle jump instructions
			if (opcode&0x07) == bpf.BPF_JMP || (opcode&0x07) == bpf.BPF_JMP32 {
				if msb == bpf.JMP_CALL {
					// Function calls don't create control flow edges
				} else if msb == bpf.JMP_EXIT {
					// Exit instructions don't have successors
					continue
				} else if opcode == 0x05 { // Unconditional jump
					jumpTarget := instIdx + int(off) + 1
					if jumpTarget >= 0 && jumpTarget < len(s.Instructions) {
						// Record that 'node' jumps to 'jumpTarget'
						if _, exists := cfg.NodesRev[jumpTarget]; exists {
							cfg.NodesRev[jumpTarget] = append(cfg.NodesRev[jumpTarget], node)
						}
					}
					continue
				} else { // Conditional jump
					jumpTarget := instIdx + int(off) + 1
					fallThrough := instIdx + 1

					// Record jump target
					if jumpTarget >= 0 && jumpTarget < len(s.Instructions) {
						if _, exists := cfg.NodesRev[jumpTarget]; exists {
							cfg.NodesRev[jumpTarget] = append(cfg.NodesRev[jumpTarget], instIdx)
						}
					}
					// Record fall-through
					if fallThrough >= 0 && fallThrough < len(s.Instructions) {
						if _, exists := cfg.NodesRev[fallThrough]; exists {
							cfg.NodesRev[fallThrough] = append(cfg.NodesRev[fallThrough], instIdx)
						}
					}
					continue
				}
			}

			// Handle sequential flow at the end of basic blocks
			if i == nodeLen-1 && node+nodeLen < len(s.Instructions) {
				nextBasicBlock := node + nodeLen
				if _, exists := cfg.NodesRev[nextBasicBlock]; exists {
					cfg.NodesRev[nextBasicBlock] = append(cfg.NodesRev[nextBasicBlock], node)
				}
			}
		}
	}

	// Update forward edges based on detailed reverse mapping
	// This ensures consistency between Nodes and NodesRev
	for target, sources := range cfg.NodesRev {
		for _, source := range sources {
			if _, exists := cfg.Nodes[source]; !exists {
				cfg.Nodes[source] = make([]int, 0)
			}
			// Check if target is not already in the successor list
			found := false
			for _, succ := range cfg.Nodes[source] {
				if succ == target {
					found = true
					break
				}
			}
			if !found {
				cfg.Nodes[source] = append(cfg.Nodes[source], target)
			}
		}
	}

	return cfg
}

// updateDependencies performs the main dependency analysis
// This corresponds to Python's update_property method
func (s *Section) updateDependencies(cfg *ControlFlowGraph, base int, state *RegisterState, nodesDone map[int]bool) {
	if nodesDone == nil {
		nodesDone = make(map[int]bool)
	}

	nodeLen, exists := cfg.NodesLen[base]
	if !exists {
		return
	}

	// Process instructions in current basic block
	for i := 0; i < nodeLen; i++ {
		instIdx := base + i
		if instIdx >= len(s.Instructions) {
			break
		}

		inst := s.Instructions[instIdx]
		if inst.Opcode == 0 { // skip NOPs
			continue
		}

		analysis := analyzeInstruction(inst)

		// Handle register alias updates
		if inst.Opcode != 0xBF && inst.Opcode != 0x07 {
			state.RegAlias[inst.DstReg] = -1
		}

		// Process used registers
		for _, regIdx := range analysis.UsedReg {
			if regIdx < 0 || regIdx >= 11 {
				continue
			}

			// Handle stack alias
			// 如果使用了 R10 寄存器，则 R10 的别名是 R0，表示它现在指向栈顶
			if regIdx == 10 {
				state.RegAlias[inst.DstReg] = 0
				// 如果当前寄存器已知别名，且指令为 ALU64 或 ALU，则更新栈偏移计算
			} else if state.RegAlias[inst.DstReg] != -1 && inst.Opcode == bpf.BPF_ALU64 {
				state.RegAlias[inst.DstReg] += int16(inst.Imm)
				// 0x85 = BPF_JMP + JMP_CALL = 0x05 + 0x80 = 0x85 是函数调用指令。
			} else if inst.Opcode != 0x85 {
				state.RegAlias[inst.DstReg] = -1
			}

			// Add dependencies based on register usage
			if len(state.Registers[regIdx]) == 0 {
				continue
			}

			for _, depInstIdx := range state.Registers[regIdx] {
				if state.RegAlias[regIdx] != -1 && state.RegAlias[regIdx] != 0 {
					// 情况1: 如果当前寄存器有别名，则将别名指向的栈偏移值添加到依赖关系中
					if stackInsts, exists := state.Stacks[state.RegAlias[regIdx]]; exists {
						for _, stackInstIdx := range stackInsts {
							s.Dependencies[instIdx].Dependencies = append(s.Dependencies[instIdx].Dependencies, stackInstIdx)
							s.Dependencies[stackInstIdx].DependedBy = append(s.Dependencies[stackInstIdx].DependedBy, instIdx)
						}
					} else {
						// 情况2: 如果当前寄存器没有别名，则将别名指向的栈偏移值设置为 -1
						state.Stacks[state.RegAlias[regIdx]] = []int{-1}
						s.Dependencies[instIdx].Dependencies = append(s.Dependencies[instIdx].Dependencies, -1)
					}
				}

				s.Dependencies[instIdx].Dependencies = append(s.Dependencies[instIdx].Dependencies, depInstIdx)
				s.Dependencies[depInstIdx].DependedBy = append(s.Dependencies[depInstIdx].DependedBy, instIdx)
			}
		}

		// Update register state
		// 如果当前指令更新了寄存器，则将当前指令索引添加到寄存器状态中
		if analysis.UpdatedReg >= 0 {
			state.Registers[analysis.UpdatedReg] = []int{instIdx}
		}

		// Handle function calls
		// 根据BPF ABI规范：
		// R0: 函数返回值
		// R1-R5: 函数参数传递
		// R6-R9: 被调用者保存寄存器（callee-saved）
		// R10: 只读栈指针
		// R1-R5是scratch registers（临时寄存器）
		// 函数调用之后，这些寄存器的值被认为是不可预测的，R1-R5 寄存器会被清空
		if analysis.IsCall {
			for j := 1; j <= 5; j++ { // r1-r5 are caller-saved
				state.Registers[j] = make([]int, 0)
			}
		}

		// Handle stack updates
		// 如果当前指令更新了栈，则将当前指令索引添加到栈状态中
		if len(analysis.UpdatedStack) >= 2 {
			offset := analysis.UpdatedStack[0]
			state.Stacks[offset] = []int{instIdx}
		}

		// Handle stack usage
		if len(analysis.UsedStack) >= 2 {
			offset := analysis.UsedStack[0]
			if offset == 0 { // tail call
				for _, stackInsts := range state.Stacks {
					for _, stackInstIdx := range stackInsts {
						if stackInstIdx == -1 {
							// Special case for initial state, skip
							continue
						}
						if stackInstIdx >= 0 && stackInstIdx < len(s.Dependencies) {
							s.Dependencies[instIdx].Dependencies = append(s.Dependencies[instIdx].Dependencies, stackInstIdx)
							s.Dependencies[stackInstIdx].DependedBy = append(s.Dependencies[stackInstIdx].DependedBy, instIdx)
						}
					}
				}
			} else if stackInsts, exists := state.Stacks[offset]; exists {
				for _, stackInstIdx := range stackInsts {
					if stackInstIdx == -1 {
						// Special case for initial state, skip
						continue
					}
					if stackInstIdx >= 0 && stackInstIdx < len(s.Dependencies) {
						s.Dependencies[instIdx].Dependencies = append(s.Dependencies[instIdx].Dependencies, stackInstIdx)
						s.Dependencies[stackInstIdx].DependedBy = append(s.Dependencies[stackInstIdx].DependedBy, instIdx)
					}
				}
			} else {
				state.Stacks[offset] = []int{-1}
				s.Dependencies[instIdx].Dependencies = append(s.Dependencies[instIdx].Dependencies, -1)
			}
		}

		// Handle exit instructions
		if analysis.IsExit {
			nodesDone[base] = true
			if len(nodesDone) >= len(cfg.NodesRev) {
				return
			}
		}
	}

	// Store state for this node
	cfg.NodeStats[base] = state.Clone()
	nodesDone[base] = true

	// Process successor nodes
	for node := range cfg.NodesRev {
		if nodesDone[node] {
			continue
		}

		// Check if all predecessors are done
		allPredsDone := true
		for _, pred := range cfg.NodesRev[node] {
			if !nodesDone[pred] {
				allPredsDone = false
				break
			}
		}

		if allPredsDone {
			// Merge states from all predecessors
			newState := NewRegisterState()
			for _, pred := range cfg.NodesRev[node] {
				if predState, exists := cfg.NodeStats[pred]; exists {
					// Merge register states
					for i := 0; i < 11; i++ {
						newState.Registers[i] = append(newState.Registers[i], predState.Registers[i]...)
					}
					// Merge stack states
					for offset, stackInsts := range predState.Stacks {
						if existing, exists := newState.Stacks[offset]; exists {
							newState.Stacks[offset] = append(existing, stackInsts...)
						} else {
							newState.Stacks[offset] = make([]int, len(stackInsts))
							copy(newState.Stacks[offset], stackInsts)
						}
					}
				}
			}

			// Remove duplicates
			for i := 0; i < 11; i++ {
				newState.Registers[i] = removeDuplicates(newState.Registers[i])
			}
			for offset := range newState.Stacks {
				newState.Stacks[offset] = removeDuplicates(newState.Stacks[offset])
			}

			// Recursively process this node
			s.updateDependencies(cfg, node, newState, nodesDone)
			break
		}
	}
}

// removeDuplicates removes duplicate integers from a slice
func removeDuplicates(slice []int) []int {
	keys := make(map[int]bool)
	result := make([]int, 0)

	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}

	return result
}
