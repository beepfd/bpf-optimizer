package optimizer

import (
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
func (s *Section) analyzeInstruction(inst *bpf.Instruction) *InstructionAnalysis {
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
		msb := opcode & 0xF0
		if msb == bpf.ALU_END { // byte exchange
			analysis.UpdatedReg = dst
			analysis.UsedReg = []int{dst}
		} else if msb == bpf.ALU_MOV { // move
			analysis.UpdatedReg = dst
			if opcode&bpf.BPF_X == bpf.BPF_X {
				analysis.UsedReg = []int{src}
			}
		} else { // regular arithmetic
			analysis.UpdatedReg = dst
			if opcode&bpf.BPF_X == bpf.BPF_X { // use register
				analysis.UsedReg = []int{dst, src}
			} else { // use immediate
				analysis.UsedReg = []int{dst}
			}
		}

	case bpf.BPF_JMP32, bpf.BPF_JMP:
		msb := opcode & 0xF0
		if msb == bpf.JMP_CALL {
			analysis.IsCall = true
			analysis.UpdatedReg = 0

			// Handle different BPF helper functions
			switch imm {
			case 12: // tail call
				analysis.UsedReg = []int{1, 2, 3}
				analysis.UsedStack = []int16{0, 0}
			case 1, 3, 23, 44: // map lookup, delete
				analysis.UsedReg = []int{1, 2}
			case 2, 69: // map update
				analysis.UsedReg = []int{1, 2, 3, 4}
			case 4, 51: // map lookup
				analysis.UsedReg = []int{1, 2, 3}
			case 5, 7, 8: // various helpers
				// only updates r0
			case 9, 10, 11: // complex helpers
				analysis.UsedReg = []int{1, 2, 3, 4, 5}
			default:
				analysis.UsedReg = []int{1, 2, 3, 4, 5}
			}
		} else if msb == bpf.JMP_EXIT {
			analysis.UsedReg = []int{0}
			analysis.IsExit = true
		} else if opcode == 0x05 { // unconditional jump
			analysis.Offset = off
		} else { // conditional jump
			analysis.UsedReg = []int{dst, src}
			analysis.Offset = off
		}

	case bpf.BPF_STX: // store register to memory
		msb := opcode & 0xE0
		if msb == bpf.BPF_MEM || msb == bpf.BPF_MEMSX || msb == bpf.BPF_ATOMIC {
			size := int16(1 << ((opcode & 0x18) >> 3))
			if dst == 10 { // stack pointer
				analysis.UpdatedStack = []int16{off, size}
				analysis.UsedReg = []int{src}
			} else {
				analysis.UsedReg = []int{src}
			}
		}

	case bpf.BPF_ST: // store immediate to memory
		msb := opcode & 0xE0
		if msb == bpf.BPF_MEM || msb == bpf.BPF_MEMSX || msb == bpf.BPF_ATOMIC {
			size := int16(1 << ((opcode & 0x18) >> 3))
			if dst == 10 { // stack pointer
				analysis.UpdatedStack = []int16{off, size}
			}
		}

	case bpf.BPF_LDX: // load from memory to register
		msb := opcode & 0xE0
		if msb == bpf.BPF_MEM || msb == bpf.BPF_MEMSX {
			size := int16(1 << ((opcode & 0x18) >> 3))
			analysis.UpdatedReg = dst
			if src == 10 { // stack pointer
				analysis.UsedStack = []int16{off, size}
			} else {
				analysis.UsedReg = []int{src}
			}
		}

	case bpf.BPF_LD: // load immediate to register
		msb := opcode & 0xE0
		if msb == bpf.BPF_IMM {
			analysis.UpdatedReg = dst
		} else if msb == bpf.BPF_ABS || msb == bpf.BPF_IND {
			analysis.UpdatedReg = dst
			analysis.UsedReg = []int{src}
		}
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

	currentNode := 0

	// First pass: identify basic block boundaries
	for i, inst := range s.Instructions {
		opcode := inst.Opcode
		off := inst.Offset
		msb := opcode & 0xF0

		if (opcode&0x07) == bpf.BPF_JMP || (opcode&0x07) == bpf.BPF_JMP32 {
			if msb == bpf.JMP_CALL {
				continue
			}
			if msb == bpf.JMP_EXIT {
				cfg.Nodes[currentNode] = []int{}
			} else if opcode == 0x05 { // unconditional jump
				jumpTarget := i + int(off) + 1
				// Only add valid jump targets (within bounds)
				if jumpTarget >= 0 && jumpTarget < len(s.Instructions) {
					cfg.Nodes[currentNode] = []int{jumpTarget}
				} else {
					cfg.Nodes[currentNode] = []int{} // Invalid jump target treated as exit
				}
			} else { // conditional jump
				cfg.Nodes[currentNode] = []int{i}
				jumpTarget := i + int(off) + 1
				fallThrough := i + 1

				successors := make([]int, 0, 2)
				// Add jump target if valid
				if jumpTarget >= 0 && jumpTarget < len(s.Instructions) {
					successors = append(successors, jumpTarget)
				}
				// Add fall-through if valid
				if fallThrough >= 0 && fallThrough < len(s.Instructions) {
					successors = append(successors, fallThrough)
				}
				cfg.Nodes[i] = successors
			}
			currentNode = i + 1
		}
	}

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

	// Sort nodes
	for i := 0; i < len(allNodes); i++ {
		for j := i + 1; j < len(allNodes); j++ {
			if allNodes[i] > allNodes[j] {
				allNodes[i], allNodes[j] = allNodes[j], allNodes[i]
			}
		}
	}

	for i := 0; i < len(allNodes)-1; i++ {
		cfg.NodesLen[allNodes[i]] = allNodes[i+1] - allNodes[i]
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

		analysis := s.analyzeInstruction(inst)

		// Handle register alias updates
		if inst.Opcode != 0xBF && inst.Opcode != 0x07 {
			if analysis.UpdatedReg >= 0 && analysis.UpdatedReg < 11 {
				state.RegAlias[analysis.UpdatedReg] = -1
			}
		}

		// Process used registers
		for _, regIdx := range analysis.UsedReg {
			if regIdx < 0 || regIdx >= 11 {
				continue
			}

			// Handle stack alias
			if regIdx == 10 {
				if analysis.UpdatedReg >= 0 && analysis.UpdatedReg < 11 {
					state.RegAlias[analysis.UpdatedReg] = 0
				}
			} else if analysis.UpdatedReg >= 0 && analysis.UpdatedReg < 11 && state.RegAlias[analysis.UpdatedReg] != -1 && inst.Opcode == 0x07 {
				state.RegAlias[analysis.UpdatedReg] += int16(inst.Imm)
			} else if inst.Opcode != 0x85 {
				if analysis.UpdatedReg >= 0 && analysis.UpdatedReg < 11 {
					state.RegAlias[analysis.UpdatedReg] = -1
				}
			}

			// Add dependencies based on register usage
			if len(state.Registers[regIdx]) == 0 {
				continue
			}

			for _, depInstIdx := range state.Registers[regIdx] {
				if depInstIdx == -1 {
					// Special case for initial state, skip
					continue
				}
				if depInstIdx >= 0 && depInstIdx < len(s.Dependencies) {
					if state.RegAlias[regIdx] != -1 && state.RegAlias[regIdx] != 0 {
						// Handle stack dependencies through register aliases
						if stackInsts, exists := state.Stacks[state.RegAlias[regIdx]]; exists {
							for _, stackInstIdx := range stackInsts {
								if stackInstIdx >= 0 && stackInstIdx < len(s.Dependencies) {
									s.Dependencies[instIdx].Dependencies = append(s.Dependencies[instIdx].Dependencies, stackInstIdx)
									s.Dependencies[stackInstIdx].DependedBy = append(s.Dependencies[stackInstIdx].DependedBy, instIdx)
								}
							}
						} else {
							state.Stacks[state.RegAlias[regIdx]] = []int{-1}
							// Don't add -1 to dependencies array
						}
					}

					s.Dependencies[instIdx].Dependencies = append(s.Dependencies[instIdx].Dependencies, depInstIdx)
					s.Dependencies[depInstIdx].DependedBy = append(s.Dependencies[depInstIdx].DependedBy, instIdx)
				}
			}
		}

		// Update register state
		if analysis.UpdatedReg >= 0 && analysis.UpdatedReg < 11 {
			state.Registers[analysis.UpdatedReg] = []int{instIdx}
		}

		// Handle function calls
		if analysis.IsCall {
			for j := 1; j <= 5; j++ { // r1-r5 are caller-saved
				state.Registers[j] = make([]int, 0)
			}
		}

		// Handle stack updates
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
				// Don't add -1 to dependencies array
			}
		}

		// Handle exit instructions
		if analysis.IsExit {
			nodesDone[base] = true
			return
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
