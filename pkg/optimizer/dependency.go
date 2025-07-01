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

// Clone creates a deep copy of the ControlFlowGraph
func (cfg *ControlFlowGraph) Clone() *ControlFlowGraph {
	newCfg := &ControlFlowGraph{
		Nodes:     make(map[int][]int),
		NodesRev:  make(map[int][]int),
		NodesLen:  make(map[int]int),
		NodeStats: make(map[int]*RegisterState),
	}

	// Copy Nodes
	for nodeID, successors := range cfg.Nodes {
		newCfg.Nodes[nodeID] = make([]int, len(successors))
		copy(newCfg.Nodes[nodeID], successors)
	}

	// Copy NodesRev
	for nodeID, predecessors := range cfg.NodesRev {
		newCfg.NodesRev[nodeID] = make([]int, len(predecessors))
		copy(newCfg.NodesRev[nodeID], predecessors)
	}

	// Copy NodesLen
	for nodeID, length := range cfg.NodesLen {
		newCfg.NodesLen[nodeID] = length
	}

	// Copy NodeStats
	for nodeID, state := range cfg.NodeStats {
		newCfg.NodeStats[nodeID] = state.Clone()
	}

	return newCfg
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
	// rs.Registers[1] = []int{-1}
	// rs.Registers[10] = []int{-1}

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

	// Build forward mapping
	buildInstructionNode(s.Instructions, cfg)

	// Build reverse mapping
	buildInstructionNodeReverse(cfg)

	// Calculate node lengths
	buildInstructionNodeLength(s.Instructions, cfg)

	// Analyze each instruction in each basic block
	rebuildInstructionNodeRev(s.Instructions, cfg)

	// Update forward edges based on detailed reverse mapping
	updateInstructionNode(cfg)

	return cfg
}

// updateDependencies performs the main dependency analysis
// This corresponds to Python's update_property method
func (s *Section) updateDependencies(cfg *ControlFlowGraph, base int, state *RegisterState, nodesDone map[int]bool, loopInfo *LoopInfo, inferOnly bool) *RegisterState {
	if nodesDone == nil {
		nodesDone = make(map[int]bool)
	}

	nodeLen, exists := cfg.NodesLen[base]
	if !exists {
		return state
	}

	// Process instructions in current basic block
	s.BuildRegisterDependencies(cfg, nodeLen, base, state, nodesDone)

	// Store state for this node
	cfg.NodeStats[base] = state.Clone()

	if inferOnly {
		return state
	}

	nodesDone[base] = true

	// Handle loop processing
	if loopInfo != nil {
		// Get predecessors of loop head
		predecessors := make(map[int]bool)
		if preds, exists := cfg.NodesRev[loopInfo.Head]; exists {
			for _, pred := range preds {
				predecessors[pred] = true
			}
		}

		// Check if all predecessors are done
		allPredsDone := true
		for pred := range predecessors {
			if !nodesDone[pred] {
				allPredsDone = false
				break
			}
		}

		if allPredsDone {
			// Collect states from all predecessors
			var predStates []*RegisterState
			for pred := range predecessors {
				if predState, exists := cfg.NodeStats[pred]; exists {
					predStates = append(predStates, predState)
				}
			}

			// Merge predecessor states
			mergedState := MergeRegisterStates(predStates)

			// First, simulate loop execution to check convergence (corresponds to Python's infer_only=1)
			simulatedState := s.updateDependencies(cfg, loopInfo.Head, mergedState.Clone(), nodesDone, loopInfo, true)

			// Check for fixed point (convergence) by comparing simulated result
			continueLoop := false
			if loopHeadState, exists := cfg.NodeStats[loopInfo.Head]; exists {
				if !simulatedState.IsEqual(loopHeadState) {
					continueLoop = true
				}
			} else {
				continueLoop = true
			}

			if continueLoop {
				// Update loop head state
				cfg.NodeStats[loopInfo.Head] = mergedState.Clone()

				// Reset processed nodes in this loop iteration (corresponds to Python's nodes_done -= loop_info[3])
				for node := range loopInfo.Processed {
					delete(nodesDone, node)
				}
				loopInfo.Processed = make(map[int]bool)

				// Reset waiting nodes in this loop iteration
				for node := range loopInfo.Waiting {
					delete(nodesDone, node)
				}
				loopInfo.Waiting = make(map[int]bool)

				// Recursively process loop with updated state
				return s.updateDependencies(cfg, loopInfo.Head, mergedState, nodesDone, loopInfo, false)
			} else {
				// Loop has converged, handle nested loop completion
				if loopInfo.Parent != nil {
					// Notify parent loop that this loop head is complete (corresponds to Python's loop_info[4][3].add(loop_info[0]))
					delete(loopInfo.Parent.Waiting, loopInfo.Head)
				}
				nodesDone[loopInfo.Head] = true

				// Continue with parent loop if it exists
				if loopInfo.Parent != nil {
					return s.updateDependencies(cfg, base, state, nodesDone, loopInfo.Parent, inferOnly)
				}
			}
		} else {
			// Not all predecessors are done, mark this node as waiting (corresponds to Python's loop_info[3].add(base))
			loopInfo.Waiting[base] = true
		}

	}

	// Mark this node as processed in current loop iteration
	if loopInfo != nil {
		loopInfo.Processed[base] = true
	}

	newBase, newState := s.findNextNode(cfg, nodesDone, loopInfo)
	if newState != nil && state != nil && state.RegAlias != nil {
		newState.RegAlias = state.RegAlias
	}

	// If no ready node found, look for loops
	if newBase == 0 {
		loopHead := s.findLoopCandidates(cfg, nodesDone)
		if loopHead != 0 {
			// Create new loop info
			newLoopInfo := NewLoopInfo(loopHead, loopInfo)

			// Initialize loop state from predecessors
			loopState := buildLoopState(cfg, loopHead)

			// Process loop
			return s.updateDependencies(cfg, loopHead, loopState, nodesDone, newLoopInfo, false)
		}
	} else if newBase != base {
		// Continue with next node
		return s.updateDependencies(cfg, newBase, newState, nodesDone, loopInfo, false)
	}

	return state
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
