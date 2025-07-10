package optimizer

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/beepfd/bpf-optimizer/pkg/bpf"
)

// Section represents a BPF code section with optimization capabilities
type Section struct {
	Name             string
	Instructions     []*bpf.Instruction
	Dependencies     []DependencyInfo // dependency information for each instruction
	ControlFlowGraph *ControlFlowGraph
}

// DependencyInfo tracks dependencies for an instruction
type DependencyInfo struct {
	Dependencies []int // indices of instructions this depends on
	DependedBy   []int // indices of instructions that depend on this
}

func (d DependencyInfo) Deduplication() DependencyInfo {
	// Remove duplicates from Dependencies
	d.Dependencies = removeDuplicateInts(d.Dependencies)
	// Remove duplicates from DependedBy
	d.DependedBy = removeDuplicateInts(d.DependedBy)

	return d
}

// removeDuplicateInts removes duplicate integers from a slice and returns a sorted slice
func removeDuplicateInts(slice []int) []int {
	if len(slice) == 0 {
		return slice
	}

	// Sort first to group duplicates together
	sort.Ints(slice)

	// Remove duplicates by comparing adjacent elements
	result := make([]int, 0, len(slice))
	result = append(result, slice[0])

	for i := 1; i < len(slice); i++ {
		if slice[i] != slice[i-1] {
			result = append(result, slice[i])
		}
	}

	return result
}

// NewSection creates a new section from hex data
func NewSection(hexData, name string, skipOptimization bool) (*Section, error) {
	if len(hexData)%16 != 0 {
		return nil, fmt.Errorf("bytecode section length must be a multiple of 16")
	}

	section := &Section{
		Name:         name,
		Instructions: make([]*bpf.Instruction, 0),
		Dependencies: make([]DependencyInfo, 0),
	}

	// Parse instructions (16 hex chars each)
	for i := 0; i < len(hexData); i += 16 {
		inst, err := bpf.NewInstruction(hexData[i : i+16])
		if err != nil {
			return nil, fmt.Errorf("failed to parse instruction at %d: %v", i/16, err)
		}
		section.Instructions = append(section.Instructions, inst)
		section.Dependencies = append(section.Dependencies, DependencyInfo{
			Dependencies: make([]int, 0),
			DependedBy:   make([]int, 0),
		})
	}

	// Build dependency graph and apply optimizations
	section.buildDependencies()
	if !skipOptimization {
		section.applyOptimizations()
	}

	return section, nil
}

// buildDependencies builds the dependency graph for instructions
// This is a complete implementation based on Python's build_dependency method
func (s *Section) buildDependencies() {
	// Build control flow graph
	cfg := s.buildControlFlowGraph()
	s.ControlFlowGraph = cfg

	// Initialize register state
	initialState := NewRegisterState()
	initialState.Registers[1] = []int{-1}
	initialState.Registers[10] = []int{-1}

	// Start dependency analysis from entry point
	nodesDone := make(map[int]bool)
	s.updateDependencies(cfg, 0, initialState, nodesDone, nil, false)
}

// applyOptimizations applies all optimization techniques
func (s *Section) applyOptimizations() {
	s.applyConstantPropagation()
	s.applyCompaction()
	s.applyPeepholeOptimization()
	//s.applySuperwordMerge(storeCandidates)
}

// isMemoryOperation checks if an instruction is a memory operation
func isMemoryOperation(inst *bpf.Instruction) bool {
	class := inst.GetInstructionClass()
	return class == bpf.BPF_LD || class == bpf.BPF_LDX ||
		class == bpf.BPF_ST || class == bpf.BPF_STX
}

// canMergeMemoryOps checks if two memory operations can be merged
func canMergeMemoryOps(inst1, inst2 *bpf.Instruction) bool {
	// Simplified check - full implementation would need address analysis
	return inst1.DstReg == inst2.DstReg &&
		inst1.SrcReg == inst2.SrcReg &&
		inst2.Offset == inst1.Offset+getMemorySize(inst1)
}

// createMergedMemoryOp creates a merged memory operation
func createMergedMemoryOp(inst1, inst2 *bpf.Instruction) *bpf.Instruction {
	// Simplified implementation
	return inst1.Clone()
}

// getMemorySize returns the memory size for an instruction
func getMemorySize(inst *bpf.Instruction) int16 {
	sizeMask := inst.Opcode & 0x18
	switch sizeMask {
	case bpf.SIZE_B:
		return 1
	case bpf.SIZE_H:
		return 2
	case bpf.SIZE_W:
		return 4
	case bpf.SIZE_DW:
		return 8
	default:
		return 1
	}
}

// Dump converts the section back to hex string
func (s *Section) Dump() []byte {
	var result strings.Builder

	for _, inst := range s.Instructions {
		result.WriteString(inst.ToHex())
	}

	hexStr := result.String()
	data := make([]byte, len(hexStr)/2)

	for i := 0; i < len(hexStr); i += 2 {
		b, _ := strconv.ParseUint(hexStr[i:i+2], 16, 8)
		data[i/2] = byte(b)
	}

	return data
}
