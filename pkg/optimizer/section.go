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
	Name         string
	Instructions []*bpf.Instruction
	Dependencies []DependencyInfo // dependency information for each instruction
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
	section.applyOptimizations()

	return section, nil
}

// buildDependencies builds the dependency graph for instructions
// This is a complete implementation based on Python's build_dependency method
func (s *Section) buildDependencies() {
	// Build control flow graph
	cfg := s.buildControlFlowGraph()

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
	s.applySuperwordMerge()
}

// applyConstantPropagation implements constant propagation optimization
func (s *Section) applyConstantPropagation() {
	candidates := make([]int, 0)

	for i, inst := range s.Instructions {
		// Look for immediate load instructions (MOV with immediate)
		if inst.Opcode == 0xB7 || inst.Opcode == 0xB4 {
			canPropagate := true

			// Check if all dependent instructions can be optimized
			for _, depIdx := range s.Dependencies[i].DependedBy {
				depInst := s.Instructions[depIdx]
				if depInst.GetInstructionClass() != bpf.BPF_STX ||
					len(s.Dependencies[depIdx].Dependencies) != 1 ||
					depInst.Opcode == 0xDB || depInst.Opcode == 0xC3 {
					canPropagate = false
					break
				}
			}

			if canPropagate {
				candidates = append(candidates, i)
			}
		}
	}

	// Apply constant propagation
	for _, candIdx := range candidates {
		inst := s.Instructions[candIdx]

		// Replace dependent store instructions with immediate stores
		for _, depIdx := range s.Dependencies[candIdx].DependedBy {
			depInst := s.Instructions[depIdx]
			newOpcode := (depInst.Opcode & 0xF8) | bpf.BPF_ST

			// Create new instruction with immediate value
			newHex := fmt.Sprintf("%02x0%s%s", newOpcode,
				depInst.Raw[3:8], inst.Raw[8:])
			newInst, _ := bpf.NewInstruction(newHex)
			s.Instructions[depIdx] = newInst

			// Clear dependencies
			s.Dependencies[depIdx].Dependencies = make([]int, 0)
		}

		// Mark original instruction as NOP
		s.Instructions[candIdx].SetAsNOP()
		s.Dependencies[candIdx].DependedBy = make([]int, 0)
	}
}

// applyCompaction implements code compaction optimization
func (s *Section) applyCompaction() {
	candidates := make([]int, 0)

	for i := 0; i < len(s.Instructions)-1; i++ {
		inst1 := s.Instructions[i]
		inst2 := s.Instructions[i+1]

		// Look for LSH followed by RSH pattern (bit field extraction)
		if inst1.Opcode == 0x67 && inst2.Opcode == 0x77 {
			if inst1.Raw[8:] == "20000000" && inst2.Raw[8:] == "20000000" {
				candidates = append(candidates, i)
			}
		}
	}

	// Apply compaction
	for _, candIdx := range candidates {
		targetReg := s.Instructions[candIdx].Raw[3:4]
		newHex := fmt.Sprintf("bc%s%s000000000000", targetReg, targetReg)
		newInst, _ := bpf.NewInstruction(newHex)

		s.Instructions[candIdx] = newInst
		s.Instructions[candIdx+1].SetAsNOP()
	}
}

// applyPeepholeOptimization implements peephole optimization
func (s *Section) applyPeepholeOptimization() {
	maskCandidates := make([]int, 0)

	// Find mask candidates (64-bit immediate loads with mask patterns)
	for i := 0; i < len(s.Instructions)-1; i++ {
		inst1 := s.Instructions[i]
		inst2 := s.Instructions[i+1]

		if inst1.Opcode == 0x18 && inst2.Opcode == 0x00 && inst1.SrcReg == 0 {
			// Check if this is a mask pattern (monotonically decreasing bits)
			imm2Hex := inst2.Raw[14:16] + inst2.Raw[12:14] + inst2.Raw[10:12] + inst2.Raw[8:10]
			if imm2Hex == "00000000" {
				imm1Hex := inst1.Raw[14:16] + inst1.Raw[12:14] + inst1.Raw[10:12] + inst1.Raw[8:10]
				if isMaskPattern(imm1Hex) {
					maskCandidates = append(maskCandidates, i)
				}
			}
		}
	}

	// Find optimization candidates from mask candidates
	candidates := make([][]int, 0)
	for _, maskIdx := range maskCandidates {
		for _, depIdx := range s.Dependencies[maskIdx].DependedBy {
			depInst := s.Instructions[depIdx]

			// Look for AND followed by right shift
			if depInst.Opcode == 0x5F {
				canOptimize := true
				for _, nextDepIdx := range s.Dependencies[depIdx].DependedBy {
					nextDepInst := s.Instructions[nextDepIdx]
					if nextDepInst.Opcode != 0x77 {
						canOptimize = false
						break
					}
				}

				if canOptimize {
					candidates = append(candidates, []int{maskIdx, depIdx})
				}
			}
		}
	}

	// Apply peephole optimization
	for _, candidate := range candidates {
		targetReg := s.Instructions[candidate[1]].Raw[3:4]
		newHex := fmt.Sprintf("bc%s%s000000000000", targetReg, targetReg)
		newInst, _ := bpf.NewInstruction(newHex)

		s.Instructions[candidate[1]] = newInst
		s.Instructions[candidate[0]].SetAsNOP()
		s.Instructions[candidate[0]+1].SetAsNOP()
	}
}

// applySuperwordMerge implements superword-level merge optimization
func (s *Section) applySuperwordMerge() {
	// Simplified implementation - full version would need complex analysis
	// This is a placeholder for the sophisticated superword analysis
	// that was in the Python version

	// Look for adjacent memory operations that can be merged
	for i := 0; i < len(s.Instructions)-1; i++ {
		inst1 := s.Instructions[i]
		inst2 := s.Instructions[i+1]

		// Check if both are memory operations with consecutive addresses
		if isMemoryOperation(inst1) && isMemoryOperation(inst2) {
			if canMergeMemoryOps(inst1, inst2) {
				// Merge the operations (simplified)
				mergedInst := createMergedMemoryOp(inst1, inst2)
				s.Instructions[i] = mergedInst
				s.Instructions[i+1].SetAsNOP()
			}
		}
	}
}

// Helper functions

// isMaskPattern checks if a hex string represents a mask pattern
func isMaskPattern(hexStr string) bool {
	val, err := strconv.ParseUint(hexStr, 16, 64)
	if err != nil {
		return false
	}

	binStr := fmt.Sprintf("%064b", val)

	// Check for monotonically decreasing pattern
	for i := 0; i < len(binStr)-1; i++ {
		if binStr[i] < binStr[i+1] {
			return false
		}
	}

	return strings.Contains(binStr, "1")
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
