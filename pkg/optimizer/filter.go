package optimizer

import (
	"fmt"

	"github.com/beepfd/bpf-optimizer/pkg/bpf"
)

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
			if inst1.Raw[8:] != "20000000" || inst2.Raw[8:] != "20000000" {
				continue
			}
			if inst1.DstReg != inst2.DstReg {
				continue
			}
			candidates = append(candidates, i)
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
	// Find mask candidates
	maskCandidates := findMaskCandidates(s.Instructions)

	// Find optimization candidates from mask candidates
	candidates := findCandidates(s, maskCandidates)

	// Apply peephole optimization
	applyPeepholeOptimization(s, candidates)
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
