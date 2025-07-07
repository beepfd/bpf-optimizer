package optimizer

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/beepfd/bpf-optimizer/pkg/bpf"
)

// findMaskCandidates finds mask candidates in the instruction sequence
// Returns indices of instructions that are 64-bit immediate loads with mask patterns
func findMaskCandidates(instructions []*bpf.Instruction) []int {
	maskCandidates := make([]int, 0)

	for i := 0; i < len(instructions)-1; i++ {
		inst1 := instructions[i]
		inst2 := instructions[i+1]

		if inst1.Opcode == bpf.BPF_LDDW && inst2.Opcode == bpf.BPF_IMM && inst1.SrcReg == 0 {
			if inst2.Imm != 0 {
				continue
			}

			// Extract the mask from the raw string using the original logic
			// The raw string is 16 characters, and we need to extract the immediate value
			imm1Hex := inst1.GetRawImm()
			if imm1Hex == "" {
				fmt.Printf("inst1: %s,index: %d, imm1Hex is empty\n", inst1.String(), i)
				continue
			}

			if isMaskPattern(imm1Hex) {
				maskCandidates = append(maskCandidates, i)
			}
		}
	}

	return maskCandidates
}

// isMaskPattern checks if a hex string represents a mask pattern
func isMaskPattern(hexStr string) bool {
	val, err := strconv.ParseUint(hexStr, 16, 64)
	if err != nil {
		return false
	}

	binStr := fmt.Sprintf("%b", val)

	// Check for monotonically decreasing pattern (from most significant bit)
	// A mask pattern typically has all 1s followed by all 0s (or similar patterns)
	inZeros := false
	for i := 0; i < len(binStr); i++ {
		if binStr[i] == '0' {
			inZeros = true
		} else if inZeros && binStr[i] == '1' {
			// Found a 1 after we've seen zeros - not a valid mask pattern
			return false
		}
	}

	return strings.Contains(binStr, "1")
}

func findCandidates(s *Section, maskCandidates []int) [][]int {
	// Find optimization candidates from mask candidates
	candidates := make([][]int, 0)
	for _, maskIdx := range maskCandidates {
		for _, depIdx := range s.Dependencies[maskIdx].DependedBy {
			depInst := s.Instructions[depIdx]

			// Look for AND followed by right shift
			if depInst.Opcode == bpf.ALU_AND_K {
				canOptimize := true
				for _, nextDepIdx := range s.Dependencies[depIdx].DependedBy {
					nextDepInst := s.Instructions[nextDepIdx]
					if nextDepInst.Opcode != bpf.ALU_RSH_K {
						canOptimize = false
						break
					}
				}

				if !canOptimize {
					continue
				}

				// Check for previous MOV instruction that can be optimized
				var includePre *int
				if len(s.Dependencies[depIdx].Dependencies) == 2 {
					// Find the other dependency (not the mask)
					for _, preIdx := range s.Dependencies[depIdx].Dependencies {
						if preIdx != maskIdx {
							preInst := s.Instructions[preIdx]
							if preInst.Opcode == bpf.ALU_MOV_K {
								includePre = &preIdx
							}
							break
						}
					}
				}

				if includePre != nil {
					candidates = append(candidates, []int{maskIdx, depIdx, *includePre})
				} else {
					candidates = append(candidates, []int{maskIdx, depIdx})
				}
			}
		}
	}

	return candidates
}

func applyPeepholeOptimization(s *Section, candidates [][]int) {
	// Apply peephole optimization
	for _, candidate := range candidates {
		var newHex string
		var targetInst *bpf.Instruction

		if len(candidate) == 3 {
			// 3-element case: [mask, item, include_pre]
			preInst := s.Instructions[candidate[2]]
			newHex = fmt.Sprintf("bc%s%s000000000000", preInst.Raw[2:3], preInst.Raw[3:4])
			targetInst = s.Instructions[candidate[1]]
		} else {
			// 2-element case: [mask, item]
			targetInst = s.Instructions[candidate[1]]
			targetReg := targetInst.Raw[3:4]
			newHex = fmt.Sprintf("bc%s%s000000000000", targetReg, targetReg)
		}

		newInst, _ := bpf.NewInstruction(newHex)

		// Apply optimizations based on candidate length
		for i, idx := range candidate {
			if i == 1 {
				// Replace the target instruction (item) with the optimized one
				s.Instructions[idx] = newInst
			} else {
				// Set other instructions as NOP
				s.Instructions[idx].SetAsNOP()
			}
		}

		// Always set mask+1 instruction as NOP (second part of 64-bit load)
		s.Instructions[candidate[0]+1].SetAsNOP()
	}
}
