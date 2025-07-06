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
