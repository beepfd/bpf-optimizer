package main

import (
	"fmt"
	"strconv"
	"strings"
)

type Instruction struct {
	Raw    string
	Opcode uint8
	SrcReg uint8
	Imm    int32
}

func isMaskPattern(hexStr string) bool {
	val, err := strconv.ParseUint(hexStr, 16, 64)
	if err != nil {
		return false
	}

	binStr := fmt.Sprintf("%032b", val)

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

func findMaskCandidates(instructions []*Instruction) []int {
	maskCandidates := make([]int, 0)

	for i := 0; i < len(instructions)-1; i++ {
		inst1 := instructions[i]
		inst2 := instructions[i+1]

		fmt.Printf("Checking instruction %d: opcode=%02x, srcReg=%d, raw=%s\n", i, inst1.Opcode, inst1.SrcReg, inst1.Raw)
		fmt.Printf("Checking instruction %d: opcode=%02x, imm=%d, raw=%s\n", i+1, inst2.Opcode, inst2.Imm, inst2.Raw)

		if inst1.Opcode == 0x18 && inst2.Opcode == 0x00 && inst1.SrcReg == 0 {
			fmt.Printf("  Opcodes and SrcReg match\n")
			if inst2.Imm != 0 {
				fmt.Printf("  Second instruction Imm is not 0: %d\n", inst2.Imm)
				continue
			}

			if len(inst1.Raw) < 16 {
				fmt.Printf("  Raw string too short: %d\n", len(inst1.Raw))
				continue
			}

			rawLen := len(inst1.Raw)
			fmt.Printf("  Raw length: %d\n", rawLen)
			if rawLen >= 16 {
				imm1Hex := inst1.Raw[rawLen-8:]
				fmt.Printf("  Using last 8 chars: %s\n", imm1Hex)
			} else {
				fmt.Printf("  Raw too short for extraction\n")
				continue
			}
			imm1Hex := inst1.Raw[rawLen-8:]
			fmt.Printf("  Extracted hex: %s\n", imm1Hex)
			if isMaskPattern(imm1Hex) {
				fmt.Printf("  Is mask pattern: true\n")
				maskCandidates = append(maskCandidates, i)
			} else {
				fmt.Printf("  Is mask pattern: false\n")
			}
		} else {
			fmt.Printf("  Opcodes or SrcReg don't match\n")
		}
	}

	return maskCandidates
}

func main() {
	instructions := []*Instruction{
		{
			Raw:    "180000000000000000000000ffffffff",
			Opcode: 0x18,
			SrcReg: 0,
			Imm:    0,
		},
		{
			Raw:    "000000000000000000000000",
			Opcode: 0x00,
			SrcReg: 0,
			Imm:    0,
		},
	}

	result := findMaskCandidates(instructions)
	fmt.Printf("Found %d candidates: %v\n", len(result), result)
}