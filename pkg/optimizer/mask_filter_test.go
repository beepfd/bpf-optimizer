package optimizer

import (
	"testing"

	"github.com/beepfd/bpf-optimizer/pkg/bpf"
)

func TestFindMaskCandidates(t *testing.T) {
	tests := []struct {
		name         string
		instructions []*bpf.Instruction
		expected     []int
	}{
		{
			name:         "empty instructions",
			instructions: []*bpf.Instruction{},
			expected:     []int{},
		},
		{
			name: "single instruction",
			instructions: []*bpf.Instruction{
				createInstructionWithOpcode(0x18, 0),
			},
			expected: []int{},
		},
		{
			name: "valid mask pattern",
			instructions: []*bpf.Instruction{
				createInstructionWithRaw("18000000ffffffff", 0x18, 0),
				createInstructionWithRaw("0000000000000000", 0x00, 0),
			},
			expected: []int{0},
		},
		{
			name: "invalid second instruction imm",
			instructions: []*bpf.Instruction{
				createInstructionWithRaw("18000000ffffffff", 0x18, 0),
				createInstructionWithRawAndImm("0000000000000000", 0x00, 0, 1),
			},
			expected: []int{},
		},
		{
			name: "wrong opcode first instruction",
			instructions: []*bpf.Instruction{
				createInstructionWithRaw("17000000ffffffff", 0x17, 0),
				createInstructionWithRaw("0000000000000000", 0x00, 0),
			},
			expected: []int{},
		},
		{
			name: "wrong opcode second instruction",
			instructions: []*bpf.Instruction{
				createInstructionWithRaw("18000000ffffffff", 0x18, 0),
				createInstructionWithRaw("0100000000000000", 0x01, 0),
			},
			expected: []int{},
		},
		{
			name: "non-zero src reg",
			instructions: []*bpf.Instruction{
				createInstructionWithRaw("18000000ffffffff", 0x18, 1),
				createInstructionWithRaw("0000000000000000", 0x00, 0),
			},
			expected: []int{},
		},
		{
			name: "multiple valid mask patterns",
			instructions: []*bpf.Instruction{
				createInstructionWithRaw("18000000ffffffff", 0x18, 0),
				createInstructionWithRaw("0000000000000000", 0x00, 0),
				createInstructionWithRaw("b700000000000000", 0xb7, 0),
				createInstructionWithRaw("180000000000ffff", 0x18, 0),
				createInstructionWithRaw("0000000000000000", 0x00, 0),
			},
			expected: []int{0, 3},
		},
		{
			name: "multiple valid mask patterns",
			instructions: []*bpf.Instruction{
				createInstructionWithRaw("18010000feffffff", 0x18, 0),
				createInstructionWithRaw("0000000000000000", 0x00, 0),
				createInstructionWithRaw("18010000ffffffff", 0x18, 0),
				createInstructionWithRaw("0000000000000000", 0x00, 0),
			},
			expected: []int{0, 2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := findMaskCandidates(tt.instructions)
			if len(result) != len(tt.expected) {
				t.Errorf("expected %d candidates, got %d", len(tt.expected), len(result))
				return
			}
			for i, expected := range tt.expected {
				if result[i] != expected {
					t.Errorf("expected candidate at index %d, got %d", expected, result[i])
				}
			}
		})
	}
}

func createInstructionWithOpcode(opcode uint8, srcReg uint8) *bpf.Instruction {
	return &bpf.Instruction{
		Opcode: opcode,
		SrcReg: srcReg,
	}
}

func createInstructionWithRaw(raw string, opcode uint8, srcReg uint8) *bpf.Instruction {
	return &bpf.Instruction{
		Raw:    raw,
		Opcode: opcode,
		SrcReg: srcReg,
		Imm:    0, // Default to 0 for valid mask patterns
	}
}

func createInstructionWithRawAndImm(raw string, opcode uint8, srcReg uint8, imm int32) *bpf.Instruction {
	return &bpf.Instruction{
		Raw:    raw,
		Opcode: opcode,
		SrcReg: srcReg,
		Imm:    imm,
	}
}

func TestIsMaskPattern(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "valid mask pattern all f",
			input:    "ffffffff",
			expected: true,
		},
		{
			name:     "valid mask pattern zeros",
			input:    "00000000",
			expected: false, // all zeros contain no '1' bits
		},
		{
			name:     "valid mask pattern descending",
			input:    "ff00ff00",
			expected: false, // not monotonically decreasing
		},
		{
			name:     "valid mask pattern monotonic",
			input:    "ffff0000",
			expected: true, // monotonically decreasing with 1s
		},
		{
			name:     "invalid mask pattern",
			input:    "12345678",
			expected: false,
		},
		{
			name:     "empty string",
			input:    "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isMaskPattern(tt.input)
			if result != tt.expected {
				t.Errorf("expected %t, got %t", tt.expected, result)
			}
		})
	}
}
