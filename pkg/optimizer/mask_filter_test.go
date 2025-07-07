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

func TestFindCandidates(t *testing.T) {
	tests := []struct {
		name           string
		section        *Section
		maskCandidates []int
		expected       [][]int
	}{
		{
			name: "empty mask candidates",
			section: &Section{
				Instructions: []*bpf.Instruction{},
				Dependencies: []DependencyInfo{},
			},
			maskCandidates: []int{},
			expected:       [][]int{},
		},
		{
			name: "single AND operation without dependencies",
			section: &Section{
				Instructions: []*bpf.Instruction{
					createInstructionWithRaw("18000000ffffffff", 0x18, 0), // mask instruction
					createInstructionWithRaw("0000000000000000", 0x00, 0), // mask part 2
					createInstructionWithRaw("5700000000000000", 0x57, 0), // AND operation
				},
				Dependencies: []DependencyInfo{
					{Dependencies: []int{}, DependedBy: []int{2}},        // mask depends on nothing, depended by AND
					{Dependencies: []int{}, DependedBy: []int{}},         // mask part 2
					{Dependencies: []int{0}, DependedBy: []int{}},        // AND depends on mask
				},
			},
			maskCandidates: []int{0},
			expected:       [][]int{},
		},
		{
			name: "AND followed by right shift - valid optimization",
			section: &Section{
				Instructions: []*bpf.Instruction{
					createInstructionWithRaw("18000000ffffffff", 0x18, 0), // mask instruction
					createInstructionWithRaw("0000000000000000", 0x00, 0), // mask part 2
					createInstructionWithRaw("5700000000000000", bpf.ALU_AND_K, 0), // AND operation
					createInstructionWithRaw("7700000000000000", bpf.ALU_RSH_K, 0), // right shift
				},
				Dependencies: []DependencyInfo{
					{Dependencies: []int{}, DependedBy: []int{2}},        // mask depends on nothing, depended by AND
					{Dependencies: []int{}, DependedBy: []int{}},         // mask part 2
					{Dependencies: []int{0}, DependedBy: []int{3}},       // AND depends on mask, depended by RSH
					{Dependencies: []int{2}, DependedBy: []int{}},        // RSH depends on AND
				},
			},
			maskCandidates: []int{0},
			expected:       [][]int{{0, 2}},
		},
		{
			name: "AND followed by non-RSH instruction - invalid optimization",
			section: &Section{
				Instructions: []*bpf.Instruction{
					createInstructionWithRaw("18000000ffffffff", 0x18, 0), // mask instruction
					createInstructionWithRaw("0000000000000000", 0x00, 0), // mask part 2
					createInstructionWithRaw("5700000000000000", bpf.ALU_AND_K, 0), // AND operation
					createInstructionWithRaw("0700000000000000", bpf.ALU_ADD, 0),   // ADD (not RSH)
				},
				Dependencies: []DependencyInfo{
					{Dependencies: []int{}, DependedBy: []int{2}},        // mask depends on nothing, depended by AND
					{Dependencies: []int{}, DependedBy: []int{}},         // mask part 2
					{Dependencies: []int{0}, DependedBy: []int{3}},       // AND depends on mask, depended by ADD
					{Dependencies: []int{2}, DependedBy: []int{}},        // ADD depends on AND
				},
			},
			maskCandidates: []int{0},
			expected:       [][]int{},
		},
		{
			name: "AND with MOV dependency - 3-element optimization",
			section: &Section{
				Instructions: []*bpf.Instruction{
					createInstructionWithRaw("18000000ffffffff", 0x18, 0), // mask instruction
					createInstructionWithRaw("0000000000000000", 0x00, 0), // mask part 2
					createInstructionWithRaw("b700000000000000", bpf.ALU_MOV_K, 0), // MOV operation
					createInstructionWithRaw("5700000000000000", bpf.ALU_AND_K, 0), // AND operation
					createInstructionWithRaw("7700000000000000", bpf.ALU_RSH_K, 0), // right shift
				},
				Dependencies: []DependencyInfo{
					{Dependencies: []int{}, DependedBy: []int{3}},        // mask depends on nothing, depended by AND
					{Dependencies: []int{}, DependedBy: []int{}},         // mask part 2
					{Dependencies: []int{}, DependedBy: []int{3}},        // MOV depends on nothing, depended by AND
					{Dependencies: []int{0, 2}, DependedBy: []int{4}},    // AND depends on mask and MOV, depended by RSH
					{Dependencies: []int{3}, DependedBy: []int{}},        // RSH depends on AND
				},
			},
			maskCandidates: []int{0},
			expected:       [][]int{{0, 3, 2}},
		},
		{
			name: "AND with non-MOV dependency - 2-element optimization",
			section: &Section{
				Instructions: []*bpf.Instruction{
					createInstructionWithRaw("18000000ffffffff", 0x18, 0), // mask instruction
					createInstructionWithRaw("0000000000000000", 0x00, 0), // mask part 2
					createInstructionWithRaw("0700000000000000", bpf.ALU_ADD, 0), // ADD operation (not MOV)
					createInstructionWithRaw("5700000000000000", bpf.ALU_AND_K, 0), // AND operation
					createInstructionWithRaw("7700000000000000", bpf.ALU_RSH_K, 0), // right shift
				},
				Dependencies: []DependencyInfo{
					{Dependencies: []int{}, DependedBy: []int{3}},        // mask depends on nothing, depended by AND
					{Dependencies: []int{}, DependedBy: []int{}},         // mask part 2
					{Dependencies: []int{}, DependedBy: []int{3}},        // ADD depends on nothing, depended by AND
					{Dependencies: []int{0, 2}, DependedBy: []int{4}},    // AND depends on mask and ADD, depended by RSH
					{Dependencies: []int{3}, DependedBy: []int{}},        // RSH depends on AND
				},
			},
			maskCandidates: []int{0},
			expected:       [][]int{{0, 3}},
		},
		{
			name: "multiple mask candidates with valid optimizations",
			section: &Section{
				Instructions: []*bpf.Instruction{
					createInstructionWithRaw("18000000ffffffff", 0x18, 0), // mask 1
					createInstructionWithRaw("0000000000000000", 0x00, 0), // mask 1 part 2
					createInstructionWithRaw("5700000000000000", bpf.ALU_AND_K, 0), // AND 1
					createInstructionWithRaw("7700000000000000", bpf.ALU_RSH_K, 0), // RSH 1
					createInstructionWithRaw("18000000ffff0000", 0x18, 0), // mask 2
					createInstructionWithRaw("0000000000000000", 0x00, 0), // mask 2 part 2
					createInstructionWithRaw("5700000000000000", bpf.ALU_AND_K, 0), // AND 2
					createInstructionWithRaw("7700000000000000", bpf.ALU_RSH_K, 0), // RSH 2
				},
				Dependencies: []DependencyInfo{
					{Dependencies: []int{}, DependedBy: []int{2}},        // mask 1
					{Dependencies: []int{}, DependedBy: []int{}},         // mask 1 part 2
					{Dependencies: []int{0}, DependedBy: []int{3}},       // AND 1
					{Dependencies: []int{2}, DependedBy: []int{}},        // RSH 1
					{Dependencies: []int{}, DependedBy: []int{6}},        // mask 2
					{Dependencies: []int{}, DependedBy: []int{}},         // mask 2 part 2
					{Dependencies: []int{4}, DependedBy: []int{7}},       // AND 2
					{Dependencies: []int{6}, DependedBy: []int{}},        // RSH 2
				},
			},
			maskCandidates: []int{0, 4},
			expected:       [][]int{{0, 2}, {4, 6}},
		},
		{
			name: "non-AND opcode - no optimization",
			section: &Section{
				Instructions: []*bpf.Instruction{
					createInstructionWithRaw("18000000ffffffff", 0x18, 0), // mask instruction
					createInstructionWithRaw("0000000000000000", 0x00, 0), // mask part 2
					createInstructionWithRaw("0700000000000000", bpf.ALU_ADD, 0), // ADD operation (not AND)
				},
				Dependencies: []DependencyInfo{
					{Dependencies: []int{}, DependedBy: []int{2}},        // mask depends on nothing, depended by ADD
					{Dependencies: []int{}, DependedBy: []int{}},         // mask part 2
					{Dependencies: []int{0}, DependedBy: []int{}},        // ADD depends on mask
				},
			},
			maskCandidates: []int{0},
			expected:       [][]int{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := findCandidates(tt.section, tt.maskCandidates)
			if len(result) != len(tt.expected) {
				t.Errorf("expected %d candidates, got %d", len(tt.expected), len(result))
				return
			}
			for i, expected := range tt.expected {
				if len(result[i]) != len(expected) {
					t.Errorf("candidate %d: expected length %d, got %d", i, len(expected), len(result[i]))
					continue
				}
				for j, expectedIdx := range expected {
					if result[i][j] != expectedIdx {
						t.Errorf("candidate %d[%d]: expected %d, got %d", i, j, expectedIdx, result[i][j])
					}
				}
			}
		})
	}
}

func TestApplyPeepholeOptimization(t *testing.T) {
	tests := []struct {
		name       string
		section    *Section
		candidates [][]int
		expected   []string // expected Raw values after optimization
	}{
		{
			name: "empty candidates",
			section: &Section{
				Instructions: []*bpf.Instruction{
					createInstructionWithRaw("18000000ffffffff", 0x18, 0),
					createInstructionWithRaw("0000000000000000", 0x00, 0),
				},
			},
			candidates: [][]int{},
			expected:   []string{"18000000ffffffff", "0000000000000000"},
		},
		{
			name: "2-element optimization",
			section: &Section{
				Instructions: []*bpf.Instruction{
					createInstructionWithRaw("18000000ffffffff", 0x18, 0), // mask instruction
					createInstructionWithRaw("0000000000000000", 0x00, 0), // mask part 2
					createInstructionWithRaw("5701000000000000", bpf.ALU_AND_K, 0), // AND operation with dst reg 1
				},
			},
			candidates: [][]int{{0, 2}}, // mask and AND instruction
			expected:   []string{bpf.NOP, bpf.NOP, "bc11000000000000"}, // mask->NOP, mask_part2->NOP, AND->optimized
		},
		{
			name: "3-element optimization",
			section: &Section{
				Instructions: []*bpf.Instruction{
					createInstructionWithRaw("18000000ffffffff", 0x18, 0), // mask instruction
					createInstructionWithRaw("0000000000000000", 0x00, 0), // mask part 2
					createInstructionWithRaw("b723000000000000", bpf.ALU_MOV_K, 0), // MOV operation with dst reg 2, src reg 3
					createInstructionWithRaw("5701000000000000", bpf.ALU_AND_K, 0), // AND operation with dst reg 1
				},
			},
			candidates: [][]int{{0, 3, 2}}, // mask, AND, MOV instruction
			expected:   []string{bpf.NOP, bpf.NOP, bpf.NOP, "bc23000000000000"}, // mask->NOP, mask_part2->NOP, MOV->NOP, AND->optimized with MOV reg
		},
		{
			name: "multiple candidates",
			section: &Section{
				Instructions: []*bpf.Instruction{
					createInstructionWithRaw("18000000ffffffff", 0x18, 0), // mask 1
					createInstructionWithRaw("0000000000000000", 0x00, 0), // mask 1 part 2
					createInstructionWithRaw("5701000000000000", bpf.ALU_AND_K, 0), // AND 1 with dst reg 1
					createInstructionWithRaw("18000000ffff0000", 0x18, 0), // mask 2
					createInstructionWithRaw("0000000000000000", 0x00, 0), // mask 2 part 2
					createInstructionWithRaw("5702000000000000", bpf.ALU_AND_K, 0), // AND 2 with dst reg 2
				},
			},
			candidates: [][]int{{0, 2}, {3, 5}}, // two 2-element optimizations
			expected:   []string{bpf.NOP, bpf.NOP, "bc11000000000000", bpf.NOP, bpf.NOP, "bc22000000000000"},
		},
		{
			name: "mixed 2-element and 3-element optimizations",
			section: &Section{
				Instructions: []*bpf.Instruction{
					createInstructionWithRaw("18000000ffffffff", 0x18, 0), // mask 1
					createInstructionWithRaw("0000000000000000", 0x00, 0), // mask 1 part 2
					createInstructionWithRaw("5701000000000000", bpf.ALU_AND_K, 0), // AND 1 with dst reg 1
					createInstructionWithRaw("18000000ffff0000", 0x18, 0), // mask 2
					createInstructionWithRaw("0000000000000000", 0x00, 0), // mask 2 part 2
					createInstructionWithRaw("b734000000000000", bpf.ALU_MOV_K, 0), // MOV with dst reg 3, src reg 4
					createInstructionWithRaw("5702000000000000", bpf.ALU_AND_K, 0), // AND 2 with dst reg 2
				},
			},
			candidates: [][]int{{0, 2}, {3, 6, 5}}, // 2-element and 3-element optimizations
			expected:   []string{bpf.NOP, bpf.NOP, "bc11000000000000", bpf.NOP, bpf.NOP, bpf.NOP, "bc34000000000000"},
		},
		{
			name: "different register patterns",
			section: &Section{
				Instructions: []*bpf.Instruction{
					createInstructionWithRaw("18000000ffffffff", 0x18, 0), // mask
					createInstructionWithRaw("0000000000000000", 0x00, 0), // mask part 2
					createInstructionWithRaw("5709000000000000", bpf.ALU_AND_K, 0), // AND with dst reg 9
				},
			},
			candidates: [][]int{{0, 2}}, // 2-element optimization
			expected:   []string{bpf.NOP, bpf.NOP, "bc99000000000000"}, // AND->optimized with reg 9
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a copy of the section to avoid modifying the original
			sectionCopy := &Section{
				Instructions: make([]*bpf.Instruction, len(tt.section.Instructions)),
			}
			for i, inst := range tt.section.Instructions {
				sectionCopy.Instructions[i] = inst.Clone()
			}

			// Apply the optimization
			applyPeepholeOptimization(sectionCopy, tt.candidates)

			// Verify the results
			if len(sectionCopy.Instructions) != len(tt.expected) {
				t.Errorf("expected %d instructions, got %d", len(tt.expected), len(sectionCopy.Instructions))
				return
			}

			for i, expectedRaw := range tt.expected {
				if sectionCopy.Instructions[i].Raw != expectedRaw {
					t.Errorf("instruction %d: expected Raw '%s', got '%s'", i, expectedRaw, sectionCopy.Instructions[i].Raw)
				}
			}
		})
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
