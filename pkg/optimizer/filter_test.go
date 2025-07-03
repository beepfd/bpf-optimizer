package optimizer

import (
	"testing"

	"github.com/beepfd/bpf-optimizer/pkg/bpf"
)

func TestApplyConstantPropagation(t *testing.T) {
	tests := []struct {
		name          string
		instructions  []string
		dependencies  []DependencyInfo
		expectedInsts []string
		expectedNOPs  []int
	}{
		{
			name: "basic constant propagation",
			instructions: []string{
				"b70100000a000000", // mov r1, 10
				"6301100000000000", // stx [r1+0], r0
			},
			dependencies: []DependencyInfo{
				{
					Dependencies: []int{},
					DependedBy:   []int{1},
				},
				{
					Dependencies: []int{0},
					DependedBy:   []int{},
				},
			},
			expectedInsts: []string{
				"0500000000000000", // NOP
				"620110000a000000", // st [r1+0], 10
			},
			expectedNOPs: []int{0},
		},
		{
			name: "32-bit constant propagation",
			instructions: []string{
				"b40200000f000000", // mov32 r2, 15
				"6302100000000000", // stx [r2+0], r0
			},
			dependencies: []DependencyInfo{
				{
					Dependencies: []int{},
					DependedBy:   []int{1},
				},
				{
					Dependencies: []int{0},
					DependedBy:   []int{},
				},
			},
			expectedInsts: []string{
				"0500000000000000", // NOP
				"620210000f000000", // st [r2+0], 15
			},
			expectedNOPs: []int{0},
		},
		{
			name: "multiple dependencies - should be propagate",
			instructions: []string{
				"b70100000a000000", // mov r1, 10
				"6301100000000000", // stx [r1+0], r0
				"6301200000000000", // stx [r1+8], r0
			},
			dependencies: []DependencyInfo{
				{
					Dependencies: []int{},
					DependedBy:   []int{1, 2},
				},
				{
					Dependencies: []int{0},
					DependedBy:   []int{},
				},
				{
					Dependencies: []int{0},
					DependedBy:   []int{},
				},
			},
			expectedInsts: []string{
				"0500000000000000", // NOP
				"620110000a000000", // st [r1+0], 10
				"620120000a000000", // st [r1+8], 10
			},
			expectedNOPs: []int{0},
		},
		{
			name: "non-STX dependent - should not propagate",
			instructions: []string{
				"b70100000a000000", // mov r1, 10
				"1f10000000000000", // add r1, r0
			},
			dependencies: []DependencyInfo{
				{
					Dependencies: []int{},
					DependedBy:   []int{1},
				},
				{
					Dependencies: []int{0},
					DependedBy:   []int{},
				},
			},
			expectedInsts: []string{
				"b70100000a000000", // unchanged
				"1f10000000000000", // unchanged
			},
			expectedNOPs: []int{},
		},
		{
			name: "STX with multiple dependencies - should not propagate",
			instructions: []string{
				"b70100000a000000", // mov r1, 10
				"b7020000ff000000", // mov r2, 255
				"6302100000000000", // stx [r2+0], r0
			},
			dependencies: []DependencyInfo{
				{
					Dependencies: []int{},
					DependedBy:   []int{2},
				},
				{
					Dependencies: []int{},
					DependedBy:   []int{2},
				},
				{
					Dependencies: []int{0, 1},
					DependedBy:   []int{},
				},
			},
			expectedInsts: []string{
				"b70100000a000000", // unchanged
				"b7020000ff000000", // unchanged
				"6302100000000000", // unchanged
			},
			expectedNOPs: []int{},
		},
		{
			name: "atomic operations - should not propagate",
			instructions: []string{
				"b70100000a000000", // mov r1, 10
				"db01100000000000", // atomic add [r1+0], r0
			},
			dependencies: []DependencyInfo{
				{
					Dependencies: []int{},
					DependedBy:   []int{1},
				},
				{
					Dependencies: []int{0},
					DependedBy:   []int{},
				},
			},
			expectedInsts: []string{
				"b70100000a000000", // unchanged
				"db01100000000000", // unchanged
			},
			expectedNOPs: []int{},
		},
		{
			name: "complex immediate value",
			instructions: []string{
				"b70100001234abcd", // mov r1, 0xcdab3412
				"6301100000000000", // stx [r1+0], r0
			},
			dependencies: []DependencyInfo{
				{
					Dependencies: []int{},
					DependedBy:   []int{1},
				},
				{
					Dependencies: []int{0},
					DependedBy:   []int{},
				},
			},
			expectedInsts: []string{
				"0500000000000000", // NOP
				"620110001234abcd", // st [r1+0], 0xcdab3412
			},
			expectedNOPs: []int{0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create section with test data
			section := &Section{
				Name:         "test",
				Instructions: make([]*bpf.Instruction, len(tt.instructions)),
				Dependencies: make([]DependencyInfo, len(tt.dependencies)),
			}

			// Parse instructions
			for i, hexStr := range tt.instructions {
				inst, err := bpf.NewInstruction(hexStr)
				if err != nil {
					t.Fatalf("Failed to parse instruction %d: %v", i, err)
				}
				section.Instructions[i] = inst
			}

			// Set dependencies
			copy(section.Dependencies, tt.dependencies)

			// Apply constant propagation
			section.applyConstantPropagation()

			// Check results
			for i, expectedHex := range tt.expectedInsts {
				actualHex := section.Instructions[i].ToHex()
				if actualHex != expectedHex {
					t.Errorf("Instruction %d: expected %s, got %s", i, expectedHex, actualHex)
				}
			}

			// Check NOPs
			for _, nopIdx := range tt.expectedNOPs {
				if !section.Instructions[nopIdx].IsNOP() {
					t.Errorf("Instruction %d should be NOP", nopIdx)
				}
			}

			// Check that non-NOP instructions are not NOPs
			for i := 0; i < len(section.Instructions); i++ {
				shouldBeNOP := false
				for _, nopIdx := range tt.expectedNOPs {
					if i == nopIdx {
						shouldBeNOP = true
						break
					}
				}
				if !shouldBeNOP && section.Instructions[i].IsNOP() {
					t.Errorf("Instruction %d should not be NOP", i)
				}
			}
		})
	}
}
