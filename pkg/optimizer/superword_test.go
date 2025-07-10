package optimizer

import (
	"testing"

	"github.com/beepfd/bpf-optimizer/pkg/bpf"
)

// createTestInstruction creates a test instruction from hex string
func createTestInstruction(hex string) *bpf.Instruction {
	inst, err := bpf.NewInstruction(hex)
	if err != nil {
		panic(err)
	}
	return inst
}

// createTestSection creates a test section with given instructions
func createTestSection(instructions []string) *Section {
	section := &Section{
		Name:         "test",
		Instructions: make([]*bpf.Instruction, 0),
		Dependencies: make([]DependencyInfo, 0),
	}

	for _, hex := range instructions {
		inst := createTestInstruction(hex)
		section.Instructions = append(section.Instructions, inst)
		section.Dependencies = append(section.Dependencies, DependencyInfo{
			Dependencies: make([]int, 0),
			DependedBy:   make([]int, 0),
		})
	}

	return section
}

// Test helper functions
func TestGetCap(t *testing.T) {
	tests := []struct {
		offset   int16
		expected int
	}{
		{0, 64},  // 8-byte aligned
		{8, 64},  // 8-byte aligned
		{4, 32},  // 4-byte aligned
		{12, 32}, // 4-byte aligned
		{2, 16},  // 2-byte aligned
		{6, 16},  // 2-byte aligned
		{1, 8},   // 1-byte aligned
		{3, 8},   // 1-byte aligned
	}

	for _, test := range tests {
		result := getCap(test.offset)
		if result != test.expected {
			t.Errorf("getCap(%d) = %d, expected %d", test.offset, result, test.expected)
		}
	}
}

func TestGetSize(t *testing.T) {
	tests := []struct {
		hex      string
		expected int
	}{
		{"6200000000000000", 32}, // BPF_ST | BPF_W (32-bit): 0x62 = 0110 0010, mask 0x18 = 0x00 -> 32-bit
		{"6a00000000000000", 16}, // BPF_ST | BPF_H (16-bit): 0x6a = 0110 1010, mask 0x18 = 0x08 -> 16-bit
		{"7200000000000000", 8},  // BPF_ST | BPF_B (8-bit): 0x72 = 0111 0010, mask 0x18 = 0x10 -> 8-bit
		{"7a00000000000000", 64}, // BPF_ST | BPF_DW (64-bit): 0x7a = 0111 1010, mask 0x18 = 0x18 -> 64-bit
	}

	for _, test := range tests {
		inst := createTestInstruction(test.hex)
		result := getSize(inst)
		if result != test.expected {
			t.Errorf("getSize(%s) = %d, expected %d", test.hex, result, test.expected)
		}
	}
}

func TestGetSizeMask(t *testing.T) {
	tests := []struct {
		size     int
		expected uint8
	}{
		{8, 0x10},  // BPF_B
		{16, 0x08}, // BPF_H
		{32, 0x00}, // BPF_W
		{64, 0x18}, // BPF_DW
	}

	for _, test := range tests {
		result := getSizeMask(test.size)
		if result != test.expected {
			t.Errorf("getSizeMask(%d) = 0x%02x, expected 0x%02x", test.size, result, test.expected)
		}
	}
}

func TestIsSubset(t *testing.T) {
	tests := []struct {
		a        []int
		b        []int
		expected bool
	}{
		{[]int{1, 2}, []int{1, 2, 3, 4}, true},
		{[]int{1, 3}, []int{1, 2, 3, 4}, true},
		{[]int{1, 2, 3, 4}, []int{1, 2}, false}, // a is not smaller than b
		{[]int{1, 5}, []int{1, 2, 3, 4}, false}, // 5 not in b
		{[]int{}, []int{1, 2, 3}, true},         // empty set is subset
	}

	for _, test := range tests {
		result := isSubset(test.a, test.b)
		if result != test.expected {
			t.Errorf("isSubset(%v, %v) = %t, expected %t", test.a, test.b, result, test.expected)
		}
	}
}

func TestHasInterveningJumpOrLoad(t *testing.T) {
	// Test with jump instruction between stores
	instructions := []string{
		"6200000012000000", // ST [r0], 0x12 (index 0)
		"0500000000000000", // NOP (index 1)
		"0500000000000000", // NOP (index 2)
		"6a00000034000000", // ST [r0], 0x34 (index 3)
	}

	section := createTestSection(instructions)
	merger := NewSuperwordMerger(section)

	// No jump/load between indices 0 and 3
	result := merger.hasInterveningJumpOrLoad(0, 3)
	if result {
		t.Error("Expected no intervening jump/load, but got true")
	}

	// Add a jump instruction
	instructions[1] = "0500050000000000" // JMP +5
	section = createTestSection(instructions)
	merger = NewSuperwordMerger(section)

	result = merger.hasInterveningJumpOrLoad(0, 3)
	if !result {
		t.Error("Expected intervening jump, but got false")
	}
}

func TestEliminateOverlappingCandidates(t *testing.T) {
	section := createTestSection([]string{"6200000012000000"})
	merger := NewSuperwordMerger(section)

	candidates := [][]int{
		{1, 2, 3, 4}, // larger set
		{1, 2},       // subset of first (should be removed)
		{3, 4},       // subset of first (should be removed)
		{5, 6},       // independent set
	}

	result := merger.eliminateOverlappingCandidates(candidates)

	expected := [][]int{
		{1, 2, 3, 4},
		{5, 6},
	}

	if len(result) != len(expected) {
		t.Errorf("Expected %d candidates after elimination, got %d", len(expected), len(result))
	}

	for i, expectedCandidate := range expected {
		if i >= len(result) {
			t.Errorf("Missing candidate %d", i)
			continue
		}

		if len(result[i]) != len(expectedCandidate) {
			t.Errorf("Candidate %d has wrong length: expected %d, got %d", i, len(expectedCandidate), len(result[i]))
			continue
		}

		for j, expectedIdx := range expectedCandidate {
			if result[i][j] != expectedIdx {
				t.Errorf("Candidate %d[%d]: expected %d, got %d", i, j, expectedIdx, result[i][j])
			}
		}
	}
}

func TestAnalyse(t *testing.T) {
	section := createTestSection([]string{"6200000012000000"})
	merger := NewSuperwordMerger(section)

	// Test case: consecutive 32-bit stores to same register with consecutive offsets
	group := []MemoryOperation{
		{Index: 0, DstReg: 0, Offset: 0, Size: 32, Capacity: 64},
		{Index: 1, DstReg: 0, Offset: 4, Size: 32, Capacity: 64},
		{Index: 2, DstReg: 0, Offset: 8, Size: 32, Capacity: 64},
		{Index: 3, DstReg: 0, Offset: 12, Size: 32, Capacity: 64},
	}

	candidates := merger.analyse(group)

	// With 4 elements, processGroup should create 1 candidate of size 4
	if len(candidates) != 1 {
		t.Errorf("Expected 1 candidate group, got %d", len(candidates))
		for i, candidate := range candidates {
			t.Logf("Candidate %d: %v", i, candidate)
		}
	}

	if len(candidates) > 0 {
		expected := []int{0, 1, 2, 3}
		if len(candidates[0]) != len(expected) {
			t.Errorf("Expected candidate length %d, got %d", len(expected), len(candidates[0]))
		} else {
			for i, expectedIdx := range expected {
				if candidates[0][i] != expectedIdx {
					t.Errorf("Candidate[%d]: expected %d, got %d", i, expectedIdx, candidates[0][i])
				}
			}
		}
	}
}

func TestAnalyseNonConsecutive(t *testing.T) {
	section := createTestSection([]string{"6200000012000000"})
	merger := NewSuperwordMerger(section)

	// Test case: non-consecutive offsets (should not be merged)
	group := []MemoryOperation{
		{Index: 0, DstReg: 0, Offset: 0, Size: 32, Capacity: 64},
		{Index: 1, DstReg: 0, Offset: 8, Size: 32, Capacity: 64}, // gap at offset 4
	}

	candidates := merger.analyse(group)

	if len(candidates) != 0 {
		t.Errorf("Expected 0 candidates for non-consecutive offsets, got %d", len(candidates))
	}
}

func TestAnalyseDifferentRegisters(t *testing.T) {
	section := createTestSection([]string{"6200000012000000"})
	merger := NewSuperwordMerger(section)

	// Test case: different destination registers (should not be merged)
	group := []MemoryOperation{
		{Index: 0, DstReg: 0, Offset: 0, Size: 32, Capacity: 64},
		{Index: 1, DstReg: 1, Offset: 4, Size: 32, Capacity: 64}, // different register
	}

	candidates := merger.analyse(group)

	if len(candidates) != 0 {
		t.Errorf("Expected 0 candidates for different registers, got %d", len(candidates))
	}
}

func TestApplyMergesSimple(t *testing.T) {
	// Test with two consecutive 32-bit stores
	instructions := []string{
		"6200000012000000", // ST [r0+0], 0x12
		"6200040034000000", // ST [r0+4], 0x34
	}

	section := createTestSection(instructions)
	merger := NewSuperwordMerger(section)

	// Apply merge for indices 0 and 1
	candidates := [][]int{{0, 1}}
	merger.applyMerges(candidates)

	// Check that first instruction was modified (merged)
	if section.Instructions[0].IsNOP() {
		t.Error("First instruction should not be NOP after merge")
	}

	// Check that second instruction was set to NOP
	if !section.Instructions[1].IsNOP() {
		t.Error("Second instruction should be NOP after merge")
	}

	// Check that the merged instruction has correct size (64-bit)
	mergedInst := section.Instructions[0]
	if mergedInst.Opcode&0x18 != 0x18 { // Should be BPF_DW (64-bit)
		t.Errorf("Merged instruction should be 64-bit, got size mask 0x%02x", mergedInst.Opcode&0x18)
	}
}

func TestApplySuperwordMergeIntegration(t *testing.T) {
	// Integration test with complete superword merge
	instructions := []string{
		"6200000012000000", // ST [r0+0], 0x12
		"6200040034000000", // ST [r0+4], 0x34
		"0500000000000000", // NOP (separator)
		"6200080056000000", // ST [r0+8], 0x56
		"62000c0078000000", // ST [r0+12], 0x78
	}

	section := createTestSection(instructions)
	merger := NewSuperwordMerger(section)

	merger.ApplySuperwordMergeWithCandidates(nil)

	// Check that instructions 0 and 1 were merged
	if section.Instructions[0].IsNOP() {
		t.Error("First instruction should not be NOP after merge")
	}
	if !section.Instructions[1].IsNOP() {
		t.Error("Second instruction should be NOP after merge")
	}

	// Check that instructions 3 and 4 were merged
	if section.Instructions[3].IsNOP() {
		t.Error("Fourth instruction should not be NOP after merge")
	}
	if !section.Instructions[4].IsNOP() {
		t.Error("Fifth instruction should be NOP after merge")
	}

	// Check that separator instruction (index 2) is unchanged
	if section.Instructions[2].IsNOP() {
		t.Error("Separator instruction should not be modified")
	}
}

func TestApplySuperwordMergeNoMerge(t *testing.T) {
	// Test case where no merge should happen
	instructions := []string{
		"6200000012000000", // ST [r0+0], 0x12
		"6200080034000000", // ST [r0+8], 0x34 (gap at offset 4, should not merge)
	}

	section := createTestSection(instructions)
	originalInst0 := section.Instructions[0].Raw
	originalInst1 := section.Instructions[1].Raw

	merger := NewSuperwordMerger(section)
	merger.ApplySuperwordMergeWithCandidates(nil)

	// Check that instructions were not modified
	if section.Instructions[0].Raw != originalInst0 {
		t.Error("First instruction should not be modified when no merge is possible")
	}
	if section.Instructions[1].Raw != originalInst1 {
		t.Error("Second instruction should not be modified when no merge is possible")
	}
}

func TestProcessGroup(t *testing.T) {
	section := createTestSection([]string{"6200000012000000"})
	merger := NewSuperwordMerger(section)

	tests := []struct {
		groupSize int
		expected  int // number of candidates that should be generated
	}{
		{8, 1}, // 8 elements -> 1 candidate of size 8
		{7, 2}, // 7 elements -> 1 candidate of size 4, 1 candidate of size 2
		{6, 2}, // 6 elements -> 1 candidate of size 4, 1 candidate of size 2
		{5, 1}, // 5 elements -> 1 candidate of size 4
		{4, 1}, // 4 elements -> 1 candidate of size 4
		{3, 1}, // 3 elements -> 1 candidate of size 2
		{2, 1}, // 2 elements -> 1 candidate of size 2
		{1, 0}, // 1 element -> no candidates
	}

	for _, test := range tests {
		candidates := [][]int{}
		group := make([]int, test.groupSize)
		for i := range group {
			group[i] = i
		}

		merger.processGroup(group, &candidates)

		if len(candidates) != test.expected {
			t.Errorf("processGroup with %d elements: expected %d candidates, got %d",
				test.groupSize, test.expected, len(candidates))
		}
	}
}
