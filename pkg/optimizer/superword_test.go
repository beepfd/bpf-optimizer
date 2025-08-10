package optimizer

import (
	"reflect"
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
	// Test with actual NOPs (ALU operations that don"t change state)
	instructions := []string{
		"6200000012000000", // ST [r0], 0x12 (index 0)
		"0700000000000000", // r0 += 0 (actual NOP, index 1)
		"0700000000000000", // r0 += 0 (actual NOP, index 2)
		"6a00000034000000", // ST [r0], 0x34 (index 3)
	}

	section := createTestSection(instructions)
	merger := NewSuperwordMerger(section)

	// No jump/load between indices 0 and 3 (ALU NOPs should not be barriers)
	result := merger.hasInterveningJumpOrLoad(0, 3)
	if result {
		t.Error("Expected no intervening jump/load, but got true")
	}

	// Test with actual jump instruction
	instructions[1] = "0500050000000000" // JMP +5
	section = createTestSection(instructions)
	merger = NewSuperwordMerger(section)

	result = merger.hasInterveningJumpOrLoad(0, 3)
	if !result {
		t.Error("Expected intervening jump, but got false")
	}

	// Test with jump that has zero offset (still a barrier)
	instructions[1] = "0500000000000000" // JMP +0 (goto +0)
	section = createTestSection(instructions)
	merger = NewSuperwordMerger(section)

	result = merger.hasInterveningJumpOrLoad(0, 3)
	if !result {
		t.Error("Expected intervening jump (even goto +0, but got false")
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

	// Due to capacity constraints, 4 32-bit instructions with 64-bit capacity
	// should be split into 2 groups of 2 instructions each
	if len(candidates) != 2 {
		t.Errorf("Expected 2 candidate groups (due to capacity constraint), got %d", len(candidates))
		for i, candidate := range candidates {
			t.Logf("Candidate %d: %v", i, candidate)
		}
	}

	if len(candidates) >= 2 {
		// First group should be [0, 1]
		expected1 := []int{0, 1}
		if len(candidates[0]) != len(expected1) {
			t.Errorf("Expected first candidate length %d, got %d", len(expected1), len(candidates[0]))
		} else {
			for i, expectedIdx := range expected1 {
				if candidates[0][i] != expectedIdx {
					t.Errorf("First candidate[%d]: expected %d, got %d", i, expectedIdx, candidates[0][i])
				}
			}
		}
		
		// Second group should be [2, 3]
		expected2 := []int{2, 3}
		if len(candidates[1]) != len(expected2) {
			t.Errorf("Expected second candidate length %d, got %d", len(expected2), len(candidates[1]))
		} else {
			for i, expectedIdx := range expected2 {
				if candidates[1][i] != expectedIdx {
					t.Errorf("Second candidate[%d]: expected %d, got %d", i, expectedIdx, candidates[1][i])
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
	// Set up store candidates for the section
	section.StoreCandidates = []int{0, 1}
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
	// Set up store candidates for the section
	section.StoreCandidates = []int{0, 1, 3, 4} // indices of store instructions
	merger := NewSuperwordMerger(section)

	merger.ApplySuperwordMergeWithCandidates()

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
	// Note: 0500000000000000 naturally has IsNOP() == true
	if section.Instructions[2].Raw != "0500000000000000" {
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
	merger.ApplySuperwordMergeWithCandidates()

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

// TestOffsetParsing tests if BPF instruction offset parsing works correctly
func TestOffsetParsing(t *testing.T) {
	// Debug test to verify offset parsing from Issue #21
	testCases := []struct {
		hex            string
		expectedOffset int16
		description    string
	}{
		{"7206f70f28000000", 0x0ff7, "Issue #21 instruction 0: *(u8 *)(r6 + 0xff7) = 0x28"},
		{"7206f60f20000000", 0x0ff6, "Issue #21 instruction 2: *(u8 *)(r6 + 0xff6) = 0x20"},
		{"7200000028000000", 0x0000, "Simple case: *(u8 *)(r0 + 0) = 0x28"},
		{"7200010020000000", 0x0001, "Simple case: *(u8 *)(r0 + 1) = 0x20"},
	}

	for _, tc := range testCases {
		inst := createTestInstruction(tc.hex)
		t.Logf("%s", tc.description)
		t.Logf("  Raw: %s", inst.Raw)
		t.Logf("  Parsed offset: 0x%04x (expected: 0x%04x)", inst.Offset, tc.expectedOffset)
		t.Logf("  Offset match: %t", inst.Offset == tc.expectedOffset)

		if inst.Offset != tc.expectedOffset {
			t.Errorf("Offset parsing error: expected 0x%04x, got 0x%04x", tc.expectedOffset, inst.Offset)
		}
	}
}

// TestJumpInstructionDetection tests if jump instruction detection works correctly
func TestJumpInstructionDetection(t *testing.T) {
	// Debug test to verify jump instruction detection logic
	jumpInst := createTestInstruction("0500000000000000") // goto +0x0

	t.Logf("Jump instruction analysis:")
	t.Logf("  Raw: %s", jumpInst.Raw)
	t.Logf("  Opcode: 0x%02x", jumpInst.Opcode)
	t.Logf("  Class: 0x%02x", jumpInst.Opcode&0x07)
	t.Logf("  IsNOP: %t", jumpInst.IsNOP())

	class := jumpInst.Opcode & 0x07
	isJump := class == bpf.BPF_LDX || class == bpf.BPF_JMP || class == 0x06

	t.Logf("  BPF_JMP constant: 0x%02x", bpf.BPF_JMP)
	t.Logf("  BPF_LDX constant: 0x%02x", bpf.BPF_LDX)
	t.Logf("  Should be detected as jump/load: %t", isJump)

	if !isJump {
		t.Error("Jump instruction should be detected as jump/load instruction")
	}
}

// TestSuperwordMergeBugReproduction reproduces the bug described in GitHub Issue #21
// https://github.com/beepfd/bpf-optimizer/issues/21
func TestSuperwordMergeBugReproduction(t *testing.T) {
	// Original instructions from the issue:
	// 513:	72 06 f7 0f 28 00 00 00	*(u8 *)(r6 + 0xff7) = 0x28
	// 514:	05 00 00 00 00 00 00 00	goto +0x0 <LBB1_95+0x1e8>
	// 515:	72 06 f6 0f 20 00 00 00	*(u8 *)(r6 + 0xff6) = 0x20

	instructions := []string{
		"7206f70f28000000", // *(u8 *)(r6 + 0xff7) = 0x28 (index 0)
		"0500000000000000", // goto +0x0 (jump instruction, index 1)
		"7206f60f20000000", // *(u8 *)(r6 + 0xff6) = 0x20 (index 2)
	}

	section := createTestSection(instructions)
	originalInst0 := section.Instructions[0].Raw
	originalInst1 := section.Instructions[1].Raw
	originalInst2 := section.Instructions[2].Raw

	merger := NewSuperwordMerger(section)

	// Apply superword merge with store candidates (indices 0 and 2)
	storeCandidates := []int{0, 2}
	merger.section.StoreCandidates = storeCandidates
	merger.ApplySuperwordMergeWithCandidates()

	t.Logf("Before optimization:")
	t.Logf("  Instruction 0: %s", originalInst0)
	t.Logf("  Instruction 1: %s", originalInst1)
	t.Logf("  Instruction 2: %s", originalInst2)

	t.Logf("After optimization:")
	t.Logf("  Instruction 0: %s (IsNOP: %t)", section.Instructions[0].Raw, section.Instructions[0].IsNOP())
	t.Logf("  Instruction 1: %s (IsNOP: %t)", section.Instructions[1].Raw, section.Instructions[1].IsNOP())
	t.Logf("  Instruction 2: %s (IsNOP: %t)", section.Instructions[2].Raw, section.Instructions[2].IsNOP())

	// Assertions to detect the bug:

	// 1. The jump instruction should NOT be modified
	if section.Instructions[1].Raw != originalInst1 {
		t.Errorf("Bug detected: Jump instruction was incorrectly modified")
		t.Errorf("  Expected: %s", originalInst1)
		t.Errorf("  Got: %s", section.Instructions[1].Raw)
	}

	// 2. Store instructions should NOT be merged because they have a jump instruction between them
	// This is the core bug - the algorithm should detect the intervening jump and avoid merging
	if section.Instructions[0].IsNOP() || section.Instructions[2].IsNOP() {
		t.Errorf("Bug detected: Store instructions were incorrectly merged despite intervening jump")
		t.Errorf("  Instruction 0 IsNOP: %t (should be false)", section.Instructions[0].IsNOP())
		t.Errorf("  Instruction 2 IsNOP: %t (should be false)", section.Instructions[2].IsNOP())
	}

	// 3. The offsets are not consecutive (0xff7 and 0xff6) so they should not be merged anyway
	// ff7 = 4087, ff6 = 4086 (little endian, so offset difference should be -1, not +1
	if section.Instructions[0].Raw != originalInst0 {
		t.Errorf("Bug detected: First store instruction was incorrectly modified")
		t.Errorf("  Expected: %s", originalInst0)
		t.Errorf("  Got: %s", section.Instructions[0].Raw)
	}

	if section.Instructions[2].Raw != originalInst2 {
		t.Errorf("Bug detected: Second store instruction was incorrectly modified")
		t.Errorf("  Expected: %s", originalInst2)
		t.Errorf("  Got: %s", section.Instructions[2].Raw)
	}
}

// TestSuperwordMergeWithInterveningJump tests that merge is correctly blocked by intervening jump
func TestSuperwordMergeWithInterveningJump(t *testing.T) {
	// Test that superword merge respects intervening jump instructions
	instructions := []string{
		"7200000028000000", // *(u8 *)(r0 + 0) = 0x28 (index 0)
		"0500000000000000", // goto +0x0 (jump instruction, index 1)
		"7200010020000000", // *(u8 *)(r0 + 1) = 0x20 (index 2)
	}

	section := createTestSection(instructions)
	originalInst0 := section.Instructions[0].Raw
	originalInst1 := section.Instructions[1].Raw
	originalInst2 := section.Instructions[2].Raw

	merger := NewSuperwordMerger(section)

	// Apply superword merge with store candidates
	storeCandidates := []int{0, 2}
	merger.section.StoreCandidates = storeCandidates
	merger.ApplySuperwordMergeWithCandidates()

	t.Logf("After optimization:")
	t.Logf("  Instruction 0: %s (IsNOP: %t, expected: %s)", section.Instructions[0].Raw, section.Instructions[0].IsNOP(), originalInst0)
	t.Logf("  Instruction 1: %s (IsNOP: %t, expected: %s)", section.Instructions[1].Raw, section.Instructions[1].IsNOP(), originalInst1)
	t.Logf("  Instruction 2: %s (IsNOP: %t, expected: %s)", section.Instructions[2].Raw, section.Instructions[2].IsNOP(), originalInst2)

	// Instructions should remain unchanged due to intervening jump
	if section.Instructions[0].Raw != originalInst0 {
		t.Error("First store instruction should not be modified due to intervening jump")
	}

	if section.Instructions[1].Raw != originalInst1 {
		t.Error("Jump instruction should not be modified")
	}

	if section.Instructions[2].Raw != originalInst2 {
		t.Error("Second store instruction should not be modified due to intervening jump")
	}

	// Store instructions (0 and 2) should not be converted to NOP when merge is blocked by jump
	// Jump instruction (1) can naturally be IsNOP() = true as it"s "0500000000000000"
	if section.Instructions[0].IsNOP() {
		t.Errorf("Instruction 0 (store) should not be NOP when merge is blocked by jump")
	}
	if section.Instructions[2].IsNOP() {
		t.Errorf("Instruction 2 (store) should not be NOP when merge is blocked by jump")
	}
}

// TestSuperwordMergeNonConsecutiveOffsets tests merge behavior with non-consecutive offsets
func TestSuperwordMergeNonConsecutiveOffsets(t *testing.T) {
	// Test instructions with non-consecutive offsets that should not be merged
	instructions := []string{
		"7200000028000000", // *(u8 *)(r0 + 0) = 0x28 (index 0)
		"7200020020000000", // *(u8 *)(r0 + 2) = 0x20 (index 1) - gap at offset 1
	}

	section := createTestSection(instructions)
	originalInst0 := section.Instructions[0].Raw
	originalInst1 := section.Instructions[1].Raw

	merger := NewSuperwordMerger(section)

	// Apply superword merge with store candidates
	storeCandidates := []int{0, 1}
	merger.section.StoreCandidates = storeCandidates
	merger.ApplySuperwordMergeWithCandidates()

	// Instructions should remain unchanged due to non-consecutive offsets
	if section.Instructions[0].Raw != originalInst0 {
		t.Error("First store instruction should not be modified due to non-consecutive offsets")
	}

	if section.Instructions[1].Raw != originalInst1 {
		t.Error("Second store instruction should not be modified due to non-consecutive offsets")
	}

	// No instructions should be converted to NOP
	for i, inst := range section.Instructions {
		if inst.IsNOP() {
			t.Errorf("Instruction %d should not be NOP when merge is not possible", i)
		}
	}
}

// TestSuperwordMergeIssue21SpecificOffsets tests the specific offset case from Issue #21
func TestSuperwordMergeIssue21SpecificOffsets(t *testing.T) {
	// Test the exact scenario from Issue #21: 0xff7, jump, 0xff6
	// These instructions should NOT be merged due to intervening jump AND wrong execution order
	instructions := []string{
		"7206f70f28000000", // *(u8 *)(r6 + 0xff7) = 0x28
		"0500000000000000", // goto +0x0 (jump instruction)
		"7206f60f20000000", // *(u8 *)(r6 + 0xff6) = 0x20 - comes AFTER the first one!
	}

	section := createTestSection(instructions)
	originalInst0 := section.Instructions[0].Raw
	originalInst1 := section.Instructions[1].Raw
	originalInst2 := section.Instructions[2].Raw

	t.Logf("BEFORE optimization:")
	t.Logf("  Instruction 0: %s, offset: 0x%04x", section.Instructions[0].Raw, section.Instructions[0].Offset)
	t.Logf("  Instruction 1: %s, offset: 0x%04x", section.Instructions[1].Raw, section.Instructions[1].Offset)
	t.Logf("  Instruction 2: %s, offset: 0x%04x", section.Instructions[2].Raw, section.Instructions[2].Offset)

	merger := NewSuperwordMerger(section)

	// Apply superword merge with store candidates (indices 0 and 2, skipping jump at 1)
	storeCandidates := []int{0, 2}
	merger.section.StoreCandidates = storeCandidates
	merger.ApplySuperwordMergeWithCandidates()

	t.Logf("AFTER optimization:")
	t.Logf("  Instruction 0: %s, offset: 0x%04x", section.Instructions[0].Raw, section.Instructions[0].Offset)
	t.Logf("  Instruction 1: %s, offset: 0x%04x", section.Instructions[1].Raw, section.Instructions[1].Offset)
	t.Logf("  Instruction 2: %s, offset: 0x%04x", section.Instructions[2].Raw, section.Instructions[2].Offset)

	t.Logf("Offset analysis:")
	t.Logf("  Store instruction 0 offset: 0x%04x", section.Instructions[0].Offset)
	t.Logf("  Store instruction 2 offset: 0x%04x", section.Instructions[2].Offset)
	t.Logf("  Offset difference: %d", int(section.Instructions[2].Offset)-int(section.Instructions[0].Offset))
	t.Logf("  Expected for consecutive 8-bit stores: +1")

	// Instructions should remain unchanged due to intervening jump and wrong order
	if section.Instructions[0].Raw != originalInst0 {
		t.Error("First store instruction should not be modified due to intervening jump")
	}

	if section.Instructions[1].Raw != originalInst1 {
		t.Error("Jump instruction should not be modified")
	}

	if section.Instructions[2].Raw != originalInst2 {
		t.Error("Second store instruction should not be modified due to intervening jump")
	}

	// Store instructions should not be converted to NOP (jump instruction can be NOP naturally)
	if section.Instructions[0].IsNOP() {
		t.Error("First store instruction should not be NOP when merge is blocked by jump")
	}
	if section.Instructions[2].IsNOP() {
		t.Error("Second store instruction should not be NOP when merge is blocked by jump")
	}
}

func TestSuperwordMerger_analyseGroup(t *testing.T) {
	type fields struct {
		section *Section
	}
	type args struct {
		group   []string
		indices []int
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   [][]int
	}{
		{
			name: "test 1: consecutive 32-bit stores to same register",
			args: args{
				group:   []string{"72074f0000000000", "72074e0000000000", "72074d0000000000", "72074c0000000000", "72074b0000000000", "72074a0000000000", "7207490000000000", "7207480000000000", "7207470000000000", "7207460000000000", "7207450000000000", "7207440000000000", "7207430000000000", "7207420000000000", "7207410000000000", "7207400000000000", "72073f0000000000", "72073e0000000000", "72073d0000000000", "72073c0000000000", "72073b0000000000", "72073a0000000000", "7207390000000000", "7207380000000000", "7207370000000000", "7207360000000000", "7207350000000000", "7207340000000000", "7207330000000000", "7207320000000000", "7207310000000000", "7207300000000000", "72072f0000000000", "72072e0000000000", "72072d0000000000", "72072c0000000000", "72072b0000000000", "72072a0000000000", "7207290000000000", "7207280000000000", "7207270000000000", "7207260000000000", "7207250000000000", "7207240000000000", "7207230000000000", "7207220000000000", "7207210000000000", "7207200000000000", "72071f0000000000", "72071e0000000000", "72071d0000000000", "72071c0000000000", "72071b0000000000", "72071a0000000000", "7207190000000000", "7207180000000000", "7207170000000000", "7207160000000000", "7207150000000000", "7207140000000000", "7207130000000000", "7207120000000000", "7207110000000000", "7207100000000000", "72070f0000000000", "72070e0000000000", "72070d0000000000", "72070c0000000000", "72070b0000000000", "72070a0000000000", "7207090000000000", "7207080000000000", "7207070000000000", "7207060000000000", "7207050000000000", "7207040000000000", "7207030000000000", "7207020000000000", "7207010000000000", "7207000000000000"},
				indices: []int{2, 64, 65, 68, 69, 81, 97, 333, 362, 405, 430, 500, 502, 504, 506, 507, 508, 510, 511, 513, 515, 750, 751, 752, 753, 967, 968, 969, 970, 972, 1010, 1011, 1012, 1013, 1014, 1015, 1016, 1017, 1018, 1019, 1020, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1090, 1257, 1258, 1259, 1260, 1396, 1452, 1453, 1454, 1531, 1532, 1533, 1534, 1590, 1591, 1592, 1593, 1594, 1595, 1596, 1597, 1598, 1599, 1600, 1601, 1602, 1603, 1604, 1605, 1606, 1607, 1608, 1609, 1610, 1611, 1612, 1613, 1614, 1615, 1616, 1617, 1618, 1619, 1620, 1621, 1622, 1623, 1624, 1625, 1626, 1627, 1628, 1629, 1630, 1631, 1632, 1633, 1634, 1635, 1636, 1637, 1638, 1639, 1640, 1641, 1642, 1643, 1644, 1645, 1646, 1647, 1648, 1649, 1650, 1651, 1652, 1653, 1654, 1655, 1656, 1657, 1658, 1659, 1660, 1661, 1662, 1663, 1664, 1665, 1666, 1667, 1668, 1669, 1822, 1825, 2749, 2800, 2923, 3185, 3195, 3223, 3237, 3286, 3288, 3313, 3338, 3411, 3413, 3415, 3417, 3418, 3419, 3421, 3422, 3424, 3426, 3434, 3435, 3436, 3437, 3438, 3442, 3562, 3588, 3618, 3619, 3620, 3621, 3622, 3623, 3624, 3625, 3626, 3627, 3628, 3629, 3630, 3631, 3632, 3633, 3634, 3635, 3636, 3637, 3638, 3639, 3640, 3641, 3642, 3643, 3644, 3645, 3646, 3647, 3648, 3649, 3650, 3724, 4458, 4468, 4495, 4506, 4517, 4528, 4539, 4550, 4561, 4572, 4583, 4594, 4605, 4616, 4627, 4638, 4649, 4659, 4669, 4801, 4811, 4812, 4813, 4836, 4840, 4917, 5091, 5130, 5191, 5277, 5287, 5315, 5329, 5377, 5379, 5404, 5466},
			},
			want: [][]int{{1090, 1088, 1087, 1086, 1085, 1084, 1083, 1082}, {1087, 1086}, {1085, 1084, 1083, 1082}, {1083, 1082}, {1081, 1080, 1079, 1078, 1077, 1076, 1075, 1074}, {1079, 1078}, {1077, 1076, 1075, 1074}, {1075, 1074}, {1073, 1072, 1071, 1070, 1069, 1068, 1067, 1066}, {1071, 1070}, {1069, 1068, 1067, 1066}, {1067, 1066}, {1065, 1064, 1063, 1062, 1061, 1060, 1059, 1058}, {1063, 1062}, {1061, 1060, 1059, 1058}, {1059, 1058}, {1057, 1056, 1055, 1054, 1053, 1052, 1051, 1050}, {1055, 1054}, {1053, 1052, 1051, 1050}, {1051, 1050}, {1049, 1048, 1047, 1046, 1045, 1044, 1043, 1042}, {1047, 1046}, {1045, 1044, 1043, 1042}, {1043, 1042}, {1041, 1040, 1039, 1038, 1037, 1036, 1035, 1034}, {1039, 1038}, {1037, 1036, 1035, 1034}, {1035, 1034}, {1033, 1032, 1031, 1030, 1029, 1028, 1027, 1026}, {1031, 1030}, {1029, 1028, 1027, 1026}, {1027, 1026}, {1025, 1024, 1023, 1022, 1021, 1020, 1019, 1018}, {1023, 1022}, {1021, 1020, 1019, 1018}, {1019, 1018}, {1017, 1016, 1015, 1014, 1013, 1012, 1011, 1010}, {1015, 1014}, {1013, 1012, 1011, 1010}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := &SuperwordMerger{
				section: tt.fields.section,
			}
			if got := sm.analyseGroup(tt.args.group, tt.args.indices); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("analyseGroup() = %v, want %v", got, tt.want)
			}
		})
	}
}
