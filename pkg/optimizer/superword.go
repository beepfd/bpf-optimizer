package optimizer

import (
	"fmt"
	"sort"

	"github.com/beepfd/bpf-optimizer/pkg/bpf"
)

// SuperwordMerger handles superword-level merge optimization
type SuperwordMerger struct {
	section *Section
}

// NewSuperwordMerger creates a new SuperwordMerger instance
func NewSuperwordMerger(section *Section) *SuperwordMerger {
	return &SuperwordMerger{
		section: section,
	}
}

// MemoryOperation represents a memory operation for analysis
type MemoryOperation struct {
	Index    int
	DstReg   uint8
	Offset   int16
	Size     int
	Capacity int
	Raw      string
}

// getCap calculates the memory alignment capacity based on offset
func getCap(offset int16) int {
	if offset%8 == 0 {
		return 64
	} else if offset%4 == 0 {
		return 32
	} else if offset%2 == 0 {
		return 16
	} else {
		return 8
	}
}

// getSize extracts the memory operation size from instruction
func getSize(inst *bpf.Instruction) int {
	mask := inst.Opcode & 0x18
	switch mask {
	case 0x00:
		return 32
	case 0x08:
		return 16
	case 0x10:
		return 8
	case 0x18:
		return 64
	default:
		return 32
	}
}

// getSizeMask converts size to BPF size mask
func getSizeMask(size int) uint8 {
	switch size {
	case 8:
		return 0x10
	case 16:
		return 0x08
	case 32:
		return 0x00
	case 64:
		return 0x18
	default:
		return 0x00
	}
}

// MergeCandidate represents a group of instructions that can be merged
type MergeCandidate struct {
	Indices []int
	Size    int
	NewSize int
}

// analyse identifies merge candidates from a group of memory operations
// This implementation closely follows the Python version's logic
func (sm *SuperwordMerger) analyse(group []MemoryOperation) [][]int {
	if len(group) < 2 {
		return nil
	}

	// Create arrays for sorting (similar to Python's numpy arrays)
	dsts := make([]uint8, len(group))
	offs := make([]int16, len(group))
	sizes := make([]int, len(group))
	indices := make([]int, len(group))

	for i, op := range group {
		dsts[i] = op.DstReg
		offs[i] = op.Offset
		sizes[i] = op.Size
		indices[i] = op.Index
	}

	// Sort by destination register and offset (lexsort equivalent)
	type sortData struct {
		dst, size int
		off       int16
		index     int
	}

	sortSlice := make([]sortData, len(group))
	for i := range group {
		sortSlice[i] = sortData{
			dst:   int(dsts[i]),
			off:   offs[i],
			size:  sizes[i],
			index: indices[i],
		}
	}

	sort.Slice(sortSlice, func(i, j int) bool {
		if sortSlice[i].dst != sortSlice[j].dst {
			return sortSlice[i].dst < sortSlice[j].dst
		}
		return sortSlice[i].off < sortSlice[j].off
	})

	// Extract sorted data
	for i, data := range sortSlice {
		dsts[i] = uint8(data.dst)
		offs[i] = data.off
		sizes[i] = data.size
		indices[i] = data.index
	}

	candidates := [][]int{}

	// Implement Python's double loop logic
	processed := make([]bool, len(dsts))

	for j := 0; j < len(dsts); j++ {
		if processed[j] {
			continue
		}

		dst := dsts[j]
		off := offs[j]
		size := sizes[j]
		// Get capacity based on the first instruction's offset (matching Python logic)
		cap := getCap(off)

		currentGroup := []int{}
		currentGroup = append(currentGroup, indices[j])
		processed[j] = true

		// Inner loop to find consecutive mergeable operations
		for k := j + 1; k < len(dsts); k++ {
			if processed[k] {
				continue
			}

			// Check capacity constraint: size * (k-j+1) <= cap (matching Python logic)
			// (k-j+1) represents number of instructions from j to k inclusive
			numInstructions := (k - j + 1)
			if dst == dsts[k] &&
				off+int16(size/8) == offs[k] &&
				size == sizes[k] &&
				size*numInstructions <= cap {
				// Update offset for next iteration
				off = offs[k]
				currentGroup = append(currentGroup, indices[k])
				processed[k] = true
			} else {
				// Process current group and break
				break
			}
		}

		// Process the group if it has enough elements
		if len(currentGroup) >= 2 {
			sm.processGroup(currentGroup, &candidates)
		}
	}

	return candidates
}

// analyseGroup analyzes a group of instruction hex strings (matching Python's analyse function)
func (sm *SuperwordMerger) analyseGroup(group []string, indices []int) [][]int {
	if len(group) < 2 {
		return nil
	}

	// Convert hex strings to MemoryOperation objects
	memOps := make([]MemoryOperation, len(group))
	for i, hexStr := range group {
		inst, err := bpf.NewInstruction(hexStr)
		if err != nil {
			continue
		}

		memOps[i] = MemoryOperation{
			Index:    indices[i],
			DstReg:   inst.DstReg,
			Offset:   inst.Offset,
			Size:     getSize(inst),
			Capacity: getCap(inst.Offset),
			Raw:      hexStr,
		}
	}

	// Use the existing analyse function
	return sm.analyse(memOps)
}

// processGroup processes a group of indices and adds appropriate candidates
// This matches the Python implementation's grouping strategy
func (sm *SuperwordMerger) processGroup(group []int, candidates *[][]int) {
	groupLen := len(group)

	if groupLen == 8 {
		*candidates = append(*candidates, append([]int{}, group...))
	} else if groupLen >= 6 {
		*candidates = append(*candidates, append([]int{}, group[:4]...))
		*candidates = append(*candidates, append([]int{}, group[4:6]...))
	} else if groupLen >= 4 {
		*candidates = append(*candidates, append([]int{}, group[:4]...))
	} else if groupLen >= 2 {
		*candidates = append(*candidates, append([]int{}, group[:2]...))
	}
}

// hasInterveningJumpOrLoad checks if there are jump or load instructions between two indices
func (sm *SuperwordMerger) hasInterveningJumpOrLoad(start, end int) bool {
	for i := start + 1; i < end; i++ {
		inst := sm.section.Instructions[i]

		opcode := inst.Opcode
		class := opcode & 0x07

		// Check for BPF_LDX, BPF_JMP, and BPF_JMP32 (matching Python logic)
		// Note: Don't skip NOP instructions - even NOP jumps are barriers
		if class == bpf.BPF_LDX || class == bpf.BPF_JMP || class == bpf.BPF_JMP32 {
			return true
		}
	}
	return false
}

// eliminateOverlappingCandidates removes candidates that are subsets of other candidates
func (sm *SuperwordMerger) eliminateOverlappingCandidates(candidates [][]int) [][]int {
	toRemove := make(map[int]bool)

	for i := 0; i < len(candidates); i++ {
		for j := 0; j < len(candidates); j++ {
			if i != j {
				// Check if candidates[i] is a subset of candidates[j]
				if isSubset(candidates[i], candidates[j]) {
					toRemove[i] = true
				}
			}
		}
	}

	result := [][]int{}
	for i, candidate := range candidates {
		if !toRemove[i] {
			result = append(result, candidate)
		}
	}

	return result
}

// isSubset checks if slice a is a subset of slice b
func isSubset(a, b []int) bool {
	if len(a) >= len(b) {
		return false
	}

	setB := make(map[int]bool)
	for _, val := range b {
		setB[val] = true
	}

	for _, val := range a {
		if !setB[val] {
			return false
		}
	}

	return true
}

// ApplySuperwordMergeWithCandidates implements superword merge with provided store candidates
func (sm *SuperwordMerger) ApplySuperwordMergeWithCandidates() {
	sm.applySuperwordMergeWithCandidates(sm.section.StoreCandidates)
}

// applySuperwordMergeWithCandidates internal implementation
func (sm *SuperwordMerger) applySuperwordMergeWithCandidates(storeCandidates []int) {
	if len(storeCandidates) < 2 {
		return
	}

	// Sort store candidates
	sort.Ints(storeCandidates)

	// Group consecutive store operations (matching Python's logic)
	allCandidates := [][]int{}
	group := []string{} // equivalent to Python's group
	indices := []int{}  // equivalent to Python's indices
	flag := false

	// Check all store instructions (Python's main loop)
	for i := 0; i < len(storeCandidates)-1; i++ {
		currentIdx := storeCandidates[i]
		nextIdx := storeCandidates[i+1]

		// Initialize group if empty
		if len(group) == 0 {
			inst := sm.section.Instructions[currentIdx]
			group = append(group, inst.Raw)
			indices = append(indices, currentIdx)
			flag = false
		}

		// Check if there are jump/load instructions between stores
		flag = false
		for j := currentIdx + 1; j < nextIdx; j++ {
			inst := sm.section.Instructions[j]

			opcode := inst.Opcode
			class := opcode & 0x07

			// Don't skip NOP instructions - even NOP jumps are barriers
			if class == bpf.BPF_LDX || class == bpf.BPF_JMP || class == bpf.BPF_JMP32 {
				// Stop updating and start analyzing current candidate list
				if len(group) >= 2 {
					candidates := sm.analyseGroup(group, indices)
					if len(candidates) > 0 {
						allCandidates = append(allCandidates, candidates...)
					}
				}
				group = []string{}
				indices = []int{}
				flag = true
				break
			}
		}

		if !flag {
			// Add next instruction to group
			inst := sm.section.Instructions[nextIdx]
			group = append(group, inst.Raw)
			indices = append(indices, nextIdx)
		}
	}

	// Process remaining group
	if len(group) >= 2 {
		candidates := sm.analyseGroup(group, indices)
		if len(candidates) > 0 {
			allCandidates = append(allCandidates, candidates...)
		}
	}

	// Eliminate overlapping candidates
	finalCandidates := sm.eliminateOverlappingCandidates(allCandidates)

	// Apply merges
	sm.applyMerges(finalCandidates)
}

// applyMerges applies the actual instruction merging
func (sm *SuperwordMerger) applyMerges(candidates [][]int) {
	for _, candidate := range candidates {
		if len(candidate) < 2 {
			continue
		}

		// Normalize candidate order (ascending index)
		sort.Ints(candidate)

		// Validation similar to Python but keeping some Go safety checks
		firstInst := sm.section.Instructions[candidate[0]]
		elemSize := getSize(firstInst)
		dstReg := firstInst.DstReg

		// Basic consistency checks (similar to Python's analyse function)
		valid := true
		for i := 1; i < len(candidate); i++ {
			inst := sm.section.Instructions[candidate[i]]
			if inst.DstReg != dstReg || getSize(inst) != elemSize {
				valid = false
				break
			}
		}

		// Check for barriers between instructions (matching Python)
		if valid {
			start := candidate[0]
			end := candidate[len(candidate)-1]
			if sm.hasInterveningJumpOrLoad(start, end) {
				valid = false
			}
		}

		if !valid {
			continue
		}

		// Calculate new merged size
		newSize := elemSize * len(candidate)

		// Validate new size (must be valid BPF size)
		if newSize != 16 && newSize != 32 && newSize != 64 {
			continue
		}

		// Build new immediate value (matching Python logic)
		newImm := ""
		for _, idx := range candidate {
			inst := sm.section.Instructions[idx]
			// Extract immediate value from instruction
			immLen := elemSize / 4
			if len(inst.Raw) >= 8+immLen {
				newImm += inst.Raw[8 : 8+immLen]
			}
		}

		// Handle immediate value based on new size (different from Python logic)
		// For merging different stores, we keep the concatenated immediate
		if newSize == 64 {
			// For 64-bit stores, we can use up to 8 hex chars (32-bit immediate)
			// But we keep only the first immediate value for now
			if len(newImm) > 8 {
				newImm = newImm[:8]
			}
		}

		// Pad with zeros to reach 8 characters
		for len(newImm) < 8 {
			newImm += "0"
		}

		// Create new instruction
		newSizeMask := getSizeMask(newSize)
		newOpcode := bpf.BPF_MEM | newSizeMask | bpf.BPF_ST
		newRegOffset := firstInst.Raw[2:8]
		newInstHex := fmt.Sprintf("%02x%s%s", newOpcode, newRegOffset, newImm)

		newInst, err := bpf.NewInstruction(newInstHex)
		if err != nil {
			continue
		}

		// Apply the merge
		sm.section.Instructions[candidate[0]] = newInst
		for i := 1; i < len(candidate); i++ {
			sm.section.Instructions[candidate[i]].SetAsNOP()
		}
	}
}
