package optimizer

// LoopInfo represents information about a detected loop
type LoopInfo struct {
	Head      int             // loop head basic block
	Registers [][]int         // register state at loop entry
	Stacks    map[int16][]int // stack state at loop entry
	Processed map[int]bool    // nodes processed in this loop iteration
	Waiting   map[int]bool    // nodes waiting for this loop to finish
	Parent    *LoopInfo       // parent loop for nested loops
}

// NewLoopInfo creates a new loop info structure
func NewLoopInfo(head int, parent *LoopInfo) *LoopInfo {
	return &LoopInfo{
		Head:      head,
		Registers: make([][]int, 11),
		Stacks:    make(map[int16][]int),
		Processed: make(map[int]bool),
		Waiting:   make(map[int]bool),
		Parent:    parent,
	}
}

// Clone creates a deep copy of LoopInfo
func (li *LoopInfo) Clone() *LoopInfo {
	newLi := &LoopInfo{
		Head:      li.Head,
		Registers: make([][]int, 11),
		Stacks:    make(map[int16][]int),
		Processed: make(map[int]bool),
		Waiting:   make(map[int]bool),
		Parent:    li.Parent, // shallow copy of parent reference
	}

	// Deep copy registers
	for i, reg := range li.Registers {
		newLi.Registers[i] = make([]int, len(reg))
		copy(newLi.Registers[i], reg)
	}

	// Deep copy stacks
	for offset, instList := range li.Stacks {
		newLi.Stacks[offset] = make([]int, len(instList))
		copy(newLi.Stacks[offset], instList)
	}

	// Deep copy processed map
	for node, processed := range li.Processed {
		newLi.Processed[node] = processed
	}

	// Deep copy waiting map
	for node, waiting := range li.Waiting {
		newLi.Waiting[node] = waiting
	}

	return newLi
}

// IsEqual checks if two register states are equal
func (rs *RegisterState) IsEqual(other *RegisterState) bool {
	// Compare registers
	for i := 0; i < 11; i++ {
		if !intSlicesEqual(rs.Registers[i], other.Registers[i]) {
			return false
		}
	}

	// Compare stacks
	if len(rs.Stacks) != len(other.Stacks) {
		return false
	}
	for offset, instList := range rs.Stacks {
		if otherList, exists := other.Stacks[offset]; !exists || !intSlicesEqual(instList, otherList) {
			return false
		}
	}

	return true
}

// intSlicesEqual checks if two int slices contain the same elements (order doesn't matter)
func intSlicesEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}

	// Convert to sets for comparison
	setA := make(map[int]bool)
	setB := make(map[int]bool)

	for _, v := range a {
		setA[v] = true
	}
	for _, v := range b {
		setB[v] = true
	}

	if len(setA) != len(setB) {
		return false
	}

	for k := range setA {
		if !setB[k] {
			return false
		}
	}

	return true
}

// MergeRegisterStates merges multiple register states
func MergeRegisterStates(states []*RegisterState) *RegisterState {
	if len(states) == 0 {
		return NewRegisterState()
	}

	merged := NewRegisterState()

	// Merge registers
	for i := 0; i < 11; i++ {
		var allInsts []int
		for _, state := range states {
			allInsts = append(allInsts, state.Registers[i]...)
		}
		merged.Registers[i] = removeDuplicates(allInsts)
	}

	// Merge stacks
	for _, state := range states {
		for offset, instList := range state.Stacks {
			if existing, exists := merged.Stacks[offset]; exists {
				merged.Stacks[offset] = removeDuplicates(append(existing, instList...))
			} else {
				merged.Stacks[offset] = make([]int, len(instList))
				copy(merged.Stacks[offset], instList)
			}
		}
	}

	return merged
}

// detectLoop detects if there's a loop from start to stop
// This corresponds to Python's get_loop function
func (s *Section) detectLoop(start, stop int, nodes map[int][]int, visited map[int]bool) []int {
	if visited == nil {
		visited = make(map[int]bool)
	}

	successors, exists := nodes[start]
	if !exists || len(successors) == 0 {
		return []int{-1} // No successors
	}

	// Check if stop is a direct successor
	for _, succ := range successors {
		if succ == stop {
			return []int{} // Found direct loop, return the stop node
		}
	}

	found := false
	path := []int{start}
	for _, succ := range successors {
		if visited[succ] {
			continue // Avoid infinite recursion
		}

		visited[succ] = true
		subPath := s.detectLoop(succ, stop, nodes, visited)
		if (len(subPath) > 0 && !contains(subPath, -1)) || len(subPath) == 0 {
			// Found a path through this successor
			path = append(path, subPath...)
			found = true
		}
	}

	if !found {
		return []int{-1}
	}

	// No path found through any successor
	return removeDuplicates(path)
}

// 需要检查整个切片是否包含-1
func contains(slice []int, value int) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}

// findLoopCandidates finds potential loop heads when normal processing is stuck
func (s *Section) findLoopCandidates(cfg *ControlFlowGraph, nodesDone map[int]bool) int {
	// Get candidates from successors of completed nodes
	candidates := make(map[int]bool)
	for doneNode := range nodesDone {
		if successors, exists := cfg.Nodes[doneNode]; exists {
			for _, succ := range successors {
				if !nodesDone[succ] {
					candidates[succ] = true
				}
			}
		}
	}

	// Check each candidate for loops
	for candidate := range candidates {
		visited := make(map[int]bool)
		loopPath := s.detectLoop(candidate, candidate, cfg.Nodes, visited)
		if len(loopPath) > 0 && !contains(loopPath, -1) {
			return candidate
		}
	}

	return 0 // No loop found
}

func buildLoopState(cfg *ControlFlowGraph, loopHead int) *RegisterState {
	// Initialize loop state from predecessors
	var predStates []*RegisterState
	if preds, exists := cfg.NodesRev[loopHead]; exists {
		for _, pred := range preds {
			if predState, exists := cfg.NodeStats[pred]; exists {
				predStates = append(predStates, predState)
			}
		}
	}

	loopState := MergeRegisterStates(predStates)

	return loopState
}
