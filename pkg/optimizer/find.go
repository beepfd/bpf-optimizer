package optimizer

import "sort"

func (s *Section) findNextNode(cfg *ControlFlowGraph, nodesDone map[int]bool, loopInfo *LoopInfo) (int, *RegisterState) {
	// Find next node to process
	newBase := 0
	var newState *RegisterState

	nodesRevKeys := make([]int, 0, len(cfg.NodesRev))
	for node := range cfg.NodesRev {
		nodesRevKeys = append(nodesRevKeys, node)
	}

	sort.Ints(nodesRevKeys)

	// Look for ready nodes (all predecessors done)
	// 以下代码主要用于寻找，前驱节点全部完成或者没有前驱节点的节点，作为下一个要处理的节点
	for _, node := range nodesRevKeys {
		if nodesDone[node] {
			continue
		}

		// Skip nodes containing BPF_EXIT instruction when in loop context (corresponds to Python's "9500000000000000" check)
		if loopInfo != nil {
			if nodeLen, exists := cfg.NodesLen[node]; exists {
				skipNode := false
				for i := 0; i < nodeLen; i++ {
					instIdx := node + i
					if instIdx < len(s.Instructions) {
						inst := s.Instructions[instIdx]
						// Check for BPF_EXIT instruction (opcode 0x95)
						if inst.Opcode == 0x95 {
							skipNode = true
							break
						}
					}
				}
				if skipNode {
					continue
				}
			}
		}

		// Check if all predecessors are done
		allPredsDone := true
		for _, pred := range cfg.NodesRev[node] {
			if !nodesDone[pred] {
				allPredsDone = false
				break
			}
		}

		if allPredsDone {
			newBase = node
			// Merge states from predecessors
			var predStates []*RegisterState
			for _, pred := range cfg.NodesRev[node] {
				if predState, exists := cfg.NodeStats[pred]; exists {
					predStates = append(predStates, predState)
				}
			}
			newState = MergeRegisterStates(predStates)
			// break
		}
	}

	return newBase, newState
}
