package optimizer

import (
	"fmt"
	"sort"

	"github.com/beepfd/bpf-optimizer/pkg/bpf"
)

// buildInstructionNode 构建前向映射
func buildInstructionNode(insts []*bpf.Instruction, cfg *ControlFlowGraph) {
	currentNode := 0
	// First pass: identify basic block boundaries
	for i, inst := range insts {
		opcode := inst.Opcode
		if (opcode&0x07) != bpf.BPF_JMP && (opcode&0x07) != bpf.BPF_JMP32 {
			continue
		}

		off := inst.Offset
		msb := opcode & 0xF0
		if msb == bpf.JMP_CALL {
			continue
		}

		if msb == bpf.JMP_EXIT {
			cfg.Nodes[currentNode] = []int{}
		} else if opcode == 5 {
			jumpTarget := i + int(off) + 1
			// Only add valid jump targets (within bounds)
			if jumpTarget >= 0 {
				cfg.Nodes[currentNode] = []int{jumpTarget}
			} else {
				cfg.Nodes[currentNode] = []int{} // Invalid jump target treated as exit
			}
		} else {
			cfg.Nodes[currentNode] = []int{i}
			jumpTarget := i + int(off) + 1
			fallThrough := i + 1

			successors := make([]int, 0, 2)
			// Add jump target if valid
			if jumpTarget >= 0 {
				successors = append(successors, jumpTarget)
			}
			// Add fall-through if valid
			if fallThrough >= 0 {
				successors = append(successors, fallThrough)
			}
			cfg.Nodes[i] = successors
		}
		currentNode = i + 1
	}
}

// buildInstructionNodeReverse 构建反向映射
func buildInstructionNodeReverse(cfg *ControlFlowGraph) {
	// Build reverse mapping
	for key, successors := range cfg.Nodes {
		if key != 0 {
			if _, exists := cfg.NodesRev[key]; !exists {
				cfg.NodesRev[key] = make([]int, 0)
			}
		}
		for _, succ := range successors {
			cfg.NodesRev[succ] = append(cfg.NodesRev[succ], key)
		}
	}
}

// buildInstructionNodeLength 构建节点长度映射
func buildInstructionNodeLength(insts []*bpf.Instruction, cfg *ControlFlowGraph) {
	allNodes := make([]int, 0)
	for node := range cfg.NodesRev {
		allNodes = append(allNodes, node)
	}
	allNodes = append(allNodes, 0, len(insts))

	// Sort nodes efficiently using Go's built-in sort
	sort.Ints(allNodes)

	for i := 0; i < len(allNodes)-1; i++ {
		cfg.NodesLen[allNodes[i]] = allNodes[i+1] - allNodes[i]
	}

	// Build detailed reverse mapping by analyzing each instruction in each basic block
	// This corresponds to Python's detailed nodes_rev construction (lines 512-533)
	cfg.NodesRev = make(map[int][]int)
	for _, node := range allNodes[:len(allNodes)-1] { // exclude the last virtual node
		cfg.NodesRev[node] = make([]int, 0)
	}

	// Remove the virtual end node if it exists
	delete(cfg.NodesRev, len(insts))
}

// rebuildInstructionNodeRev 重建反向映射
func rebuildInstructionNodeRev(insts []*bpf.Instruction, cfg *ControlFlowGraph) {
	// Analyze each instruction in each basic block
	// Sort nodes to ensure deterministic order
	var sortedNodes []int
	for node := range cfg.NodesLen {
		sortedNodes = append(sortedNodes, node)
	}
	sort.Ints(sortedNodes)
	
	// Debug: Log node processing order for 4810 area
	fmt.Printf("DEBUG: rebuildInstructionNodeRev - Node processing order around 4810: ")
	for _, node := range sortedNodes {
		if node >= 4800 && node <= 4820 {
			fmt.Printf("%d ", node)
		}
	}
	fmt.Printf("\n")
	
	for _, node := range sortedNodes {
		nodeLen := cfg.NodesLen[node]
		for i := 0; i < nodeLen; i++ {
			instIdx := node + i
			if instIdx >= len(insts) {
				break
			}

			inst := insts[instIdx]
			opcode := inst.Opcode
			off := inst.Offset
			msb := opcode & 0xF0

			// Handle jump instructions
			if (opcode&0x07) == bpf.BPF_JMP || (opcode&0x07) == bpf.BPF_JMP32 {
				if msb == bpf.JMP_CALL {
					// Function calls don't create control flow edges
				} else if msb == bpf.JMP_EXIT {
					// Exit instructions don't have successors
					continue
				} else if opcode == 0x05 { // Unconditional jump
					jumpTarget := instIdx + int(off) + 1
					if jumpTarget >= 0 && jumpTarget < len(insts) {
						// Record that 'node' jumps to 'jumpTarget'
						if _, exists := cfg.NodesRev[jumpTarget]; exists {
							cfg.NodesRev[jumpTarget] = append(cfg.NodesRev[jumpTarget], node)
						}
					}
					continue
				} else { // Conditional jump
					jumpTarget := instIdx + int(off) + 1
					fallThrough := instIdx + 1

					// Record jump target
					if jumpTarget >= 0 && jumpTarget < len(insts) {
						if _, exists := cfg.NodesRev[jumpTarget]; exists {
							cfg.NodesRev[jumpTarget] = append(cfg.NodesRev[jumpTarget], instIdx)
						}
					}
					// Record fall-through
					if fallThrough >= 0 && fallThrough < len(insts) {
						if _, exists := cfg.NodesRev[fallThrough]; exists {
							cfg.NodesRev[fallThrough] = append(cfg.NodesRev[fallThrough], instIdx)
						}
					}
					continue
				}
			}

			// Handle sequential flow at the end of basic blocks
			if i == nodeLen-1 && node+nodeLen < len(insts) {
				nextBasicBlock := node + nodeLen
				if _, exists := cfg.NodesRev[nextBasicBlock]; exists {
					cfg.NodesRev[nextBasicBlock] = append(cfg.NodesRev[nextBasicBlock], node)
				}
			}
		}
	}
}

// updateInstructionNode 更新前向映射
// 根据详细反向映射更新前向映射，确保 Nodes 和 NodesRev 的一致性
func updateInstructionNode(cfg *ControlFlowGraph) {
	for target, sources := range cfg.NodesRev {
		if _, exists := cfg.Nodes[target]; !exists {
			cfg.Nodes[target] = make([]int, 0)
		}

		for _, source := range sources {
			// Check if target is not already in the successor list
			found := false
			for _, succ := range cfg.Nodes[source] {
				if succ == target {
					found = true
					break
				}
			}
			if !found {
				cfg.Nodes[source] = append(cfg.Nodes[source], target)
			}
		}

		sort.Ints(cfg.NodesRev[target])
	}
}
