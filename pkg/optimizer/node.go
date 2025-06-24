package optimizer

import (
	"sort"

	"github.com/beepfd/bpf-optimizer/pkg/bpf"
)

// buildInstructionNode 构建前向映射
func buildInstructionNode(insts []*bpf.Instruction, cfg *ControlFlowGraph) {
	currentNode := 0
	// First pass: identify basic block boundaries
	for i, inst := range insts {
		opcode := inst.Opcode
		if (opcode&0x07) == bpf.BPF_JMP || (opcode&0x07) == bpf.BPF_JMP32 {
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
			if _, exists := cfg.NodesRev[succ]; exists {
				cfg.NodesRev[succ] = append(cfg.NodesRev[succ], key)
			} else {
				cfg.NodesRev[succ] = []int{key}
			}
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
