package optimizer

import "github.com/beepfd/bpf-optimizer/pkg/bpf"

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
