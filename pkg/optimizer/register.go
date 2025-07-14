package optimizer

import (
	"fmt"
	"sort"

	"github.com/beepfd/bpf-optimizer/pkg/bpf"
)

func (s *Section) BuildRegisterDependencies(cfg *ControlFlowGraph, nodeLen, base int, state *RegisterState, nodesDone map[int]bool) (shouldReturn bool) {
	for i := 0; i < nodeLen; i++ {
		instIdx := base + i
		if instIdx >= len(s.Instructions) {
			break
		}

		inst := s.Instructions[instIdx]
		if inst.Opcode == 0 { // skip NOPs
			continue
		}

		analysis := analyzeInstruction(inst)

		// Handle register alias updates
		if inst.Opcode != 0xBF && inst.Opcode != 0x07 {
			state.RegAlias[inst.DstReg] = -1
		}

		// Process used registers
		s.ProcessUsedRegisters(instIdx, analysis, inst, state)

		// Update register state
		// 如果当前指令更新了寄存器，则将当前指令索引添加到寄存器状态中
		if analysis.UpdatedReg >= 0 {
			state.Registers[analysis.UpdatedReg] = []int{instIdx}
		}

		// Handle function calls
		// 根据BPF ABI规范：
		// R0: 函数返回值
		// R1-R5: 函数参数传递
		// R6-R9: 被调用者保存寄存器（callee-saved）
		// R10: 只读栈指针
		// R1-R5是scratch registers（临时寄存器）
		// 函数调用之后，这些寄存器的值被认为是不可预测的，R1-R5 寄存器会被清空
		if analysis.IsCall {
			for j := 1; j <= 5; j++ { // r1-r5 are caller-saved
				state.Registers[j] = make([]int, 0)
			}
		}

		// Handle stack updates
		// 如果当前指令更新了栈，则将当前指令索引添加到栈状态中
		if len(analysis.UpdatedStack) >= 2 {
			offset := analysis.UpdatedStack[0]
			state.Stacks[offset] = []int{instIdx}
		}

		// Handle stack usage
		s.ProcessUsedStack(instIdx, analysis, inst, state)

		// Handle exit instructions
		if analysis.IsExit {
			nodesDone[base] = true
			if len(nodesDone) >= len(cfg.NodesRev) {
				shouldReturn = true
			}
		}
	}

	return
}

func (s *Section) ProcessUsedRegisters(instIdx int, analysis *InstructionAnalysis, inst *bpf.Instruction, state *RegisterState) {
	for _, regIdx := range analysis.UsedReg {
		if regIdx < 0 || regIdx >= 11 {
			continue
		}

		// Handle stack alias
		// 如果使用了 R10 寄存器，则 R10 的别名是 R0，表示它现在指向栈顶
		if regIdx == 10 {
			state.RegAlias[inst.DstReg] = 0
			// 如果当前寄存器已知别名，且指令为 ALU64 或 ALU，则更新栈偏移计算
		} else if state.RegAlias[inst.DstReg] != -1 && inst.Opcode == bpf.BPF_ALU64 {
			state.RegAlias[inst.DstReg] += int16(inst.Imm)
			// 0x85 = BPF_JMP + JMP_CALL = 0x05 + 0x80 = 0x85 是函数调用指令。
		} else if inst.Opcode != 0x85 {
			state.RegAlias[inst.DstReg] = -1
		}

		// Add dependencies based on register usage
		if len(state.Registers[regIdx]) == 0 {
			continue
		}

		for _, depInstIdx := range state.Registers[regIdx] {
			if state.RegAlias[regIdx] != -1 && state.RegAlias[regIdx] != 0 {
				// 情况1: 如果当前寄存器有别名，则将别名指向的栈偏移值添加到依赖关系中
				if stackInsts, exists := state.Stacks[state.RegAlias[regIdx]]; exists {
					for _, stackInstIdx := range stackInsts {
						s.Dependencies[instIdx].Dependencies = append(s.Dependencies[instIdx].Dependencies, stackInstIdx)
						// 计算实际的数组索引
						actualIndex := calculateActualIndex(stackInstIdx, len(s.Dependencies))
						if actualIndex >= 0 && actualIndex < len(s.Dependencies) {
							s.Dependencies[actualIndex].DependedBy = append(s.Dependencies[actualIndex].DependedBy, instIdx)
						}
					}
				} else {
					// 情况2: 如果当前寄存器没有别名，则将别名指向的栈偏移值设置为 -1
					state.Stacks[state.RegAlias[regIdx]] = []int{-1}
					s.Dependencies[instIdx].Dependencies = append(s.Dependencies[instIdx].Dependencies, -1)
				}
			}

			// Check if dependency already exists to prevent duplicates
			dependencyExists := s.FoundDependency(instIdx, depInstIdx)
			if !dependencyExists {
				s.Dependencies[instIdx].Dependencies = append(s.Dependencies[instIdx].Dependencies, depInstIdx)
				// 修复：正确处理负数索引的动态位置计算
				actualDepIndex := calculateActualIndex(depInstIdx, len(s.Dependencies))
				if actualDepIndex >= 0 && actualDepIndex < len(s.Dependencies) {
					// Check if reverse dependency already exists
					dependedByExists := s.FoundDependedBy(actualDepIndex, instIdx)
					if !dependedByExists {
						s.Dependencies[actualDepIndex].DependedBy = append(s.Dependencies[actualDepIndex].DependedBy, instIdx)
					}
				}
			}
		}
	}
}

// calculateActualIndex 计算负数索引的实际位置
// 支持 Python 风格的负数索引: n + index
func calculateActualIndex(index int, arrayLength int) int {
	if index < 0 {
		return arrayLength + index
	}
	return index
}

func (s *Section) ProcessUsedStack(instIdx int, analysis *InstructionAnalysis, inst *bpf.Instruction, state *RegisterState) {
	if len(analysis.UsedStack) >= 2 {
		offset := analysis.UsedStack[0]
		if offset == 0 { // tail call
			// Sort stack offsets to ensure deterministic order
			var stackOffsets []int16
			for stackOffset := range state.Stacks {
				stackOffsets = append(stackOffsets, stackOffset)
			}
			sort.Slice(stackOffsets, func(i, j int) bool {
				return stackOffsets[i] < stackOffsets[j]
			})

			// Debug: Log stack processing order
			if instIdx >= 4810 && instIdx <= 4813 {
				fmt.Printf("DEBUG: ProcessUsedStack - instIdx %d, stack offsets order: %v\n",
					instIdx, stackOffsets)
			}

			for _, stackOffset := range stackOffsets {
				stackInsts := state.Stacks[stackOffset]
				for _, stackInstIdx := range stackInsts {
					if stackInstIdx == -1 {
						// Special case for initial state, skip
						continue
					}
					if stackInstIdx >= 0 && stackInstIdx < len(s.Dependencies) {
						// Check if dependency already exists
						dependencyExists := s.FoundDependency(instIdx, stackInstIdx)
						if !dependencyExists {
							s.Dependencies[instIdx].Dependencies = append(s.Dependencies[instIdx].Dependencies, stackInstIdx)
						}

						// Check if reverse dependency already exists
						dependedByExists := s.FoundDependedBy(stackInstIdx, instIdx)
						if !dependedByExists {
							s.Dependencies[stackInstIdx].DependedBy = append(s.Dependencies[stackInstIdx].DependedBy, instIdx)
						}
					}
				}
			}
		} else if stackInsts, exists := state.Stacks[offset]; exists {
			for _, stackInstIdx := range stackInsts {
				// Check if dependency already exists
				dependencyExists := s.FoundDependency(instIdx, stackInstIdx)
				if !dependencyExists {
					s.Dependencies[instIdx].Dependencies = append(s.Dependencies[instIdx].Dependencies, stackInstIdx)
				}

				actualIndex := calculateActualIndex(stackInstIdx, len(s.Dependencies))
				if actualIndex >= 0 && actualIndex < len(s.Dependencies) {
					// Check if reverse dependency already exists
					dependedByExists := s.FoundDependedBy(actualIndex, instIdx)
					if !dependedByExists {
						s.Dependencies[actualIndex].DependedBy = append(s.Dependencies[actualIndex].DependedBy, instIdx)
					}
				}
			}
		} else {
			state.Stacks[offset] = []int{-1}
			s.Dependencies[instIdx].Dependencies = append(s.Dependencies[instIdx].Dependencies, -1)
		}
	}
}
