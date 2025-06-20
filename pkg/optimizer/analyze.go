package optimizer

import "github.com/beepfd/bpf-optimizer/pkg/bpf"

func (a *InstructionAnalysis) ALU(opcode uint8, dst int, src int) {
	msb := opcode & 0xF0
	switch msb {
	case bpf.ALU_END: // byte exchange
		a.UpdatedReg = dst
		a.UsedReg = []int{dst}
	case bpf.ALU_MOV: // move
		a.UpdatedReg = dst
		if opcode&bpf.BPF_X == bpf.BPF_X {
			a.UsedReg = []int{src}
		}
	default: // regular arithmetic
		a.UpdatedReg = dst
		if opcode&bpf.BPF_X == bpf.BPF_X { // use register
			a.UsedReg = []int{dst, src}
		} else { // use immediate
			a.UsedReg = []int{dst}
		}
	}
}

func (a *InstructionAnalysis) JMP(opcode uint8, dst int, src int, off int16, imm int32) {
	msb := opcode & 0xF0
	switch msb {
	case bpf.JMP_CALL:
		a.IsCall = true
		a.UpdatedReg = 0

		// Handle different BPF helper functions
		switch imm {
		case 12: // tail call
			a.UsedReg = []int{1, 2, 3}
			a.UsedStack = []int16{0, 0}
		case 1, 3, 23, 44: // map lookup, delete
			a.UsedReg = []int{1, 2}
		case 2, 69: // map update
			a.UsedReg = []int{1, 2, 3, 4}
		case 4, 51: // map lookup
			a.UsedReg = []int{1, 2, 3}
		case 5, 7, 8: // various helpers
			// only updates r0
		case 9, 10, 11: // complex helpers
			a.UsedReg = []int{1, 2, 3, 4, 5}
		default:
			a.UsedReg = []int{1, 2, 3, 4, 5}
		}
	case bpf.JMP_EXIT:
		a.UsedReg = []int{0}
		a.IsExit = true
	case 0x05: // unconditional jump
		a.Offset = off
	default: // conditional jump
		a.UsedReg = []int{dst, src}
		a.Offset = off
	}
}

func (a *InstructionAnalysis) STX(opcode uint8, dst int, src int, off int16, imm int32) {
	msb := opcode & 0xE0
	if msb == bpf.BPF_MEM || msb == bpf.BPF_MEMSX || msb == bpf.BPF_ATOMIC {
		size := int16(1 << ((opcode & 0x18) >> 3))
		if dst == 10 { // stack pointer
			a.UpdatedStack = []int16{off, size}
			a.UsedReg = []int{src}
		} else {
			a.UsedReg = []int{src}
		}
	}
}

func (a *InstructionAnalysis) ST(opcode uint8, dst int, src int, off int16, imm int32) {
	msb := opcode & 0xE0
	if msb == bpf.BPF_MEM || msb == bpf.BPF_MEMSX || msb == bpf.BPF_ATOMIC {
		size := int16(1 << ((opcode & 0x18) >> 3))
		if dst == 10 { // stack pointer
			a.UpdatedStack = []int16{off, size}
		}
	}
}

func (a *InstructionAnalysis) LDX(opcode uint8, dst int, src int, off int16, imm int32) {
	msb := opcode & 0xE0
	if msb == bpf.BPF_MEM || msb == bpf.BPF_MEMSX {
		size := int16(1 << ((opcode & 0x18) >> 3))
		a.UpdatedReg = dst
		if src == 10 { // stack pointer
			a.UsedStack = []int16{off, size}
		} else {
			a.UsedReg = []int{src}
		}
	}
}

func (a *InstructionAnalysis) LD(opcode uint8, dst int, src int, off int16, imm int32) {
	msb := opcode & 0xE0
	if msb == bpf.BPF_IMM {
		a.UpdatedReg = dst
	} else if msb == bpf.BPF_ABS || msb == bpf.BPF_IND {
		a.UpdatedReg = dst
		a.UsedReg = []int{src}
	}
}
