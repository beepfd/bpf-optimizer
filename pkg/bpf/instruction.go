package bpf

import (
	"fmt"
)

// Instruction represents a BPF instruction (16 bytes)
type Instruction struct {
	Raw    string // 16-byte hex string representation
	Opcode uint8
	DstReg uint8
	SrcReg uint8
	Offset int16
	Imm    int32
}

// NewInstruction creates a new instruction from hex string
func NewInstruction(hexStr string) (*Instruction, error) {
	if len(hexStr) != 16 {
		return nil, fmt.Errorf("instruction must be 16 hex characters, got %d", len(hexStr))
	}

	inst := &Instruction{Raw: hexStr}

	// eBPF 指令格式
	// 62  0a  fc  ff  00  00  00  00
	// |   |   |   |   |             |
	// |   |   |   |   +--- 立即数 (32位)
	// |   |   +---+------- 偏移量 (16位)
	// |   +--------------- 寄存器字段 (4位src + 4位dst)
	// +------------------- 操作码 (8位)

	// Parse opcode (first byte)
	var err error
	inst.Opcode, err = parseOpcode(hexStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse opcode: %v", err)
	}

	// Parse registers (second byte)
	inst.DstReg, inst.SrcReg, err = parseRegisters(hexStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse registers: %v", err)
	}

	// Parse offset (bytes 2-3, little endian)
	inst.Offset, err = parseOffset(hexStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse offset: %v", err)
	}

	// Parse immediate (bytes 4-7, little endian)
	inst.Imm, err = parseImmediate(hexStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse immediate: %v", err)
	}

	return inst, nil
}

// ToHex converts instruction back to hex string
func (inst *Instruction) ToHex() string {
	return inst.Raw
}

// GetInstructionClass returns the BPF instruction class
func (inst *Instruction) GetInstructionClass() uint8 {
	return inst.Opcode & 0x07
}

// GetALUOp returns the ALU operation code
func (inst *Instruction) GetALUOp() uint8 {
	return inst.Opcode & 0xF0
}

// IsLoadImm64 checks if this is a 64-bit immediate load instruction
func (inst *Instruction) IsLoadImm64() bool {
	return inst.Opcode == 0x18
}

// IsNOP checks if this instruction is a NOP
func (inst *Instruction) IsNOP() bool {
	return inst.Raw == NOP
}

// SetAsNOP marks this instruction as NOP
func (inst *Instruction) SetAsNOP() {
	inst.Raw = NOP
	inst.Opcode = 0x05
	inst.DstReg = 0
	inst.SrcReg = 0
	inst.Offset = 0
	inst.Imm = 0
}

// Clone creates a deep copy of the instruction
func (inst *Instruction) Clone() *Instruction {
	return &Instruction{
		Raw:    inst.Raw,
		Opcode: inst.Opcode,
		DstReg: inst.DstReg,
		SrcReg: inst.SrcReg,
		Offset: inst.Offset,
		Imm:    inst.Imm,
	}
}

// String returns a human-readable representation
func (inst *Instruction) String() string {
	return fmt.Sprintf("Opcode: 0x%02x, Dst: r%d, Src: r%d, Off: %d, Imm: %d, Raw: %s",
		inst.Opcode, inst.DstReg, inst.SrcReg, inst.Offset, inst.Imm, inst.Raw)
}

func (inst *Instruction) GetRawImm() string {
	if len(inst.Raw) < 16 {
		return ""
	}

	return inst.Raw[14:16] + inst.Raw[12:14] + inst.Raw[10:12] + inst.Raw[8:10]
}
