package bpf

import (
	"encoding/hex"
	"fmt"
	"strconv"
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

	// Parse opcode (first byte)
	opcode, err := strconv.ParseUint(hexStr[0:2], 16, 8)
	if err != nil {
		return nil, fmt.Errorf("failed to parse opcode: %v", err)
	}
	inst.Opcode = uint8(opcode)

	// Parse registers (second byte)
	regs, err := strconv.ParseUint(hexStr[2:4], 16, 8)
	if err != nil {
		return nil, fmt.Errorf("failed to parse registers: %v", err)
	}
	inst.DstReg = uint8(regs & 0x0F)
	inst.SrcReg = uint8((regs & 0xF0) >> 4)

	// Parse offset (bytes 2-3, little endian)
	offsetBytes, err := hex.DecodeString(hexStr[6:8] + hexStr[4:6])
	if err != nil {
		return nil, fmt.Errorf("failed to parse offset: %v", err)
	}
	inst.Offset = int16(offsetBytes[0]) | (int16(offsetBytes[1]) << 8)

	// Parse immediate (bytes 4-7, little endian)
	immBytes, err := hex.DecodeString(hexStr[14:16] + hexStr[12:14] + hexStr[10:12] + hexStr[8:10])
	if err != nil {
		return nil, fmt.Errorf("failed to parse immediate: %v", err)
	}
	inst.Imm = int32(immBytes[0]) | (int32(immBytes[1]) << 8) | (int32(immBytes[2]) << 16) | (int32(immBytes[3]) << 24)

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
