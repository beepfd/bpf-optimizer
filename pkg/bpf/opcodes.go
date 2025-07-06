// Package bpf provides BPF instruction definitions and constants
// Ported from Python macros.py
// See https://docs.kernel.org/bpf/instruction-set.html#legacy-bpf-packet-access-instructions
package bpf

// BPF instruction classes
const (
	BPF_LD    = 0x00
	BPF_LDX   = 0x01
	BPF_ST    = 0x02
	BPF_STX   = 0x03
	BPF_ALU   = 0x04
	BPF_JMP   = 0x05
	BPF_JMP32 = 0x06
	BPF_ALU64 = 0x07
)

// SOURCE operands
const (
	BPF_K = 0x00 // use 32-bit immediate as source operand
	BPF_X = 0x08 // use 'src_reg' register as source operand
)

// BPF_ALU operations
const (
	ALU_ADD   = 0x00
	ALU_SUB   = 0x10
	ALU_MUL   = 0x20
	ALU_DIV   = 0x30
	ALU_SDIV  = 0x30
	ALU_OR    = 0x40
	ALU_AND   = 0x50
	ALU_RSH   = 0x60
	ALU_LSH   = 0x70
	ALU_NEG   = 0x80
	ALU_MOD   = 0x90
	ALU_SMOD  = 0x90
	ALU_XOR   = 0xa0
	ALU_MOV   = 0xb0
	ALU_MOVSX = 0xb0 // offset decides the bits
	ALU_ARSH  = 0xc0
	ALU_END   = 0xd0
)

// BPF_BYTE operations
const (
	BPF_TO_LE = 0x00
	BPF_TO_BE = 0x08
)

// BPF_JUMP operations
const (
	JMP_A    = 0x00
	JMP_EQ   = 0x10
	JMP_GT   = 0x20
	JMP_GE   = 0x30
	JMP_SET  = 0x40
	JMP_NE   = 0x50
	JMP_SGT  = 0x60
	JMP_SGE  = 0x70
	JMP_CALL = 0x80
	JMP_EXIT = 0x90
	JMP_LT   = 0xa0
	JMP_LE   = 0xb0
	JMP_SLT  = 0xc0
	JMP_SLE  = 0xd0
)

// BPF_MEMORY modes
const (
	BPF_IMM    = 0x00
	BPF_ABS    = 0x20
	BPF_IND    = 0x40
	BPF_MEM    = 0x60
	BPF_MEMSX  = 0x80
	BPF_ATOMIC = 0xc0
)

// BPF MEMORY sizes
const (
	SIZE_W  = 0x00
	SIZE_H  = 0x08
	SIZE_B  = 0x10
	SIZE_DW = 0x18
)

// ATOMIC operations
const (
	ATOMIC_ADD = ALU_ADD
	ATOMIC_OR  = ALU_OR
	ATOMIC_AND = ALU_AND
	ATOMIC_XOR = ALU_XOR
)

// ATOMIC modifiers
const (
	ATOMIC_FETCH   = 0x01
	ATOMIC_XCHG    = 0xe1
	ATOMIC_CMPXCHG = 0xf1
)

// NOP instruction (jump 0) - used to replace removed instructions
const NOP = "0500000000000000"

// 0x18	lddw dst, imm	dst = imm
// 0x20	ldabsw src, dst, imm	See kernel documentation
// 0x28	ldabsh src, dst, imm	...
// 0x30	ldabsb src, dst, imm	...
// 0x38	ldabsdw src, dst, imm	...
// 0x40	ldindw src, dst, imm	...
// 0x48	ldindh src, dst, imm	...
// 0x50	ldindb src, dst, imm	...
// 0x58	ldinddw src, dst, imm	...
// 0x61	ldxw dst, [src+off]	dst = *(uint32_t *) (src + off)
// 0x69	ldxh dst, [src+off]	dst = *(uint16_t *) (src + off)
// 0x71	ldxb dst, [src+off]	dst = *(uint8_t *) (src + off)
// 0x79	ldxdw dst, [src+off]	dst = *(uint64_t *) (src + off)
// 0x62	stw [dst+off], imm	*(uint32_t *) (dst + off) = imm
// 0x6a	sth [dst+off], imm	*(uint16_t *) (dst + off) = imm
// 0x72	stb [dst+off], imm	*(uint8_t *) (dst + off) = imm
// 0x7a	stdw [dst+off], imm	*(uint64_t *) (dst + off) = imm
// 0x63	stxw [dst+off], src	*(uint32_t *) (dst + off) = src
// 0x6b	stxh [dst+off], src	*(uint16_t *) (dst + off) = src
// 0x73	stxb [dst+off], src	*(uint8_t *) (dst + off) = src
// 0x7b	stxdw [dst+off], src	*(uint64_t *) (dst + off) = src
const (
	BPF_LDDW    = 0x18
	BPF_LDABSW  = 0x20
	BPF_LDABSH  = 0x28
	BPF_LDABSB  = 0x30
	BPF_LDABSDB = 0x38
	BPF_LDINDW  = 0x40
	BPF_LDINDH  = 0x48
	BPF_LDINDB  = 0x50
	BPF_LDINDDW = 0x58
	BPF_LDXW    = 0x61
	BPF_LDXH    = 0x69
	BPF_LDXB    = 0x71
	BPF_LDXDW   = 0x79
	BPF_STW     = 0x62
	BPF_STH     = 0x6a
	BPF_STB     = 0x72
	BPF_STDW    = 0x7a
	BPF_STXW    = 0x63
	BPF_STXH    = 0x6b
	BPF_STXB    = 0x73
	BPF_STXDW   = 0x7b
)
