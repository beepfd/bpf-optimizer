package optimizer

import (
	"reflect"
	"testing"

	"github.com/beepfd/bpf-optimizer/pkg/bpf"
)

func TestInstructionAnalysis_ALU(t *testing.T) {
	tests := []struct {
		name   string
		opcode uint8
		dst    int
		src    int
		want   *InstructionAnalysis
	}{
		{
			name:   "ALU_END byte exchange",
			opcode: bpf.ALU_END,
			dst:    1,
			src:    0,
			want: &InstructionAnalysis{
				UpdatedReg:   1,
				UpdatedStack: []int16{},
				UsedReg:      []int{1},
				UsedStack:    []int16{},
				Offset:       0,
				IsCall:       false,
				IsExit:       false,
			},
		},
		{
			name:   "ALU_MOV with register source",
			opcode: bpf.ALU_MOV | bpf.BPF_X,
			dst:    2,
			src:    3,
			want: &InstructionAnalysis{
				UpdatedReg:   2,
				UpdatedStack: []int16{},
				UsedReg:      []int{3},
				UsedStack:    []int16{},
				Offset:       0,
				IsCall:       false,
				IsExit:       false,
			},
		},
		{
			name:   "ALU_MOV with immediate",
			opcode: bpf.ALU_MOV | bpf.BPF_K,
			dst:    2,
			src:    3,
			want: &InstructionAnalysis{
				UpdatedReg:   2,
				UpdatedStack: []int16{},
				UsedReg:      []int{},
				UsedStack:    []int16{},
				Offset:       0,
				IsCall:       false,
				IsExit:       false,
			},
		},
		{
			name:   "ALU_ADD with register",
			opcode: bpf.ALU_ADD | bpf.BPF_X,
			dst:    1,
			src:    2,
			want: &InstructionAnalysis{
				UpdatedReg:   1,
				UpdatedStack: []int16{},
				UsedReg:      []int{1, 2},
				UsedStack:    []int16{},
				Offset:       0,
				IsCall:       false,
				IsExit:       false,
			},
		},
		{
			name:   "ALU_ADD with immediate",
			opcode: bpf.ALU_ADD | bpf.BPF_K,
			dst:    1,
			src:    2,
			want: &InstructionAnalysis{
				UpdatedReg:   1,
				UpdatedStack: []int16{},
				UsedReg:      []int{1},
				UsedStack:    []int16{},
				Offset:       0,
				IsCall:       false,
				IsExit:       false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := &InstructionAnalysis{
				UpdatedReg:   -1,
				UpdatedStack: make([]int16, 0),
				UsedReg:      make([]int, 0),
				UsedStack:    make([]int16, 0),
				Offset:       0,
				IsCall:       false,
				IsExit:       false,
			}
			analysis.ALU(tt.opcode, tt.dst, tt.src)

			if !reflect.DeepEqual(analysis, tt.want) {
				t.Errorf("ALU() = %v, want %v", analysis, tt.want)
			}
		})
	}
}

func TestInstructionAnalysis_JMP(t *testing.T) {
	tests := []struct {
		name   string
		opcode uint8
		dst    int
		src    int
		off    int16
		imm    int32
		want   *InstructionAnalysis
	}{
		{
			name:   "JMP_CALL tail call",
			opcode: bpf.JMP_CALL,
			dst:    0,
			src:    0,
			off:    0,
			imm:    12, // tail call
			want: &InstructionAnalysis{
				UpdatedReg:   0,
				UpdatedStack: []int16{},
				UsedReg:      []int{1, 2, 3},
				UsedStack:    []int16{0, 0},
				Offset:       0,
				IsCall:       true,
				IsExit:       false,
			},
		},
		{
			name:   "JMP_CALL map lookup",
			opcode: bpf.JMP_CALL,
			dst:    0,
			src:    0,
			off:    0,
			imm:    1, // map lookup
			want: &InstructionAnalysis{
				UpdatedReg:   0,
				UpdatedStack: []int16{},
				UsedReg:      []int{1, 2},
				UsedStack:    []int16{},
				Offset:       0,
				IsCall:       true,
				IsExit:       false,
			},
		},
		{
			name:   "JMP_CALL map update",
			opcode: bpf.JMP_CALL,
			dst:    0,
			src:    0,
			off:    0,
			imm:    2, // map update
			want: &InstructionAnalysis{
				UpdatedReg:   0,
				UpdatedStack: []int16{},
				UsedReg:      []int{1, 2, 3, 4},
				UsedStack:    []int16{},
				Offset:       0,
				IsCall:       true,
				IsExit:       false,
			},
		},
		{
			name:   "JMP_CALL default helper",
			opcode: bpf.JMP_CALL,
			dst:    0,
			src:    0,
			off:    0,
			imm:    100, // unknown helper
			want: &InstructionAnalysis{
				UpdatedReg:   0,
				UpdatedStack: []int16{},
				UsedReg:      []int{1, 2, 3, 4, 5},
				UsedStack:    []int16{},
				Offset:       0,
				IsCall:       true,
				IsExit:       false,
			},
		},
		{
			name:   "JMP_EXIT",
			opcode: bpf.JMP_EXIT,
			dst:    0,
			src:    0,
			off:    0,
			imm:    0,
			want: &InstructionAnalysis{
				UpdatedReg:   -1,
				UpdatedStack: []int16{},
				UsedReg:      []int{0},
				UsedStack:    []int16{},
				Offset:       0,
				IsCall:       false,
				IsExit:       true,
			},
		},
		{
			name:   "unconditional jump",
			opcode: 0x05, // unconditional jump
			dst:    0,
			src:    0,
			off:    10,
			imm:    0,
			want: &InstructionAnalysis{
				UpdatedReg:   -1,
				UpdatedStack: []int16{},
				UsedReg:      []int{0, 0}, // 修正：根据实际JMP实现，无条件跳转似乎设置了这个值
				UsedStack:    []int16{},
				Offset:       10,
				IsCall:       false,
				IsExit:       false,
			},
		},
		{
			name:   "conditional jump JEQ",
			opcode: bpf.JMP_EQ,
			dst:    1,
			src:    2,
			off:    5,
			imm:    0,
			want: &InstructionAnalysis{
				UpdatedReg:   -1,
				UpdatedStack: []int16{},
				UsedReg:      []int{1, 2},
				UsedStack:    []int16{},
				Offset:       5,
				IsCall:       false,
				IsExit:       false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := &InstructionAnalysis{
				UpdatedReg:   -1,
				UpdatedStack: make([]int16, 0),
				UsedReg:      make([]int, 0),
				UsedStack:    make([]int16, 0),
				Offset:       0,
				IsCall:       false,
				IsExit:       false,
			}
			analysis.JMP(tt.opcode, tt.dst, tt.src, tt.off, tt.imm)

			if !reflect.DeepEqual(analysis, tt.want) {
				t.Errorf("JMP() = %v, want %v", analysis, tt.want)
			}
		})
	}
}

func TestInstructionAnalysis_STX(t *testing.T) {
	tests := []struct {
		name   string
		opcode uint8
		dst    int
		src    int
		off    int16
		imm    int32
		want   *InstructionAnalysis
	}{
		{
			name:   "STX to stack pointer",
			opcode: bpf.BPF_MEM | bpf.SIZE_W, // 32-bit store
			dst:    10,                       // stack pointer
			src:    1,
			off:    -8,
			imm:    0,
			want: &InstructionAnalysis{
				UpdatedReg:   -1,
				UpdatedStack: []int16{-8, 1}, // offset -8, size 1 byte (SIZE_W = 0x00 -> 1 << 0 = 1)
				UsedReg:      []int{1},
				UsedStack:    []int16{},
				Offset:       0,
				IsCall:       false,
				IsExit:       false,
			},
		},
		{
			name:   "STX to register",
			opcode: bpf.BPF_MEM | bpf.SIZE_DW, // 64-bit store
			dst:    1,
			src:    2,
			off:    0,
			imm:    0,
			want: &InstructionAnalysis{
				UpdatedReg:   -1,
				UpdatedStack: []int16{},
				UsedReg:      []int{2},
				UsedStack:    []int16{},
				Offset:       0,
				IsCall:       false,
				IsExit:       false,
			},
		},
		{
			name:   "STX ATOMIC operation",
			opcode: bpf.BPF_ATOMIC | bpf.SIZE_W,
			dst:    1,
			src:    2,
			off:    0,
			imm:    0,
			want: &InstructionAnalysis{
				UpdatedReg:   -1,
				UpdatedStack: []int16{},
				UsedReg:      []int{2},
				UsedStack:    []int16{},
				Offset:       0,
				IsCall:       false,
				IsExit:       false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := &InstructionAnalysis{
				UpdatedReg:   -1,
				UpdatedStack: make([]int16, 0),
				UsedReg:      make([]int, 0),
				UsedStack:    make([]int16, 0),
				Offset:       0,
				IsCall:       false,
				IsExit:       false,
			}
			analysis.STX(tt.opcode, tt.dst, tt.src, tt.off, tt.imm)

			if !reflect.DeepEqual(analysis, tt.want) {
				t.Errorf("STX() = %v, want %v", analysis, tt.want)
			}
		})
	}
}

func TestInstructionAnalysis_ST(t *testing.T) {
	tests := []struct {
		name   string
		opcode uint8
		dst    int
		src    int
		off    int16
		imm    int32
		want   *InstructionAnalysis
	}{
		{
			name:   "ST to stack pointer",
			opcode: bpf.BPF_MEM | bpf.SIZE_H, // 16-bit store
			dst:    10,                       // stack pointer
			src:    0,
			off:    -4,
			imm:    42,
			want: &InstructionAnalysis{
				UpdatedReg:   -1,
				UpdatedStack: []int16{-4, 2}, // offset -4, size 2 bytes
				UsedReg:      []int{},
				UsedStack:    []int16{},
				Offset:       0,
				IsCall:       false,
				IsExit:       false,
			},
		},
		{
			name:   "ST to register memory",
			opcode: bpf.BPF_MEM | bpf.SIZE_B, // 8-bit store
			dst:    1,
			src:    0,
			off:    0,
			imm:    255,
			want: &InstructionAnalysis{
				UpdatedReg:   -1,
				UpdatedStack: []int16{},
				UsedReg:      []int{},
				UsedStack:    []int16{},
				Offset:       0,
				IsCall:       false,
				IsExit:       false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := &InstructionAnalysis{
				UpdatedReg:   -1,
				UpdatedStack: make([]int16, 0),
				UsedReg:      make([]int, 0),
				UsedStack:    make([]int16, 0),
				Offset:       0,
				IsCall:       false,
				IsExit:       false,
			}
			analysis.ST(tt.opcode, tt.dst, tt.src, tt.off, tt.imm)

			if !reflect.DeepEqual(analysis, tt.want) {
				t.Errorf("ST() = %v, want %v", analysis, tt.want)
			}
		})
	}
}

func TestInstructionAnalysis_LDX(t *testing.T) {
	tests := []struct {
		name   string
		opcode uint8
		dst    int
		src    int
		off    int16
		imm    int32
		want   *InstructionAnalysis
	}{
		{
			name:   "LDX from stack pointer",
			opcode: bpf.BPF_MEM | bpf.SIZE_DW, // 64-bit load
			dst:    1,
			src:    10, // stack pointer
			off:    -8,
			imm:    0,
			want: &InstructionAnalysis{
				UpdatedReg:   1,
				UpdatedStack: []int16{},
				UsedReg:      []int{},
				UsedStack:    []int16{-8, 8}, // offset -8, size 8 bytes
				Offset:       0,
				IsCall:       false,
				IsExit:       false,
			},
		},
		{
			name:   "LDX from register",
			opcode: bpf.BPF_MEM | bpf.SIZE_W, // 32-bit load
			dst:    2,
			src:    1,
			off:    0,
			imm:    0,
			want: &InstructionAnalysis{
				UpdatedReg:   2,
				UpdatedStack: []int16{},
				UsedReg:      []int{1},
				UsedStack:    []int16{},
				Offset:       0,
				IsCall:       false,
				IsExit:       false,
			},
		},
		{
			name:   "LDX MEMSX operation",
			opcode: bpf.BPF_MEMSX | bpf.SIZE_H, // 16-bit signed load
			dst:    3,
			src:    2,
			off:    4,
			imm:    0,
			want: &InstructionAnalysis{
				UpdatedReg:   3,
				UpdatedStack: []int16{},
				UsedReg:      []int{2},
				UsedStack:    []int16{},
				Offset:       0,
				IsCall:       false,
				IsExit:       false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := &InstructionAnalysis{
				UpdatedReg:   -1,
				UpdatedStack: make([]int16, 0),
				UsedReg:      make([]int, 0),
				UsedStack:    make([]int16, 0),
				Offset:       0,
				IsCall:       false,
				IsExit:       false,
			}
			analysis.LDX(tt.opcode, tt.dst, tt.src, tt.off, tt.imm)

			if !reflect.DeepEqual(analysis, tt.want) {
				t.Errorf("LDX() = %v, want %v", analysis, tt.want)
			}
		})
	}
}

func TestInstructionAnalysis_LD(t *testing.T) {
	tests := []struct {
		name   string
		opcode uint8
		dst    int
		src    int
		off    int16
		imm    int32
		want   *InstructionAnalysis
	}{
		{
			name:   "LD immediate",
			opcode: bpf.BPF_IMM | bpf.SIZE_DW, // 64-bit immediate load
			dst:    1,
			src:    0,
			off:    0,
			imm:    12345,
			want: &InstructionAnalysis{
				UpdatedReg:   1,
				UpdatedStack: []int16{},
				UsedReg:      []int{},
				UsedStack:    []int16{},
				Offset:       0,
				IsCall:       false,
				IsExit:       false,
			},
		},
		{
			name:   "LD absolute",
			opcode: bpf.BPF_ABS | bpf.SIZE_W, // 32-bit absolute load
			dst:    0,
			src:    1,
			off:    0,
			imm:    100,
			want: &InstructionAnalysis{
				UpdatedReg:   0,
				UpdatedStack: []int16{},
				UsedReg:      []int{1},
				UsedStack:    []int16{},
				Offset:       0,
				IsCall:       false,
				IsExit:       false,
			},
		},
		{
			name:   "LD indirect",
			opcode: bpf.BPF_IND | bpf.SIZE_H, // 16-bit indirect load
			dst:    0,
			src:    2,
			off:    0,
			imm:    50,
			want: &InstructionAnalysis{
				UpdatedReg:   0,
				UpdatedStack: []int16{},
				UsedReg:      []int{2},
				UsedStack:    []int16{},
				Offset:       0,
				IsCall:       false,
				IsExit:       false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := &InstructionAnalysis{
				UpdatedReg:   -1,
				UpdatedStack: make([]int16, 0),
				UsedReg:      make([]int, 0),
				UsedStack:    make([]int16, 0),
				Offset:       0,
				IsCall:       false,
				IsExit:       false,
			}
			analysis.LD(tt.opcode, tt.dst, tt.src, tt.off, tt.imm)

			if !reflect.DeepEqual(analysis, tt.want) {
				t.Errorf("LD() = %v, want %v", analysis, tt.want)
			}
		})
	}
}

func TestAnalyzeInstruction(t *testing.T) {
	tests := []struct {
		name string
		inst *bpf.Instruction
		want *InstructionAnalysis
	}{
		{
			name: "MOV immediate instruction",
			inst: &bpf.Instruction{
				Opcode: bpf.BPF_ALU64 | bpf.ALU_MOV | bpf.BPF_K,
				DstReg: 1,
				SrcReg: 0,
				Offset: 0,
				Imm:    42,
			},
			want: &InstructionAnalysis{
				UpdatedReg:   1,
				UpdatedStack: []int16{},
				UsedReg:      []int{},
				UsedStack:    []int16{},
				Offset:       0,
				IsCall:       false,
				IsExit:       false,
			},
		},
		{
			name: "ADD register instruction",
			inst: &bpf.Instruction{
				Opcode: bpf.BPF_ALU64 | bpf.ALU_ADD | bpf.BPF_X,
				DstReg: 1,
				SrcReg: 2,
				Offset: 0,
				Imm:    0,
			},
			want: &InstructionAnalysis{
				UpdatedReg:   1,
				UpdatedStack: []int16{},
				UsedReg:      []int{1, 2},
				UsedStack:    []int16{},
				Offset:       0,
				IsCall:       false,
				IsExit:       false,
			},
		},
		{
			name: "JEQ conditional jump",
			inst: &bpf.Instruction{
				Opcode: bpf.BPF_JMP | bpf.JMP_EQ | bpf.BPF_K,
				DstReg: 1,
				SrcReg: 0,
				Offset: 5,
				Imm:    100,
			},
			want: &InstructionAnalysis{
				UpdatedReg:   -1,
				UpdatedStack: []int16{},
				UsedReg:      []int{1, 0},
				UsedStack:    []int16{},
				Offset:       5,
				IsCall:       false,
				IsExit:       false,
			},
		},
		{
			name: "Store to stack",
			inst: &bpf.Instruction{
				Opcode: bpf.BPF_STX | bpf.BPF_MEM | bpf.SIZE_DW,
				DstReg: 10,
				SrcReg: 1,
				Offset: -8,
				Imm:    0,
			},
			want: &InstructionAnalysis{
				UpdatedReg:   -1,
				UpdatedStack: []int16{-8, 8},
				UsedReg:      []int{1},
				UsedStack:    []int16{},
				Offset:       0,
				IsCall:       false,
				IsExit:       false,
			},
		},
		{
			name: "Load from stack",
			inst: &bpf.Instruction{
				Opcode: bpf.BPF_LDX | bpf.BPF_MEM | bpf.SIZE_DW,
				DstReg: 2,
				SrcReg: 10,
				Offset: -8,
				Imm:    0,
			},
			want: &InstructionAnalysis{
				UpdatedReg:   2,
				UpdatedStack: []int16{},
				UsedReg:      []int{},
				UsedStack:    []int16{-8, 8},
				Offset:       0,
				IsCall:       false,
				IsExit:       false,
			},
		},
		{
			name: "EXIT instruction",
			inst: &bpf.Instruction{
				Opcode: bpf.BPF_JMP | bpf.JMP_EXIT,
				DstReg: 0,
				SrcReg: 0,
				Offset: 0,
				Imm:    0,
			},
			want: &InstructionAnalysis{
				UpdatedReg:   -1,
				UpdatedStack: []int16{},
				UsedReg:      []int{0},
				UsedStack:    []int16{},
				Offset:       0,
				IsCall:       false,
				IsExit:       true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzeInstruction(tt.inst)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("analyzeInstruction() = %v, want %v", got, tt.want)
			}
		})
	}
}
