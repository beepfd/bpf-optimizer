package bpf

import (
	"bufio"
	"bytes"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func buildTestInstructionFromFile(testFile string) (hexStr string, want []*Instruction) {
	raw, err := os.ReadFile(testFile)
	if err != nil {
		panic(err)
	}

	want = make([]*Instruction, 0)
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	// b700000001000000,183,0,0,0,1
	// hexStr: b700000001000000
	// opcode: 183
	// srcReg: 0
	// dstReg: 0
	// offset: 0
	// imm: 1
	for scanner.Scan() {
		line := scanner.Text()
		splited := strings.Split(line, ",")
		hexStr += splited[0]

		opcode, _ := strconv.ParseUint(splited[1], 10, 8)
		srcReg, _ := strconv.ParseUint(splited[2], 10, 8)
		dstReg, _ := strconv.ParseUint(splited[3], 10, 8)
		offset, _ := strconv.ParseInt(splited[4], 10, 16)
		imm, _ := strconv.ParseInt(splited[5], 10, 32)

		want = append(want, &Instruction{
			Raw:    splited[0],
			Opcode: uint8(opcode),
			SrcReg: uint8(srcReg),
			DstReg: uint8(dstReg),
			Offset: int16(offset),
			Imm:    int32(imm),
		})
	}
	return hexStr, want
}

func TestNewInstruction(t *testing.T) {
	type args struct {
		hexStr string
	}

	hexStr, want := buildTestInstructionFromFile("../../testdata/bpf_generic_uprobe_v61_codebytes_test.csv")

	tests := []struct {
		name    string
		args    args
		want    []*Instruction
		wantErr bool
	}{
		{
			name: "tetragon bpf_generic_uprobe_v61 codebytes",
			args: args{
				hexStr: hexStr,
			},
			want:    want,
			wantErr: false,
		},
		{
			name: "single instruction",
			args: args{
				hexStr: "07010000d0feffff",
			},
			want: []*Instruction{
				// 07010000d0feffff 7 0 1 0 -304
				{Raw: "07010000d0feffff", Opcode: 7, DstReg: 1, SrcReg: 0, Offset: 0, Imm: -304},
			},
			wantErr: false,
		},
		{
			name: "multiple instructions",
			// 00000000000009f8 <LBB7_53>:
			// 319:       bf 71 00 00 00 00 00 00 r1 = r7
			// 320:       07 01 00 00 40 00 00 00 r1 += 0x40
			// 321:       b7 02 00 00 01 00 00 00 r2 = 0x1
			// 322:       15 02 08 00 00 00 00 00 if r2 == 0x0 goto +0x8 <LBB7_55>
			// 323:       bf a2 00 00 00 00 00 00 r2 = r10
			// 324:       07 02 00 00 a8 ff ff ff r2 += -0x58
			// 325:       79 23 40 00 00 00 00 00 r3 = *(u64 *)(r2 + 0x40)
			// 326:       b7 02 00 00 10 00 00 00 r2 = 0x10
			// 327:       0f 23 00 00 00 00 00 00 r3 += r2
			// 328:       b7 02 00 00 04 00 00 00 r2 = 0x4
			// 329:       85 00 00 00 04 00 00 00 call 0x4
			// 330:       05 00 02 00 00 00 00 00 goto +0x2 <LBB7_56>
			args: args{
				hexStr: "bf71000000000000" +
					"0701000040000000" +
					"b702000001000000" +
					"1502080000000000" +
					"bfa2000000000000" +
					"07020000a8ffffff" +
					"7923400000000000" +
					"b702000010000000" +
					"0f23000000000000" +
					"b702000004000000" +
					"8500000004000000" +
					"0500020000000000",
			},
			want: []*Instruction{
				{Raw: "bf71000000000000", Opcode: 191, DstReg: 1, SrcReg: 7, Offset: 0, Imm: 0},
				{Raw: "0701000040000000", Opcode: 7, DstReg: 1, SrcReg: 0, Offset: 0, Imm: 64},
				{Raw: "b702000001000000", Opcode: 183, DstReg: 2, SrcReg: 0, Offset: 0, Imm: 1},
				{Raw: "1502080000000000", Opcode: 21, DstReg: 2, SrcReg: 0, Offset: 8, Imm: 0},
				{Raw: "bfa2000000000000", Opcode: 191, DstReg: 2, SrcReg: 10, Offset: 0, Imm: 0},
				{Raw: "07020000a8ffffff", Opcode: 7, DstReg: 2, SrcReg: 0, Offset: 0, Imm: -88},
				{Raw: "7923400000000000", Opcode: 121, DstReg: 3, SrcReg: 2, Offset: 64, Imm: 0},
				{Raw: "b702000010000000", Opcode: 183, DstReg: 2, SrcReg: 0, Offset: 0, Imm: 16},
				{Raw: "0f23000000000000", Opcode: 15, DstReg: 3, SrcReg: 2, Offset: 0, Imm: 0},
				{Raw: "b702000004000000", Opcode: 183, DstReg: 2, SrcReg: 0, Offset: 0, Imm: 4},
				{Raw: "8500000004000000", Opcode: 133, DstReg: 0, SrcReg: 0, Offset: 0, Imm: 4},
				{Raw: "0500020000000000", Opcode: 5, DstReg: 0, SrcReg: 0, Offset: 2, Imm: 0},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var count int = 0
			for i := 0; i < len(tt.args.hexStr); i += 16 {
				got, err := NewInstruction(tt.args.hexStr[i : i+16])
				if (err != nil) != tt.wantErr {
					t.Errorf("NewInstruction() error = %v, wantErr %v", err, tt.wantErr)
					return
				}

				// fmt.Printf("got: %v, want: %v\n", got, tt.want[count])
				if !reflect.DeepEqual(got, tt.want[count]) {
					t.Errorf("NewInstruction() got = %v, want %v", got, tt.want[count])
				}
				count++
			}

		})
	}
}
