package optimizer

import (
	"bufio"
	"bytes"
	"log"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/beepfd/bpf-optimizer/pkg/bpf"
)

// Helper functions for parsing CSV data
func toInt(s string) int {
	if s == "None" || s == "" {
		return -1
	}
	val, _ := strconv.Atoi(s)
	return val
}

func toInt16(s string) int16 {
	if s == "None" || s == "" {
		return 0
	}
	val, _ := strconv.ParseInt(s, 10, 16)
	return int16(val)
}

func toIntSlice(s string) []int {
	if s == "[]" || s == "" {
		return []int{}
	}
	s = strings.Trim(s, "[]")
	if s == "" {
		return []int{}
	}
	parts := strings.Split(s, ",")
	result := make([]int, len(parts))
	for i, part := range parts {
		result[i], _ = strconv.Atoi(strings.TrimSpace(part))
	}
	return result
}

func toInt16Slice(s string) []int16 {
	if s == "[]" || s == "" {
		return []int16{}
	}
	s = strings.Trim(s, "[]")
	if s == "" {
		return []int16{}
	}
	parts := strings.Split(s, ",")
	result := make([]int16, len(parts))
	for i, part := range parts {
		val, _ := strconv.ParseInt(strings.TrimSpace(part), 10, 16)
		result[i] = int16(val)
	}
	return result
}

func loadAnalysisFromFile(filePath string) ([]*bpf.Instruction, []*InstructionAnalysis) {
	// b702000008000000,2,[],[],[],None,False,False
	// hexStr: b702000008000000
	// updated_reg: 2
	// updated_stack: []
	// used_reg: []
	// used_stack: []
	// offset: 0
	// is_call: False
	// is_exit: False
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatalf("Failed to read CSV file: %v", err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))

	analysis := make([]*InstructionAnalysis, 0)
	insns := make([]*bpf.Instruction, 0)

	for scanner.Scan() {
		line := scanner.Text()
		splited := strings.Split(line, "/")
		hexStr := splited[0]

		insn, err := bpf.NewInstruction(hexStr)
		if err != nil {
			log.Fatalf("Failed to create instruction: %v", err)
		}

		insns = append(insns, insn)
		analysis = append(analysis, &InstructionAnalysis{
			UpdatedReg:   toInt(splited[1]),
			UpdatedStack: toInt16Slice(splited[2]),
			UsedReg:      toIntSlice(splited[3]),
			UsedStack:    toInt16Slice(splited[4]),
			Offset:       toInt16(splited[5]),
			IsCall:       splited[6] == "True",
			IsExit:       splited[7] == "True",
		})
	}
	return insns, analysis
}

func TestAnalyzeInstructions(t *testing.T) {
	insns, analysis := loadAnalysisFromFile("../../testdata/analyz_result.csv")
	for i, insn := range insns {
		got := analyzeInstruction(insn)
		want := analysis[i]
		if !reflect.DeepEqual(got, want) {
			t.Errorf("index: %d, insn: %v, analyzeInstruction() = %v, want %v", i, insn, got, want)
		}

		// fmt.Printf("got: %v, want: %v\n", got, analysis[i])
	}
}

func TestAnalyzeInstruction(t *testing.T) {
	tests := []struct {
		name      string
		hexStr    string
		want      *InstructionAnalysis
		wantError bool
	}{
		{
			name:   "JMP_CALL",
			hexStr: "8500000001000000",
			want: &InstructionAnalysis{
				UpdatedReg:   0,
				UpdatedStack: []int16{},
				UsedReg:      []int{1, 2},
				UsedStack:    []int16{},
				Offset:       0,
				IsCall:       false,
				IsExit:       false,
			},
			wantError: false,
		},
		{
			name:   "LD immediate",
			hexStr: "79a1d0ff00000000",
			want: &InstructionAnalysis{
				UpdatedReg:   1,
				UpdatedStack: []int16{},
				UsedReg:      []int{},
				UsedStack:    []int16{-48, 64},
				Offset:       0,
				IsCall:       false,
				IsExit:       false,
			},
			wantError: false,
		},

		{
			name:   "JMP opcode 5",
			hexStr: "05005d0000000000",
			want: &InstructionAnalysis{
				UpdatedReg:   -1,
				UpdatedStack: []int16{},
				UsedReg:      []int{},
				UsedStack:    []int16{},
				Offset:       93,
				IsCall:       false,
				IsExit:       false,
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inst, err := bpf.NewInstruction(tt.hexStr)
			if (err != nil) != tt.wantError {
				t.Errorf("NewInstruction() error = %v, wantErr %v", err, tt.wantError)
				return
			}

			got := analyzeInstruction(inst)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("analyzeInstruction() = %v, want %v", got, tt.want)
			}
		})
	}
}
