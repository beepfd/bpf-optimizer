package optimizer

import "testing"

func TestSection_ProcessUsedRegisters(t *testing.T) {
	type fields struct {
		Name         string
		Instructions []*bpf.Instruction
		Dependencies []DependencyInfo
	}
	type args struct {
		instIdx  int
		analysis *InstructionAnalysis
		inst     *bpf.Instruction
		state    *RegisterState
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Section{
				Name:         tt.fields.Name,
				Instructions: tt.fields.Instructions,
				Dependencies: tt.fields.Dependencies,
			}
			s.ProcessUsedRegisters(tt.args.instIdx, tt.args.analysis, tt.args.inst, tt.args.state)
		})
	}
}
