package optimizer

import "testing"

func Test_buildInstructionNode(t *testing.T) {
	type args struct {
		insts []*bpf.Instruction
		cfg   *ControlFlowGraph
	}
	tests := []struct {
		name string
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buildInstructionNode(tt.args.insts, tt.args.cfg)
		})
	}
}
