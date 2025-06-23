package optimizer

import (
	"reflect"
	"testing"
)

func TestSection_buildControlFlowGraph(t *testing.T) {
	type fields struct {
		Name         string
		Instructions []*bpf.Instruction
		Dependencies []DependencyInfo
	}
	tests := []struct {
		name   string
		fields fields
		want   *ControlFlowGraph
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
			if got := s.buildControlFlowGraph(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("buildControlFlowGraph() = %v, want %v", got, tt.want)
			}
		})
	}
}
