package optimizer

import (
	"reflect"
	"testing"

	"github.com/beepfd/bpf-optimizer/pkg/bpf"
)

var (
	step1NextNodes = map[int]bool{899: true, 578: true, 215: true, 784: true, 306: true, 36: true, 3: true, 839: true, 1608: true, 152: true, 1656: true, 1257: true, 282: true, 1218: true, 330: true}
)

func TestSection_findNextNode(t *testing.T) {
	cfg, _, _, err := parseUpdatePropertyInitArgs("../../testdata/update_property_init_args")
	if err != nil {
		t.Fatalf("Failed to parse update_property_init_args: %v", err)
	}

	insns, _ := loadAnalysisFromFile("../../testdata/analyz_result.csv")
	insns = insns[0:2257]
	section := &Section{
		Instructions: insns,
		Dependencies: make([]DependencyInfo, 0),
	}

	cfg2 := cfg.Clone()
	cfg2.NodeStats = map[int]*RegisterState{
		1656: {
			// regs = [[1674], [1672], [1671], [], [], [], [1667], [1656], [1658], [1668], []]
			Registers: [][]int{
				{1674},
				{1672},
				{1671},
				{},
				{},
				{},
				{1667},
				{1656},
				{1658},
				{1668},
				{},
			},
			// stack = {-56: [1657], -64: [1659], -48: [1660], -36: [1669]}
			Stacks: map[int16][]int{
				-56: {1657},
				-64: {1659},
				-48: {1660},
				-36: {1669},
			},
			RegAlias: NewRegisterState().RegAlias,
		},
	}

	type fields struct {
		Name         string
		Instructions []*bpf.Instruction
		Dependencies []DependencyInfo
	}
	type args struct {
		cfg       *ControlFlowGraph
		nodesDone map[int]bool
		loopInfo  *LoopInfo
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  *RegisterState
	}{
		{
			name: "step1",
			fields: fields{
				Name:         "test",
				Instructions: insns,
				Dependencies: section.Dependencies,
			},
			args: args{
				cfg:       cfg,
				nodesDone: map[int]bool{0: true},
				loopInfo:  nil,
			},
			want:  1656,
			want1: NewRegisterState(),
		},

		{
			name: "step2",
			fields: fields{
				Name:         "test",
				Instructions: insns,
				Dependencies: section.Dependencies,
			},
			args: args{
				cfg:       cfg2,
				nodesDone: map[int]bool{0: true, 1656: true},
				loopInfo:  nil,
			},
			want: 1675,
			want1: &RegisterState{
				// new_regs = [[1674], [1672], [1671], [], [], [], [1667], [1656], [1658], [1668], []]
				Registers: [][]int{
					{1674},
					{1672},
					{1671},
					{},
					{},
					{},
					{1667},
					{1656},
					{1658},
					{1668},
					{},
				},
				// new_stack = {-56: [1657], -64: [1659], -48: [1660], -36: [1669]}
				Stacks: map[int16][]int{
					-56: {1657},
					-64: {1659},
					-48: {1660},
					-36: {1669},
				},
				RegAlias: NewRegisterState().RegAlias,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Section{
				Name:         tt.fields.Name,
				Instructions: tt.fields.Instructions,
				Dependencies: tt.fields.Dependencies,
			}
			got, got1 := s.findNextNode(tt.args.cfg, tt.args.nodesDone, tt.args.loopInfo)
			if got != tt.want {
				t.Errorf("findNextNode() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("findNextNode() got1 = %v, want %v", got1, tt.want1)
			}

			t.Logf("got = %v, got1 = %v", got, got1)
		})
	}
}
