package optimizer

import (
	"testing"

	"github.com/beepfd/bpf-optimizer/pkg/bpf"
	"github.com/beepfd/bpf-optimizer/tool"
)

func Test_buildInstructionNode(t *testing.T) {
	cfgs, err := parseControlFlowGraphFromFiles(
		"../../testdata/dep_nodes_step1",
		"../../testdata/dep_nodes_rev",
		"../../testdata/dep_nodes_len",
	)
	if err != nil {
		t.Fatalf("Failed to parse control flow graphs: %v", err)
	}

	type args struct {
		elfPath string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "match merlin generated elf",
			args: args{
				elfPath: "../../testdata/bpf_generic_uprobe_v61.o",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sections, err := buildInstruction(tt.args.elfPath)
			if err != nil {
				t.Fatalf("Failed to build instruction: %v", err)
			}

			cfg := &ControlFlowGraph{
				Nodes:     make(map[int][]int),
				NodesRev:  make(map[int][]int),
				NodesLen:  make(map[int]int),
				NodeStats: make(map[int]*RegisterState),
			}

			// 此处只需要测试第一个 section 的节点
			// 因为该 section 为 .text 段，包含了所有函数
			buildInstructionNode(sections[0].Instructions, cfg)
			buildInstructionNodeReverse(cfg)
			buildInstructionNodeLength(sections[0].Instructions, cfg)

			got := cfg.Nodes
			want := cfgs[0].Nodes
			if !tool.CompareIntSliceMap(got, want) {
				errors := []string{"Nodes maps differ"}
				errors = append(errors, tool.FormatMapDifference("Nodes", got, want))
				if len(errors) > 0 {
					t.Errorf("ControlFlowGraph comparison failed: %v", errors)
				}
			}

			gotNodesLen := cfg.NodesLen
			wantNodesLen := cfgs[0].NodesLen
			if !tool.CompareIntIntMap(gotNodesLen, wantNodesLen) {
				errors := []string{"NodesLen maps differ"}
				errors = append(errors, tool.FormatIntMapDifference("NodesLen", gotNodesLen, wantNodesLen))
				if len(errors) > 0 {
					t.Errorf("ControlFlowGraph comparison failed: %v", errors)
				}
			}
		})
	}
}

func Test_buildInstructionNodeRev(t *testing.T) {
	cfgs, err := parseControlFlowGraphFromFiles(
		"../../testdata/dep_nodes",
		"../../testdata/dep_nodes_rev",
		"../../testdata/dep_nodes_len",
	)
	if err != nil {
		t.Fatalf("Failed to parse control flow graphs: %v", err)
	}

	type args struct {
		elfPath string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "match merlin generated elf",
			args: args{
				elfPath: "../../testdata/bpf_generic_uprobe_v61.o",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sections, err := buildInstruction(tt.args.elfPath)
			if err != nil {
				t.Fatalf("Failed to build instruction: %v", err)
			}

			cfg := &ControlFlowGraph{
				Nodes:     make(map[int][]int),
				NodesRev:  make(map[int][]int),
				NodesLen:  make(map[int]int),
				NodeStats: make(map[int]*RegisterState),
			}

			// 此处只需要测试第一个 section 的节点
			// 因为该 section 为 .text 段，包含了所有函数
			buildInstructionNode(sections[0].Instructions, cfg)
			buildInstructionNodeReverse(cfg)
			buildInstructionNodeLength(sections[0].Instructions, cfg)
			rebuildInstructionNodeRev(sections[0].Instructions, cfg)
			updateInstructionNode(cfg)

			got := cfg.Nodes
			want := cfgs[0].Nodes
			if !tool.CompareIntSliceMap(got, want) {
				errors := []string{"Nodes maps differ"}
				errors = append(errors, tool.FormatMapDifference("Nodes", got, want))
				if len(errors) > 0 {
					t.Errorf("ControlFlowGraph comparison failed: %v", errors)
				}
			}

			gotNodesLen := cfg.NodesLen
			wantNodesLen := cfgs[0].NodesLen
			if !tool.CompareIntIntMap(gotNodesLen, wantNodesLen) {
				errors := []string{"NodesLen maps differ"}
				errors = append(errors, tool.FormatIntMapDifference("NodesLen", gotNodesLen, wantNodesLen))
				if len(errors) > 0 {
					t.Errorf("ControlFlowGraph comparison failed: %v", errors)
				}
			}

			gotNodesRev := cfg.NodesRev
			wantNodesRev := cfgs[0].NodesRev
			if !tool.CompareIntSliceMap(gotNodesRev, wantNodesRev) {
				errors := []string{"NodesRev maps differ"}
				errors = append(errors, tool.FormatMapDifference("NodesRev", gotNodesRev, wantNodesRev))
				if len(errors) > 0 {
					t.Errorf("ControlFlowGraph comparison failed: %v", errors)
				}
			}
		})
	}
}

func Test_buildInstructionNodeSingleInstruction(t *testing.T) {
	type args struct {
		hex string
	}
	tests := []struct {
		name string
		args args
		want map[int][]int
	}{
		{
			name: "test",
			args: args{
				hex: "0500000000000000",
			},
			want: map[int][]int{
				0: {1},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inst, err := bpf.NewInstruction(tt.args.hex)
			if err != nil {
				t.Fatalf("Failed to parse instruction: %v", err)
			}

			cfg := &ControlFlowGraph{
				Nodes:     make(map[int][]int),
				NodesRev:  make(map[int][]int),
				NodesLen:  make(map[int]int),
				NodeStats: make(map[int]*RegisterState),
			}

			buildInstructionNode([]*bpf.Instruction{inst}, cfg)
			got := cfg.Nodes
			want := tt.want
			if !tool.CompareIntSliceMap(got, want) {
				errors := []string{"Nodes maps differ"}
				errors = append(errors, tool.FormatMapDifference("Nodes", got, want))
				if len(errors) > 0 {
					t.Errorf("ControlFlowGraph comparison failed: %v", errors)
				}
			}
		})
	}
}
