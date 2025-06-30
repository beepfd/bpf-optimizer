package optimizer

import (
	"reflect"
	"testing"

	"github.com/beepfd/bpf-optimizer/pkg/bpf"
)

func TestMergeRegisterStates(t *testing.T) {
	type args struct {
		states []*RegisterState
	}
	tests := []struct {
		name string
		args args
		want *RegisterState
	}{
		{
			name: "空状态列表",
			args: args{
				states: []*RegisterState{},
			},
			want: NewRegisterState(),
		},
		{
			name: "单个状态",
			args: args{
				states: []*RegisterState{
					{
						Registers: [][]int{
							{5},    // r0
							{3, 7}, // r1
							{},     // r2
							{12},   // r3
							{}, {}, {}, {}, {}, {},
							{8}, // r10
						},
						Stacks: map[int16][]int{
							-8:  {15},
							-16: {20},
						},
						RegAlias: []int16{-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
					},
				},
			},
			want: &RegisterState{
				Registers: [][]int{
					{5},    // r0
					{3, 7}, // r1
					{},     // r2
					{12},   // r3
					{}, {}, {}, {}, {}, {},
					{8}, // r10
				},
				Stacks: map[int16][]int{
					-8:  {15},
					-16: {20},
				},
				RegAlias: []int16{-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
			},
		},
		{
			name: "多个状态合并",
			args: args{
				states: []*RegisterState{
					// 节点10的状态
					{
						Registers: [][]int{
							{5},    // r0
							{3, 7}, // r1
							{},     // r2
							{12},   // r3
							{}, {}, {}, {}, {}, {},
							{8}, // r10
						},
						Stacks: map[int16][]int{
							-8:  {15},
							-16: {20},
						},
						RegAlias: []int16{-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
					},
					// 节点25的状态
					{
						Registers: [][]int{
							{9},  // r0
							{3},  // r1
							{18}, // r2
							{},   // r3
							{}, {}, {}, {}, {}, {},
							{22}, // r10
						},
						Stacks: map[int16][]int{
							-8:  {25},
							-24: {30},
						},
						RegAlias: []int16{-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
					},
					// 节点40的状态
					{
						Registers: [][]int{
							{5, 35}, // r0
							{7},     // r1
							{},      // r2
							{},      // r3
							{}, {}, {}, {}, {}, {},
							{8}, // r10
						},
						Stacks: map[int16][]int{
							-16: {40},
							-24: {45},
						},
						RegAlias: []int16{-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
					},
				},
			},
			want: &RegisterState{
				Registers: [][]int{
					{5, 9, 35}, // r0: 合并并去重
					{3, 7},     // r1: 合并并去重
					{18},       // r2
					{12},       // r3
					{}, {}, {}, {}, {}, {},
					{8, 22}, // r10: 合并并去重
				},
				Stacks: map[int16][]int{
					-8:  {15, 25}, // 合并相同偏移量
					-16: {20, 40}, // 合并相同偏移量
					-24: {30, 45}, // 合并相同偏移量
				},
				RegAlias: []int16{-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
			},
		},
		{
			name: "包含重复依赖的合并测试",
			args: args{
				states: []*RegisterState{
					{
						Registers: [][]int{
							{1, 2, 3}, // r0
							{4, 5},    // r1
							{}, {}, {}, {}, {}, {}, {}, {},
							{6}, // r10
						},
						Stacks: map[int16][]int{
							-8: {10, 11},
						},
						RegAlias: []int16{-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
					},
					{
						Registers: [][]int{
							{2, 3, 7}, // r0: 包含重复的2, 3
							{5, 8},    // r1: 包含重复的5
							{}, {}, {}, {}, {}, {}, {}, {},
							{6, 9}, // r10: 包含重复的6
						},
						Stacks: map[int16][]int{
							-8:  {11, 12}, // 包含重复的11
							-16: {13},
						},
						RegAlias: []int16{-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
					},
				},
			},
			want: &RegisterState{
				Registers: [][]int{
					{1, 2, 3, 7}, // r0: 去重后的结果
					{4, 5, 8},    // r1: 去重后的结果
					{}, {}, {}, {}, {}, {}, {}, {},
					{6, 9}, // r10: 去重后的结果
				},
				Stacks: map[int16][]int{
					-8:  {10, 11, 12}, // 去重后的结果
					-16: {13},
				},
				RegAlias: []int16{-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MergeRegisterStates(tt.args.states); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MergeRegisterStates() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSection_findLoopCandidates(t *testing.T) {
	cfg, _, _, nodeDone, err := parseUpdatePropertyCandidatesArgs("../../testdata/update_property_candidates_args")
	if err != nil {
		t.Fatalf("Failed to parse update_property_init_args: %v", err)
	}

	insns, _ := loadAnalysisFromFile("../../testdata/analyz_result.csv")
	insns = insns[0:2257]
	section := &Section{
		Instructions: insns,
		Dependencies: make([]DependencyInfo, 0),
	}
	for i := 0; i < len(insns); i++ {
		section.Dependencies = append(section.Dependencies, DependencyInfo{
			Dependencies: make([]int, 0),
			DependedBy:   make([]int, 0),
		})
	}

	type fields struct {
		Name         string
		Instructions []*bpf.Instruction
		Dependencies []DependencyInfo
	}
	type args struct {
		cfg       *ControlFlowGraph
		nodesDone map[int]bool
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
	}{
		{
			name: "test",
			args: args{
				cfg:       cfg,
				nodesDone: nodeDone,
			},
			want: 2176,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Section{
				Name:         tt.fields.Name,
				Instructions: tt.fields.Instructions,
				Dependencies: tt.fields.Dependencies,
			}
			if got := s.findLoopCandidates(tt.args.cfg, tt.args.nodesDone); got != tt.want {
				t.Errorf("findLoopCandidates() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDetectLoopFixed(t *testing.T) {
	// Parse the test data
	cfg, _, _, _, err := parseUpdatePropertyCandidatesArgs("../../testdata/update_property_candidates_args")
	if err != nil {
		t.Fatalf("Failed to parse update_property_candidates_args: %v", err)
	}

	insns, _ := loadAnalysisFromFile("../../testdata/analyz_result.csv")
	insns = insns[0:2257]
	section := &Section{
		Instructions: insns,
		Dependencies: make([]DependencyInfo, 0),
	}
	for i := 0; i < len(insns); i++ {
		section.Dependencies = append(section.Dependencies, DependencyInfo{
			Dependencies: make([]int, 0),
			DependedBy:   make([]int, 0),
		})
	}

	// Test detectLoop with start=2176, stop=2176
	start := 2176
	stop := 2176

	visited := make(map[int]bool)
	result := section.detectLoop(start, stop, cfg.Nodes, visited)

	// The function should find the loop path: 2176 -> 2180 -> 2181 -> 2185 -> 2188 -> 2155 -> 2156 -> 2176
	// It should return the path without the final 2176: [2176 2180 2181 2185 2188 2155]
	expectedPath := []int{2176, 2180, 2181, 2185, 2188, 2155}

	if len(result) == 0 || contains(result, -1) {
		t.Errorf("Expected to find a loop, but got: %v", result)
		return
	}

	// Check that the result contains the expected nodes (order might differ due to removeDuplicates)
	resultSet := make(map[int]bool)
	for _, node := range result {
		resultSet[node] = true
	}

	expectedSet := make(map[int]bool)
	for _, node := range expectedPath {
		expectedSet[node] = true
	}

	if len(resultSet) != len(expectedSet) {
		t.Errorf("Expected path length %d, got %d. Expected: %v, Got: %v",
			len(expectedSet), len(resultSet), expectedPath, result)
		return
	}

	for node := range expectedSet {
		if !resultSet[node] {
			t.Errorf("Expected node %d in result, but not found. Expected: %v, Got: %v",
				node, expectedPath, result)
			return
		}
	}

	t.Logf("Successfully detected loop: %v", result)
}

func Test_buildLoopState(t *testing.T) {
	cfg, _, _, _, err := parseUpdatePropertyCandidatesArgs("../../testdata/update_property_candidates_args")
	if err != nil {
		t.Fatalf("Failed to parse update_property_candidates_args: %v", err)
	}

	type args struct {
		cfg      *ControlFlowGraph
		loopHead int
	}
	tests := []struct {
		name string
		args args
		want *RegisterState
	}{
		{
			name: "test",
			args: args{
				cfg:      cfg,
				loopHead: 2176,
			},
			want: &RegisterState{
				// new_regs = [[2133], [2130], [2131], [2135], [2134], [], [1667], [2128], [1658], [2046], []]
				Registers: [][]int{{2133}, {2130}, {2131}, {2135}, {2134}, {}, {1667}, {2128}, {1658}, {2046}, {}},
				// new_stack = {-56: [1657], -64: [1659], -48: [1660], -36: [1669], -72: [1999], -104: [2019], -32: [2020], -16: [2022], -96: [2023], -80: [2129], -112: [2044], -88: [2136]}
				Stacks:   map[int16][]int{-56: {1657}, -64: {1659}, -48: {1660}, -36: {1669}, -72: {1999}, -104: {2019}, -32: {2020}, -16: {2022}, -96: {2023}, -80: {2129}, -112: {2044}, -88: {2136}},
				RegAlias: []int16{-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildLoopState(tt.args.cfg, tt.args.loopHead); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("buildLoopState() = %v, want %v", got, tt.want)
			}
		})
	}
}
