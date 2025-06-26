package optimizer

import (
	"reflect"
	"testing"
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
