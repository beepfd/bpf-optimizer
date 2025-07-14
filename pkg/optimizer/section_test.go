package optimizer

import (
	"os"
	"reflect"
	"testing"

	"github.com/beepfd/bpf-optimizer/tool"
)

func TestNewSectionWithoutOptimizer(t *testing.T) {
	deps := buildFakeDependencies("../../testdata/dep_node_stat_index1_result")
	cfgs, err := parseControlFlowGraphFromFiles(
		"../../testdata/dep_nodes",
		"../../testdata/dep_nodes_rev",
		"../../testdata/dep_nodes_len",
	)
	if err != nil {
		t.Fatalf("Failed to parse control flow graphs: %v", err)
	}

	type args struct {
		hexDataFile string
		name        string
	}
	tests := []struct {
		name    string
		args    args
		want    *Section
		wantErr bool
	}{
		{
			name: "test1",
			args: args{
				hexDataFile: "../../testdata/section_data",
				name:        ".text",
			},
			want: &Section{
				Name:         ".text",
				Dependencies: deps,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hexData, err := os.ReadFile(tt.args.hexDataFile)
			if err != nil {
				t.Errorf("NewSection() error = %v", err)
				return
			}
			got, err := NewSection(string(hexData), tt.args.name, true)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSection() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			gotCFG := got.ControlFlowGraph
			wantCFG := cfgs[0]
			if !tool.CompareIntSliceMap(gotCFG.Nodes, wantCFG.Nodes) {
				errors := []string{"Nodes maps differ"}
				errors = append(errors, tool.FormatMapDifference("Nodes", gotCFG.Nodes, wantCFG.Nodes))
				if len(errors) > 0 {
					t.Errorf("ControlFlowGraph comparison failed: %v", errors)
				}
			}

			gotNodesLen := gotCFG.NodesLen
			wantNodesLen := cfgs[0].NodesLen
			if !tool.CompareIntIntMap(gotNodesLen, wantNodesLen) {
				errors := []string{"NodesLen maps differ"}
				errors = append(errors, tool.FormatIntMapDifference("NodesLen", gotNodesLen, wantNodesLen))
				if len(errors) > 0 {
					t.Errorf("ControlFlowGraph comparison failed: %v", errors)
				}
			}

			gotNodesRev := gotCFG.NodesRev
			wantNodesRev := cfgs[0].NodesRev
			if !tool.CompareIntSliceMap(gotNodesRev, wantNodesRev) {
				errors := []string{"NodesRev maps differ"}
				errors = append(errors, tool.FormatMapDifference("NodesRev", gotNodesRev, wantNodesRev))
				if len(errors) > 0 {
					t.Errorf("ControlFlowGraph comparison failed: %v", errors)
				}
			}

			if len(got.Dependencies) != len(tt.want.Dependencies) {
				t.Errorf("NewSection() got = %v, want %v", got.Dependencies, tt.want.Dependencies)
				return
			}
			for i := range got.Dependencies {
				if !reflect.DeepEqual(
					got.Dependencies[i].Deduplication().Dependencies,
					tt.want.Dependencies[i].Deduplication().Dependencies,
				) {
					t.Errorf("NewSection() dependencies index %d got = %v, want %v",
						i, got.Dependencies[i].Deduplication().Dependencies, tt.want.Dependencies[i].Deduplication().Dependencies)
				}

				if !reflect.DeepEqual(
					got.Dependencies[i].Deduplication().DependedBy,
					tt.want.Dependencies[i].Deduplication().DependedBy,
				) {
					t.Errorf("NewSection() dependedby index %d got = %v, want %v",
						i, got.Dependencies[i].Deduplication().DependedBy, tt.want.Dependencies[i].Deduplication().DependedBy)
				}

			}
		})
	}
}

func TestNewSection(t *testing.T) {
	// deps := buildFakeDependencies("../../testdata/dep_node_stat_index1_result")

	type args struct {
		hexDataFile       string
		name              string
		optimizedDataFile string
		depsFile          string
	}
	tests := []struct {
		name    string
		args    args
		want    *Section
		wantErr bool
	}{
		{
			name: ".text section",
			args: args{
				hexDataFile:       "../../testdata/section_data",
				optimizedDataFile: "../../testdata/section_data_optimized",
				name:              ".text",
				depsFile:          "../../testdata/section_data_text_deps",
			},
		},
		{
			name: "uprobe_section",
			args: args{
				hexDataFile:       "../../testdata/section_data_uprobe_raw",
				optimizedDataFile: "../../testdata/section_data_uprobe_optimized",
				depsFile:          "../../testdata/section_data_uprobe_deps",
				name:              "uprobe",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hexData, err := os.ReadFile(tt.args.hexDataFile)
			if err != nil {
				t.Errorf("NewSection() error = %v", err)
				return
			}

			optimizedData, err := os.ReadFile(tt.args.optimizedDataFile)
			if err != nil {
				t.Errorf("NewSection() error = %v", err)
				return
			}

			optimizedDataInstRaws, err := tool.ParsePythonSliceInt(string(optimizedData))
			if err != nil {
				t.Errorf("ParsePythonSliceInt() error = %v", err)
				return
			}

			got, err := NewSection(string(hexData), tt.args.name, false)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSection() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			deps := buildFakeDependencies(tt.args.depsFile)

			// Debug: Print total length comparison
			t.Logf("Total dependencies length - Expected: %d, Got: %d", len(deps), len(got.Dependencies))

			// Debug: Focus on 4810 instruction and surrounding area
			debugStart := 4800
			debugEnd := 4820
			if debugStart < len(deps) && debugEnd < len(deps) {
				t.Logf("=== Debug dependency analysis for instructions %d-%d ===", debugStart, debugEnd)
				for i := debugStart; i <= debugEnd && i < len(deps) && i < len(got.Dependencies); i++ {
					expectedDeps := deps[i].Deduplication()
					gotDeps := got.Dependencies[i].Deduplication()

					if !equalIntSlice(gotDeps.Dependencies, expectedDeps.Dependencies) ||
						!equalIntSlice(gotDeps.DependedBy, expectedDeps.DependedBy) {
						t.Logf("MISMATCH at %d: Expected {%v %v}, Got {%v %v}",
							i, expectedDeps.Dependencies, expectedDeps.DependedBy,
							gotDeps.Dependencies, gotDeps.DependedBy)

						// Show instruction details
						if i < len(got.Instructions) {
							t.Logf("  Instruction %d: Raw=%s, Opcode=0x%02x",
								i, got.Instructions[i].Raw, got.Instructions[i].Opcode)
						}
					}
				}
			}

			for i, instRaw := range optimizedDataInstRaws {
				gotInst := got.Instructions[i]
				if gotInst == nil {
					t.Errorf("Test %s: instruction mismatch, ins index %d, got: <nil>, expected: %s",
						tt.name, i, instRaw)
					continue
				}
				if gotInst.Raw != instRaw {
					t.Errorf("Test %s: instruction mismatch, ins index %d, got: %s, expected: %s",
						tt.name, i, gotInst.Raw, instRaw)
				}
			}

		})
	}
}

// TestRemoveDuplicateInts tests the removeDuplicateInts helper function
func TestRemoveDuplicateInts(t *testing.T) {
	tests := []struct {
		name     string
		input    []int
		expected []int
	}{
		{
			name:     "empty slice",
			input:    []int{},
			expected: []int{},
		},
		{
			name:     "no duplicates",
			input:    []int{1, 2, 3, 4, 5},
			expected: []int{1, 2, 3, 4, 5},
		},
		{
			name:     "unsorted with duplicates",
			input:    []int{3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5},
			expected: []int{1, 2, 3, 4, 5, 6, 9},
		},
		{
			name:     "all same elements",
			input:    []int{5, 5, 5, 5, 5},
			expected: []int{5},
		},
		{
			name:     "single element",
			input:    []int{42},
			expected: []int{42},
		},
		{
			name:     "consecutive duplicates",
			input:    []int{1, 1, 2, 2, 3, 3},
			expected: []int{1, 2, 3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := removeDuplicateInts(tt.input)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("removeDuplicateInts(%v) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

// TestDependencyInfoDeduplication tests the Deduplication method
func TestDependencyInfoDeduplication(t *testing.T) {
	tests := []struct {
		name     string
		input    DependencyInfo
		expected DependencyInfo
	}{
		{
			name: "no duplicates",
			input: DependencyInfo{
				Dependencies: []int{1, 2, 3},
				DependedBy:   []int{4, 5, 6},
			},
			expected: DependencyInfo{
				Dependencies: []int{1, 2, 3},
				DependedBy:   []int{4, 5, 6},
			},
		},
		{
			name: "with duplicates in both fields",
			input: DependencyInfo{
				Dependencies: []int{3, 1, 2, 1, 3},
				DependedBy:   []int{6, 4, 5, 4, 6},
			},
			expected: DependencyInfo{
				Dependencies: []int{1, 2, 3},
				DependedBy:   []int{4, 5, 6},
			},
		},
		{
			name: "empty dependencies",
			input: DependencyInfo{
				Dependencies: []int{},
				DependedBy:   []int{1, 2, 1, 3},
			},
			expected: DependencyInfo{
				Dependencies: []int{},
				DependedBy:   []int{1, 2, 3},
			},
		},
		{
			name: "complex duplicates",
			input: DependencyInfo{
				Dependencies: []int{10, 25, 40, 10, 25, 40, 15, 15},
				DependedBy:   []int{50, 60, 70, 50, 80, 60},
			},
			expected: DependencyInfo{
				Dependencies: []int{10, 15, 25, 40},
				DependedBy:   []int{50, 60, 70, 80},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.input.Deduplication()
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("DependencyInfo.Deduplication() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestSection2(t *testing.T) {
	mismatchCount := 0
	totalTests := 100

	for i := 0; i < totalTests; i++ {
		hexData, err := os.ReadFile("../../testdata/section_data_uprobe_raw")
		if err != nil {
			t.Errorf("NewSection() error = %v", err)
			return
		}
		got, err := NewSection(string(hexData), "uprobe", false)
		if err != nil {
			t.Errorf("NewSection() error = %v", err)
			return
		}

		if got.Instructions[4810].Raw != "0500000000000000" {
			mismatchCount++
			t.Logf("Test %d: instruction mismatch, got: %s, expected: 0500000000000000",
				i+1, got.Instructions[4810].Raw)
		}
	}

	t.Logf("统计结果: %d/%d 次测试出现不匹配, 不匹配率: %.2f%%",
		mismatchCount, totalTests, float64(mismatchCount)/float64(totalTests)*100)

	if mismatchCount > 0 {
		t.Errorf("发现 %d 次不匹配情况", mismatchCount)
	}

}
