package bpf

import (
	"reflect"
	"testing"
)

func TestNewInstruction(t *testing.T) {
	type args struct {
		hexStr string
	}
	tests := []struct {
		name    string
		args    args
		want    *Instruction
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewInstruction(tt.args.hexStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewInstruction() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewInstruction() got = %v, want %v", got, tt.want)
			}
		})
	}
}
