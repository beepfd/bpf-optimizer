package bpf

import "testing"

func Test_parseImmediate(t *testing.T) {
	type args struct {
		hexStr string
	}
	tests := []struct {
		name    string
		args    args
		want    int32
		wantErr bool
	}{
		{
			name: "test1",
			args: args{
				hexStr: "07010000d0feffff",
			},
			want:    -304,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseImmediate(tt.args.hexStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseImmediate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseImmediate() got = %v, want %v", got, tt.want)
			}
		})
	}
}
