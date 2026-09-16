package target

import (
	"context"
	"reflect"
	"sort"
	"testing"
)

func TestParsePorts(t *testing.T) {
	tests := []struct {
		input    string
		expected []int
		wantErr  bool
	}{
		{"", []int{5353}, false},
		{"5353", []int{5353}, false},
		{"5353, 5000", []int{5000, 5353}, false},
		{"5000-5003", []int{5000, 5001, 5002, 5003}, false},
		{"5353, 5000-5002", []int{5000, 5001, 5002, 5353}, false},
		{"invalid", nil, true},
		{"5005-5000", nil, true},
		{"70000", nil, true},
	}

	for _, tt := range tests {
		got, err := ParsePorts(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParsePorts(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if !tt.wantErr {
			sort.Ints(got)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("ParsePorts(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		}
	}
}

func TestGenerateTargets(t *testing.T) {
	ctx := context.Background()

	// TC-INP-01: Single IP target
	ch1, err := GenerateTargets(ctx, "192.168.1.10", []int{5353})
	if err != nil {
		t.Fatalf("TC-INP-01 failed: %v", err)
	}
	var targets1 []Target
	for tgt := range ch1 {
		targets1 = append(targets1, tgt)
	}
	if len(targets1) != 1 || targets1[0].IP != "192.168.1.10" {
		t.Errorf("TC-INP-01 expected 1 target with IP 192.168.1.10, got %+v", targets1)
	}

	// TC-INP-02: CIDR /30 (4 IPs * 2 ports = 8 targets)
	ch2, err := GenerateTargets(ctx, "192.168.1.0/30", []int{5353, 5000})
	if err != nil {
		t.Fatalf("TC-INP-02 failed: %v", err)
	}
	var targets2 []Target
	for tgt := range ch2 {
		targets2 = append(targets2, tgt)
	}
	if len(targets2) != 8 {
		t.Errorf("TC-INP-02 expected 8 targets, got %d", len(targets2))
	}

	// TC-INP-03: Invalid IP and Invalid CIDR error checking
	invalidCases := []string{
		"999.999.1.1",
		"192.168.1.0/33",
		"192.168.1.0/-1",
		"abc.def.ghi.jkl",
		"",
	}
	for _, inv := range invalidCases {
		_, err := GenerateTargets(ctx, inv, []int{5353})
		if err == nil {
			t.Errorf("TC-INP-03 expected error for invalid input %q, got nil", inv)
		}
	}
}
