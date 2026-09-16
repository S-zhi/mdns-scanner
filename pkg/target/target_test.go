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

	// Test CIDR /30 (4 IPs * 2 ports = 8 targets)
	ch, err := GenerateTargets(ctx, "192.168.1.0/30", []int{5353, 5000})
	if err != nil {
		t.Fatalf("GenerateTargets failed: %v", err)
	}

	var targets []Target
	for tgt := range ch {
		targets = append(targets, tgt)
	}

	if len(targets) != 8 {
		t.Errorf("expected 8 targets, got %d", len(targets))
	}
}
