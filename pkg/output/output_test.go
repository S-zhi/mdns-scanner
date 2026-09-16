package output

import (
	"bytes"
	"strings"
	"testing"

	"mdns-scanner/pkg/parser"
)

func TestFormatter(t *testing.T) {
	asset := &parser.Asset{
		IP:       "192.168.1.100",
		Port:     5353,
		Host:     "synology-nas.local",
		Name:     "synology-nas",
		Hostname: "synology-nas.local",
		IPv4:     []string{"192.168.1.100"},
		IPv6:     []string{"fe80::1"},
		TTL:      120,
		Answers:  []string{"_http._tcp.local", "_qdiscover._tcp.local"},
		Services: []parser.ServiceEntry{
			{
				Port:    5000,
				Proto:   "tcp",
				Service: "http",
				Target:  "synology-nas.local",
				Banner: map[string]string{
					"model": "DS920+",
				},
			},
		},
		Banner: map[string]string{
			"model":   "DS920+",
			"version": "7.2",
		},
	}

	var buf bytes.Buffer
	f := NewFormatter(&buf, false)
	if err := f.PrintAsset(asset); err != nil {
		t.Fatalf("PrintAsset failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "5000/tcp http:") {
		t.Errorf("expected output to contain '5000/tcp http:', got: %s", out)
	}
	if !strings.Contains(out, "answers: PTR:") {
		t.Errorf("expected output to contain 'answers: PTR:', got: %s", out)
	}
	if !strings.Contains(out, "model: DS920+") {
		t.Errorf("expected output to contain 'model: DS920+', got: %s", out)
	}
}
