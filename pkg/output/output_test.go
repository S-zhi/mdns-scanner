package output

import (
	"bytes"
	"strings"
	"testing"

	"mdns-scanner/pkg/parser"
)

// TC-FMT-01: Table-driven unit test verifying formatted output matches problem sample
func TestFormatter_PrintDeviceAsset(t *testing.T) {
	asset := &parser.DeviceAsset{
		IP:       "192.168.1.120",
		Hostname: "slw-nas.local",
		Name:     "slw-nas",
		TTL:      10,
		IPv4:     []string{"192.168.1.120"},
		IPv6:     []string{"fe80::265e:beff:fe69:a313"},
		Answers: []string{
			"_workstation._tcp.local",
			"_http._tcp.local",
			"_smb._tcp.local",
			"_qdiscover._tcp.local",
			"_device-info._tcp.local",
			"_afpovertcp._tcp.local",
		},
		Services: map[string]parser.ServiceEntry{
			"9/tcp workstation:": {
				Port:     9,
				Proto:    "tcp",
				Service:  "workstation",
				Name:     "slw-nas [24:5e:be:69:a3:13]",
				IPv4:     "192.168.1.120",
				IPv6:     "fe80::265e:beff:fe69:a313",
				Hostname: "slw-nas.local",
				TTL:      10,
			},
			"5000/tcp http:": {
				Port:     5000,
				Proto:    "tcp",
				Service:  "http",
				Name:     "slw-nas",
				IPv4:     "192.168.1.120",
				IPv6:     "fe80::265e:beff:fe69:a313",
				Hostname: "slw-nas.local",
				TTL:      10,
				Banner:   "path=/",
			},
			"445/tcp smb:": {
				Port:     445,
				Proto:    "tcp",
				Service:  "smb",
				Name:     "slw-nas",
				IPv4:     "192.168.1.120",
				IPv6:     "fe80::265e:beff:fe69:a313",
				Hostname: "slw-nas.local",
				TTL:      10,
			},
			"5000/tcp qdiscover:": {
				Port:     5000,
				Proto:    "tcp",
				Service:  "qdiscover",
				Name:     "slw-nas",
				IPv4:     "192.168.1.120",
				IPv6:     "fe80::265e:beff:fe69:a313",
				Hostname: "slw-nas.local",
				TTL:      10,
				Banner:   "accessType=https,accessPort=86,model=TS-X64,displayModel=TS-464C,fwVer=5.2.9,fwBuildNum=20260214",
			},
		},
	}

	var buf bytes.Buffer
	f := NewFormatter(&buf, false)
	if err := f.PrintDeviceAsset(asset); err != nil {
		t.Fatalf("PrintDeviceAsset failed: %v", err)
	}

	out := buf.String()

	// Assertions for structure alignment
	expectedSnippets := []string{
		"services:",
		"5000/tcp http:",
		"path=/",
		"5000/tcp qdiscover:",
		"model=TS-X64",
		"displayModel=TS-464C",
		"fwVer=5.2.9",
		"answers:",
		"PTR:",
		"_workstation._tcp.local",
		"_qdiscover._tcp.local",
	}

	for _, snippet := range expectedSnippets {
		if !strings.Contains(out, snippet) {
			t.Errorf("expected output to contain %q, but got:\n%s", snippet, out)
		}
	}
}

func TestFormatter_PrintNil(t *testing.T) {
	var buf bytes.Buffer
	f := NewFormatter(&buf, false)
	if err := f.PrintDeviceAsset(nil); err != nil {
		t.Errorf("expected nil error on nil asset, got %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected empty buffer for nil asset, got %s", buf.String())
	}
}
