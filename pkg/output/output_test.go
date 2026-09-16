package output

import (
	"bytes"
	"strings"
	"testing"

	"mdns-scanner/pkg/parser"
)

func TestFormatterExactAlignment(t *testing.T) {
	asset := &parser.DeviceAsset{
		IP:          "192.168.1.50",
		Hostname:    "slw-nas.local",
		DefaultName: "slw-nas",
		TTL:         10,
		IPv4:        []string{"192.168.1.50"},
		IPv6:        []string{"fe80::265e:beff:fe69:a313"},
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
				IPv4:     "192.168.1.50",
				IPv6:     "fe80::265e:beff:fe69:a313",
				Hostname: "slw-nas.local",
				TTL:      10,
			},
			"5000/tcp http:": {
				Port:     5000,
				Proto:    "tcp",
				Service:  "http",
				Name:     "slw-nas",
				IPv4:     "192.168.1.50",
				IPv6:     "fe80::265e:beff:fe69:a313",
				Hostname: "slw-nas.local",
				TTL:      10,
				Banner:   "path=/",
			},
			"device-info:": {
				Port:     0,
				Service:  "device-info",
				Name:     "slw-nas(AFP)",
				IPv4:     "192.168.1.50",
				IPv6:     "fe80::265e:beff:fe69:a313",
				Hostname: "slw-nas.local",
				TTL:      10,
				Banner:   "model=Xserve",
			},
		},
		ServiceKeys: []string{"9/tcp workstation:", "5000/tcp http:", "device-info:"},
	}

	var buf bytes.Buffer
	f := NewFormatter(&buf, false)
	if err := f.PrintDeviceAsset(asset); err != nil {
		t.Fatalf("PrintDeviceAsset failed: %v", err)
	}

	out := buf.String()

	expectedSubstrings := []string{
		"services:\n",
		"9/tcp workstation:\n",
		"Name=slw-nas [24:5e:be:69:a3:13]\n",
		"IPv4=192.168.1.50\n",
		"IPv6=fe80::265e:beff:fe69:a313\n",
		"Hostname=slw-nas.local\n",
		"TTL=10\n",
		"5000/tcp http:\n",
		"path=/\n",
		"device-info:\n",
		"model=Xserve\n",
		"answers:\n",
		"PTR:\n",
		"_workstation._tcp.local\n",
		"_http._tcp.local\n",
		"_smb._tcp.local\n",
	}

	for _, sub := range expectedSubstrings {
		if !strings.Contains(out, sub) {
			t.Errorf("expected output to contain %q, but got:\n%s", sub, out)
		}
	}
}
