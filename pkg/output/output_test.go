package output

import (
	"bytes"
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
			"445/tcp smb:": {
				Port:     445,
				Proto:    "tcp",
				Service:  "smb",
				Name:     "slw-nas",
				IPv4:     "192.168.1.50",
				IPv6:     "fe80::265e:beff:fe69:a313",
				Hostname: "slw-nas.local",
				TTL:      10,
			},
			"5000/tcp qdiscover:": {
				Port:     5000,
				Proto:    "tcp",
				Service:  "qdiscover",
				Name:     "slw-nas",
				IPv4:     "192.168.1.50",
				IPv6:     "fe80::265e:beff:fe69:a313",
				Hostname: "slw-nas.local",
				TTL:      10,
				Banner:   "accessType=https,accessPort=86,model=TS-X64,displayModel=TS-464C,fwVer=5.2.9,fwBuildNum=20260214",
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
			"548/tcp afpovertcp:": {
				Port:     548,
				Proto:    "tcp",
				Service:  "afpovertcp",
				Name:     "slw-nas(AFP)",
				IPv4:     "192.168.1.50",
				IPv6:     "fe80::265e:beff:fe69:a313",
				Hostname: "slw-nas.local",
				TTL:      10,
			},
		},
		ServiceKeys: []string{
			"9/tcp workstation:",
			"5000/tcp http:",
			"445/tcp smb:",
			"5000/tcp qdiscover:",
			"device-info:",
			"548/tcp afpovertcp:",
		},
	}

	expected := `services:
9/tcp workstation:
Name=slw-nas [24:5e:be:69:a3:13]
IPv4=192.168.1.50
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
5000/tcp http:
Name=slw-nas
IPv4=192.168.1.50
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
path=/
445/tcp smb:
Name=slw-nas
IPv4=192.168.1.50
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
5000/tcp qdiscover:
Name=slw-nas
IPv4=192.168.1.50
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
accessType=https,accessPort=86,model=TS-X64,displayModel=TS-464C,fwVer=5.2.9,fwBuildNum=20260214
device-info:
Name=slw-nas(AFP)
IPv4=192.168.1.50
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
model=Xserve
548/tcp afpovertcp:
Name=slw-nas(AFP)
IPv4=192.168.1.50
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
answers:
PTR:
_workstation._tcp.local
_http._tcp.local
_smb._tcp.local
_qdiscover._tcp.local
_device-info._tcp.local
_afpovertcp._tcp.local
`

	var buf bytes.Buffer
	f := NewFormatter(&buf, false)
	if err := f.PrintDeviceAsset(asset); err != nil {
		t.Fatalf("PrintDeviceAsset failed: %v", err)
	}

	if got := buf.String(); got != expected {
		t.Errorf("output mismatch:\nWANT:\n%s\nGOT:\n%s", expected, got)
	}
}

