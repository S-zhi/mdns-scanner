package parser

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"mdns-scanner/pkg/probe"
	"mdns-scanner/pkg/target"
)

// TC-TXT-01 ~ 04: Table-driven unit tests for TXT Banner parsing and panic prevention
func TestFormatTXTBanner(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected string
	}{
		{
			name:     "TC-TXT-01: Standard QNAP NAS attributes",
			input:    []string{"accessType=https", "accessPort=86", "model=TS-X64", "displayModel=TS-464C", "fwVer=5.2.9", "fwBuildNum=20260214"},
			expected: "accessType=https,accessPort=86,model=TS-X64,displayModel=TS-464C,fwVer=5.2.9,fwBuildNum=20260214",
		},
		{
			name:     "TC-TXT-02: Empty TXT slice (no panic, empty return)",
			input:    []string{},
			expected: "",
		},
		{
			name:     "TC-TXT-02b: Slice with empty strings only",
			input:    []string{"  ", ""},
			expected: "",
		},
		{
			name:     "TC-TXT-03: Tag without equals sign (no index out of range panic)",
			input:    []string{"model=Xserve", "tag_only"},
			expected: "model=Xserve,tag_only",
		},
		{
			name:     "TC-TXT-04: Multiple equals signs (URLs / queries preserved safely)",
			input:    []string{"path=/?user=admin&token=123", "param=a=b=c"},
			expected: "path=/?user=admin&token=123,param=a=b=c",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatTXTBanner(tt.input)
			if got != tt.expected {
				t.Errorf("FormatTXTBanner() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TC-AGG-01 & 02: Test Aggregator handling of PTR, SRV, TXT, A, AAAA and fallback logic
func TestAggregator_ProcessRawResponse(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetReply(&dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id: 1234,
		},
	})

	// Add PTR answers
	msg.Answer = append(msg.Answer, &dns.PTR{
		Hdr: dns.RR_Header{Name: "_services._dns-sd._udp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 10},
		Ptr: "_http._tcp.local.",
	})
	msg.Answer = append(msg.Answer, &dns.PTR{
		Hdr: dns.RR_Header{Name: "_services._dns-sd._udp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 10},
		Ptr: "_qdiscover._tcp.local.",
	})

	// Add SRV record
	msg.Extra = append(msg.Extra, &dns.SRV{
		Hdr:      dns.RR_Header{Name: "slw-nas._http._tcp.local.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 10},
		Priority: 0,
		Weight:   0,
		Port:     5000,
		Target:   "slw-nas.local.",
	})

	// Add TXT records (Deep Banner)
	msg.Extra = append(msg.Extra, &dns.TXT{
		Hdr: dns.RR_Header{Name: "slw-nas._http._tcp.local.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 10},
		Txt: []string{"path=/"},
	})

	// Add A and AAAA records
	msg.Extra = append(msg.Extra, &dns.A{
		Hdr: dns.RR_Header{Name: "slw-nas.local.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10},
		A:   net.ParseIP("192.168.1.120"),
	})
	msg.Extra = append(msg.Extra, &dns.AAAA{
		Hdr:  dns.RR_Header{Name: "slw-nas.local.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 10},
		AAAA: net.ParseIP("fe80::265e:beff:fe69:a313"),
	})

	raw := &probe.RawResponse{
		Target: target.Target{IP: "192.168.1.120", Port: 5353},
		Msg:    msg,
	}

	agg := NewAggregator()
	asset := agg.ProcessRawResponse(raw)
	if asset == nil {
		t.Fatal("expected non-nil asset")
	}

	if asset.Hostname != "slw-nas.local" {
		t.Errorf("expected hostname slw-nas.local, got %s", asset.Hostname)
	}

	if len(asset.IPv4) == 0 || asset.IPv4[0] != "192.168.1.120" {
		t.Errorf("expected IPv4 192.168.1.120, got %+v", asset.IPv4)
	}

	if len(asset.IPv6) == 0 || asset.IPv6[0] != "fe80::265e:beff:fe69:a313" {
		t.Errorf("expected IPv6 fe80::265e:beff:fe69:a313, got %+v", asset.IPv6)
	}

	// Verify service entry
	svc, ok := asset.Services["5000/tcp http:"]
	if !ok {
		t.Fatalf("expected service key '5000/tcp http:' in asset.Services, got %+v", asset.Services)
	}

	if svc.Banner != "path=/" {
		t.Errorf("expected banner 'path=/', got %q", svc.Banner)
	}

	// TC-AGG-02: Test fallback when A record is missing
	msgMissingA := new(dns.Msg)
	msgMissingA.SetReply(&dns.Msg{MsgHdr: dns.MsgHdr{Id: 5678}})
	msgMissingA.Answer = append(msgMissingA.Answer, &dns.PTR{
		Hdr: dns.RR_Header{Name: "_services._dns-sd._udp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 10},
		Ptr: "_workstation._tcp.local.",
	})
	rawMissingA := &probe.RawResponse{
		Target: target.Target{IP: "10.0.0.5", Port: 5353},
		Msg:    msgMissingA,
	}

	agg2 := NewAggregator()
	assetFallback := agg2.ProcessRawResponse(rawMissingA)
	if len(assetFallback.IPv4) == 0 || assetFallback.IPv4[0] != "10.0.0.5" {
		t.Errorf("expected fallback IPv4 10.0.0.5, got %+v", assetFallback.IPv4)
	}
}
