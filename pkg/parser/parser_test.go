package parser

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"mdns-scanner/pkg/probe"
	"mdns-scanner/pkg/target"
)

func TestParseRawResponse(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetReply(&dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id: 1234,
		},
	})

	// Add PTR answers
	msg.Answer = append(msg.Answer, &dns.PTR{
		Hdr: dns.RR_Header{Name: "_services._dns-sd._udp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 120},
		Ptr: "_http._tcp.local.",
	})
	msg.Answer = append(msg.Answer, &dns.PTR{
		Hdr: dns.RR_Header{Name: "_services._dns-sd._udp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 120},
		Ptr: "_qdiscover._tcp.local.",
	})

	// Add SRV record
	msg.Extra = append(msg.Extra, &dns.SRV{
		Hdr:      dns.RR_Header{Name: "SynologyNAS._http._tcp.local.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 120},
		Priority: 0,
		Weight:   0,
		Port:     5000,
		Target:   "synology-nas.local.",
	})

	// Add TXT records (Deep Banner)
	msg.Extra = append(msg.Extra, &dns.TXT{
		Hdr: dns.RR_Header{Name: "SynologyNAS._http._tcp.local.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 120},
		Txt: []string{"model=DS920+", "version=7.2-64570", "vendor=Synology", "proto=https"},
	})

	// Add A record
	msg.Extra = append(msg.Extra, &dns.A{
		Hdr: dns.RR_Header{Name: "synology-nas.local.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120},
		A:   net.ParseIP("192.168.1.100"),
	})

	raw := &probe.RawResponse{
		Target: target.Target{IP: "192.168.1.100", Port: 5353},
		Msg:    msg,
	}

	asset := ParseRawResponse(raw)
	if asset == nil {
		t.Fatal("expected non-nil asset")
	}

	if asset.Hostname != "synology-nas.local" {
		t.Errorf("expected hostname synology-nas.local, got %s", asset.Hostname)
	}

	if asset.Banner["model"] != "DS920+" {
		t.Errorf("expected banner model=DS920+, got %s", asset.Banner["model"])
	}

	if asset.Banner["version"] != "7.2-64570" {
		t.Errorf("expected banner version=7.2-64570, got %s", asset.Banner["version"])
	}

	foundHttp := false
	for _, s := range asset.Services {
		tag := s.FormatTag()
		if tag == "5000/tcp http:" {
			foundHttp = true
		}
	}
	if !foundHttp {
		t.Errorf("expected to find service '5000/tcp http:' in %+v", asset.Services)
	}
}
