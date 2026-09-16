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

	// PTR records
	msg.Answer = append(msg.Answer, &dns.PTR{
		Hdr: dns.RR_Header{Name: "_services._dns-sd._udp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 10},
		Ptr: "_http._tcp.local.",
	})
	msg.Answer = append(msg.Answer, &dns.PTR{
		Hdr: dns.RR_Header{Name: "_services._dns-sd._udp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 10},
		Ptr: "_smb._tcp.local.",
	})
	msg.Answer = append(msg.Answer, &dns.PTR{
		Hdr: dns.RR_Header{Name: "_services._dns-sd._udp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 10},
		Ptr: "_device-info._tcp.local.",
	})

	// SRV record
	msg.Extra = append(msg.Extra, &dns.SRV{
		Hdr:      dns.RR_Header{Name: "slw-nas._http._tcp.local.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 10},
		Priority: 0,
		Weight:   0,
		Port:     5000,
		Target:   "slw-nas.local.",
	})

	// TXT records
	msg.Extra = append(msg.Extra, &dns.TXT{
		Hdr: dns.RR_Header{Name: "slw-nas._http._tcp.local.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 10},
		Txt: []string{"path=/"},
	})
	msg.Extra = append(msg.Extra, &dns.TXT{
		Hdr: dns.RR_Header{Name: "slw-nas(AFP)._device-info._tcp.local.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 10},
		Txt: []string{"model=Xserve"},
	})

	// A & AAAA record
	msg.Extra = append(msg.Extra, &dns.A{
		Hdr: dns.RR_Header{Name: "slw-nas.local.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10},
		A:   net.ParseIP("192.168.1.50"),
	})
	msg.Extra = append(msg.Extra, &dns.AAAA{
		Hdr:  dns.RR_Header{Name: "slw-nas.local.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 10},
		AAAA: net.ParseIP("fe80::265e:beff:fe69:a313"),
	})

	raw := &probe.RawResponse{
		Target: target.Target{IP: "192.168.1.50", Port: 5353},
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

	httpSvc, exists := asset.Services["5000/tcp http:"]
	if !exists {
		t.Fatal("expected 5000/tcp http: service to exist")
	}
	if httpSvc.Banner != "path=/" {
		t.Errorf("expected banner path=/, got %s", httpSvc.Banner)
	}

	devInfoSvc, exists := asset.Services["device-info:"]
	if !exists {
		t.Fatal("expected device-info: service to exist")
	}
	if devInfoSvc.Banner != "model=Xserve" {
		t.Errorf("expected banner model=Xserve, got %s", devInfoSvc.Banner)
	}
}
