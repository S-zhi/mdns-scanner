package probe

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"mdns-scanner/pkg/target"
)

func startMockMDNSServer(t *testing.T) (string, func()) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}

	stopChan := make(chan struct{})

	go func() {
		buf := make([]byte, 2048)
		for {
			select {
			case <-stopChan:
				return
			default:
			}

			_ = pc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				continue
			}

			req := new(dns.Msg)
			if err := req.Unpack(buf[:n]); err != nil {
				continue
			}

			resp := new(dns.Msg)
			resp.SetReply(req)
			resp.Answer = append(resp.Answer, &dns.PTR{
				Hdr: dns.RR_Header{Name: "_services._dns-sd._udp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 120},
				Ptr: "_http._tcp.local.",
			})
			resp.Extra = append(resp.Extra, &dns.SRV{
				Hdr:    dns.RR_Header{Name: "MockServer._http._tcp.local.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 120},
				Port:   8080,
				Target: "mockserver.local.",
			})
			resp.Extra = append(resp.Extra, &dns.TXT{
				Hdr: dns.RR_Header{Name: "MockServer._http._tcp.local.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 120},
				Txt: []string{"model=MockDevice", "version=1.0.0"},
			})

			wire, err := resp.Pack()
			if err == nil {
				_, _ = pc.WriteTo(wire, addr)
			}
		}
	}()

	return pc.LocalAddr().String(), func() {
		close(stopChan)
		_ = pc.Close()
	}
}

func TestProbeEngine(t *testing.T) {
	serverAddr, cleanup := startMockMDNSServer(t)
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(serverAddr)
	ports, _ := target.ParsePorts(portStr)

	cfg := Config{
		Concurrency: 2,
		Timeout:     500 * time.Millisecond,
		Retries:     1,
		QueryNames:  []string{"_services._dns-sd._udp.local."},
	}

	engine := NewEngine(cfg)

	targetsChan := make(chan target.Target, 1)
	targetsChan <- target.Target{IP: host, Port: ports[0]}
	close(targetsChan)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	results := engine.Run(ctx, targetsChan)

	var received *RawResponse
	for res := range results {
		received = res
		break
	}

	if received == nil {
		t.Fatal("expected to receive response from mock mDNS server")
	}

	if len(received.Msg.Answer) == 0 {
		t.Error("expected non-empty answers")
	}
}
