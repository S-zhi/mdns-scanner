package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/miekg/dns"
)

func main() {
	port := 5353
	if len(os.Args) > 1 {
		fmt.Sscanf(os.Args[1], "%d", &port)
	}

	conn, err := net.ListenPacket("udp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start mock mDNS server on port %d: %v\n", port, err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("[*] Mock mDNS Responder listening on 0.0.0.0:%d (Press Ctrl+C to stop)...\n", port)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		_ = conn.Close()
		os.Exit(0)
	}()

	buf := make([]byte, 2048)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			break
		}

		req := new(dns.Msg)
		if err := req.Unpack(buf[:n]); err != nil {
			continue
		}

		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Authoritative = true

		// Answers: PTR list
		resp.Answer = append(resp.Answer, &dns.PTR{
			Hdr: dns.RR_Header{Name: "_services._dns-sd._udp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 120},
			Ptr: "_http._tcp.local.",
		})
		resp.Answer = append(resp.Answer, &dns.PTR{
			Hdr: dns.RR_Header{Name: "_services._dns-sd._udp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 120},
			Ptr: "_qdiscover._tcp.local.",
		})

		// Extra: SRV records
		resp.Extra = append(resp.Extra, &dns.SRV{
			Hdr:    dns.RR_Header{Name: "SynologyNAS._http._tcp.local.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 120},
			Port:   5000,
			Target: "synology-nas.local.",
		})
		resp.Extra = append(resp.Extra, &dns.SRV{
			Hdr:    dns.RR_Header{Name: "SynologyNAS._qdiscover._tcp.local.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 120},
			Port:   5000,
			Target: "synology-nas.local.",
		})

		// Extra: TXT records (Deep Metadata Banner)
		resp.Extra = append(resp.Extra, &dns.TXT{
			Hdr: dns.RR_Header{Name: "SynologyNAS._http._tcp.local.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 120},
			Txt: []string{
				"model=DS920+",
				"version=7.2-64570",
				"vendor=Synology",
				"support_proto=http,https",
				"mac=00:11:32:AA:BB:CC",
			},
		})

		// Extra: A and AAAA records
		resp.Extra = append(resp.Extra, &dns.A{
			Hdr: dns.RR_Header{Name: "synology-nas.local.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120},
			A:   net.ParseIP("127.0.0.1"),
		})

		wire, err := resp.Pack()
		if err == nil {
			_, _ = conn.WriteTo(wire, addr)
		}
	}
}
