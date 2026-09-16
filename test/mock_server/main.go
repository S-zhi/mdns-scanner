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

	fmt.Printf("[*] Mock mDNS Server running on port %d\n", port)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		_ = conn.Close()
		os.Exit(0)
	}()

	buf := make([]byte, 4096)
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

		// Answers PTR
		ptrServices := []string{
			"_workstation._tcp.local.",
			"_http._tcp.local.",
			"_smb._tcp.local.",
			"_qdiscover._tcp.local.",
			"_device-info._tcp.local.",
			"_afpovertcp._tcp.local.",
		}
		for _, ptr := range ptrServices {
			resp.Answer = append(resp.Answer, &dns.PTR{
				Hdr: dns.RR_Header{Name: "_services._dns-sd._udp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 10},
				Ptr: ptr,
			})
		}

		// SRV Records
		resp.Extra = append(resp.Extra, &dns.SRV{
			Hdr:    dns.RR_Header{Name: "slw-nas [24:5e:be:69:a3:13]._workstation._tcp.local.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 10},
			Port:   9,
			Target: "slw-nas.local.",
		})
		resp.Extra = append(resp.Extra, &dns.SRV{
			Hdr:    dns.RR_Header{Name: "slw-nas._http._tcp.local.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 10},
			Port:   5000,
			Target: "slw-nas.local.",
		})
		resp.Extra = append(resp.Extra, &dns.SRV{
			Hdr:    dns.RR_Header{Name: "slw-nas._smb._tcp.local.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 10},
			Port:   445,
			Target: "slw-nas.local.",
		})
		resp.Extra = append(resp.Extra, &dns.SRV{
			Hdr:    dns.RR_Header{Name: "slw-nas._qdiscover._tcp.local.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 10},
			Port:   5000,
			Target: "slw-nas.local.",
		})
		resp.Extra = append(resp.Extra, &dns.SRV{
			Hdr:    dns.RR_Header{Name: "slw-nas(AFP)._afpovertcp._tcp.local.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 10},
			Port:   548,
			Target: "slw-nas.local.",
		})

		// TXT Records (Banners)
		resp.Extra = append(resp.Extra, &dns.TXT{
			Hdr: dns.RR_Header{Name: "slw-nas._http._tcp.local.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 10},
			Txt: []string{"path=/"},
		})
		resp.Extra = append(resp.Extra, &dns.TXT{
			Hdr: dns.RR_Header{Name: "slw-nas._qdiscover._tcp.local.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 10},
			Txt: []string{
				"accessType=https",
				"accessPort=86",
				"model=TS-X64",
				"displayModel=TS-464C",
				"fwVer=5.2.9",
				"fwBuildNum=20260214",
			},
		})
		resp.Extra = append(resp.Extra, &dns.TXT{
			Hdr: dns.RR_Header{Name: "slw-nas(AFP)._device-info._tcp.local.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 10},
			Txt: []string{"model=Xserve"},
		})

		// A and AAAA Records
		resp.Extra = append(resp.Extra, &dns.A{
			Hdr: dns.RR_Header{Name: "slw-nas.local.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10},
			A:   net.ParseIP("192.168.1.50"),
		})
		resp.Extra = append(resp.Extra, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: "slw-nas.local.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 10},
			AAAA: net.ParseIP("fe80::265e:beff:fe69:a313"),
		})

		wire, err := resp.Pack()
		if err == nil {
			_, _ = conn.WriteTo(wire, addr)
		}
	}
}
