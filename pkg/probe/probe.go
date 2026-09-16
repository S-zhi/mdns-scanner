package probe

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"mdns-scanner/pkg/target"
)

// RawResponse contains the raw UDP response and network metadata
type RawResponse struct {
	Target   target.Target
	Msg      *dns.Msg
	Latency  time.Duration
	Received time.Time
}

// Config controls probe execution
type Config struct {
	Concurrency int
	Timeout     time.Duration
	Retries     int
	QueryNames  []string
}

// DefaultConfig returns recommended mapping configuration
func DefaultConfig() Config {
	return Config{
		Concurrency: 100,
		Timeout:     2 * time.Second,
		Retries:     1,
		QueryNames: []string{
			"_services._dns-sd._udp.local.",
		},
	}
}

// Engine manages concurrent mDNS probing
type Engine struct {
	cfg Config
}

// NewEngine creates a new probe engine
func NewEngine(cfg Config) *Engine {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 100
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	if len(cfg.QueryNames) == 0 {
		cfg.QueryNames = []string{"_services._dns-sd._udp.local."}
	}
	return &Engine{cfg: cfg}
}

// BuildMDNSQuery crafts a DNS query message with the QU (unicast-response) bit set
func BuildMDNSQuery(qname string) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(qname), dns.TypePTR)
	msg.RecursionDesired = false

	// RFC 6762 Section 5.4: Unicast-Response (QU) bit
	// Top bit of the class field (0x8000 | 0x0001 = 0x8001)
	if len(msg.Question) > 0 {
		msg.Question[0].Qclass = dns.ClassINET | 0x8000
	}
	return msg, nil
}

// ProbeSingle sends a unicast mDNS probe to a target and waits for response
func (e *Engine) ProbeSingle(ctx net.Conn, tgt target.Target, qname string) (*RawResponse, error) {
	msg, err := BuildMDNSQuery(qname)
	if err != nil {
		return nil, err
	}

	wire, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS query: %w", err)
	}

	addr := tgt.String()
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(e.cfg.Timeout)); err != nil {
		return nil, err
	}

	if _, err := conn.Write(wire); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return nil, err
	}
	latency := time.Since(start)

	resp := new(dns.Msg)
	if err := resp.Unpack(buf[:n]); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS response: %w", err)
	}

	return &RawResponse{
		Target:   tgt,
		Msg:      resp,
		Latency:  latency,
		Received: time.Now(),
	}, nil
}

// Run executes concurrent probing against targets channel
func (e *Engine) Run(ctx context.Context, targets <-chan target.Target) <-chan *RawResponse {
	results := make(chan *RawResponse, e.cfg.Concurrency*2)

	var wg sync.WaitGroup

	for i := 0; i < e.cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case tgt, ok := <-targets:
					if !ok {
						return
					}

					for _, qname := range e.cfg.QueryNames {
						var resp *RawResponse
						var err error

						// Try initial + retries
						for attempt := 0; attempt <= e.cfg.Retries; attempt++ {
							resp, err = e.ProbeSingle(nil, tgt, qname)
							if err == nil && resp != nil && resp.Msg != nil && (len(resp.Msg.Answer) > 0 || len(resp.Msg.Extra) > 0) {
								break
							}
						}

						if err == nil && resp != nil {
							select {
							case <-ctx.Done():
								return
							case results <- resp:
							}
							// Found response on this target, avoid duplicate queries
							break
						}
					}
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	return results
}
