package target

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Target represents a single scan destination
type Target struct {
	IP   string
	Port int
}

func (t Target) String() string {
	return net.JoinHostPort(t.IP, strconv.Itoa(t.Port))
}

// ParsePorts parses port definitions:
// - "5353" -> [5353]
// - "5353,5000" -> [5353, 5000]
// - "5000-5005" -> [5000, 5001, 5002, 5003, 5004, 5005]
// - "5353,5000-5002" -> [5353, 5000, 5001, 5002]
func ParsePorts(portStr string) ([]int, error) {
	if strings.TrimSpace(portStr) == "" {
		return []int{5353}, nil
	}

	portMap := make(map[int]struct{})
	parts := strings.Split(portStr, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}
			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid start port in range: %s", rangeParts[0])
			}
			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid end port in range: %s", rangeParts[1])
			}
			if start > end || start < 1 || end > 65535 {
				return nil, fmt.Errorf("port range out of bounds [1-65535]: %d-%d", start, end)
			}
			for p := start; p <= end; p++ {
				portMap[p] = struct{}{}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("port out of bounds [1-65535]: %d", p)
			}
			portMap[p] = struct{}{}
		}
	}

	ports := make([]int, 0, len(portMap))
	for p := range portMap {
		ports = append(ports, p)
	}
	return ports, nil
}

// GenerateTargets streams targets via channel with O(1) memory footprint.
// Supports:
// - Single IP: "192.168.1.10"
// - CIDR: "192.168.1.0/24"
// - Comma-separated: "192.168.1.1,192.168.1.2,10.0.0.0/24"
func GenerateTargets(ctx context.Context, targetStr string, ports []int) (<-chan Target, error) {
	if strings.TrimSpace(targetStr) == "" {
		return nil, fmt.Errorf("target cannot be empty")
	}

	// First, validate all tokens
	tokens := strings.Split(targetStr, ",")
	cleanTokens := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		// Validate token as IP or CIDR
		if strings.Contains(tok, "/") {
			_, _, err := net.ParseCIDR(tok)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", tok, err)
			}
		} else {
			ip := net.ParseIP(tok)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP address %q", tok)
			}
		}
		cleanTokens = append(cleanTokens, tok)
	}

	if len(cleanTokens) == 0 {
		return nil, fmt.Errorf("no valid targets provided")
	}

	out := make(chan Target, 256)

	go func() {
		defer close(out)
		for _, tok := range cleanTokens {
			if strings.Contains(tok, "/") {
				_, ipNet, _ := net.ParseCIDR(tok)
				if err := streamCIDR(ctx, ipNet, ports, out); err != nil {
					return
				}
			} else {
				ip := net.ParseIP(tok)
				for _, port := range ports {
					select {
					case <-ctx.Done():
						return
					case out <- Target{IP: ip.String(), Port: port}:
					}
				}
			}
		}
	}()

	return out, nil
}

func streamCIDR(ctx context.Context, ipNet *net.IPNet, ports []int, out chan<- Target) error {
	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		// IPv6 CIDR
		for _, port := range ports {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case out <- Target{IP: ipNet.IP.String(), Port: port}:
			}
		}
		return nil
	}

	mask := binary.BigEndian.Uint32(ipNet.Mask)
	start := binary.BigEndian.Uint32(ip4)
	total := ^mask + 1

	// For /31 and /32, probe all IPs. For others, typically scan the usable host range.
	var first, last uint32
	if total <= 2 {
		first = start
		last = start + total - 1
	} else {
		// Include all IPs in the CIDR (including .0 and .255 as in network mapping servers can be anywhere)
		first = start
		last = start + total - 1
	}

	for cur := first; cur <= last; cur++ {
		curIP := make(net.IP, 4)
		binary.BigEndian.PutUint32(curIP, cur)

		for _, port := range ports {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case out <- Target{IP: curIP.String(), Port: port}:
			}
		}

		// Prevent uint32 overflow if last is 255.255.255.255
		if cur == ^uint32(0) {
			break
		}
	}
	return nil
}
