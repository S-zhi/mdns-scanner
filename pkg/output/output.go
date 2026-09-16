package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"mdns-scanner/pkg/parser"
)

// Formatter outputs discovered DeviceAssets matching the exact assessment structure
type Formatter struct {
	w      io.Writer
	asJSON bool
}

// NewFormatter creates a new Formatter
func NewFormatter(w io.Writer, asJSON bool) *Formatter {
	if w == nil {
		w = os.Stdout
	}
	return &Formatter{
		w:      w,
		asJSON: asJSON,
	}
}

// PrintDeviceAsset formats and outputs a single DeviceAsset matching the exact specification:
// services:
// 9/tcp workstation:
// Name=...
// IPv4=...
// IPv6=...
// Hostname=...
// TTL=...
// 5000/tcp http:
// ...
// answers:
// PTR:
// _workstation._tcp.local
func (f *Formatter) PrintDeviceAsset(asset *parser.DeviceAsset) error {
	if asset == nil {
		return nil
	}

	if f.asJSON {
		enc := json.NewEncoder(f.w)
		enc.SetIndent("", "  ")
		return enc.Encode(asset)
	}

	var sb strings.Builder

	sb.WriteString("services:\n")

	// Print services in order
	for _, tag := range asset.ServiceKeys {
		svc, ok := asset.Services[tag]
		if !ok {
			continue
		}

		sb.WriteString(svc.FormatTag() + "\n")

		name := svc.Name
		if name == "" {
			name = asset.DefaultName
		}
		sb.WriteString(fmt.Sprintf("Name=%s\n", name))

		ipv4 := svc.IPv4
		if ipv4 == "" && len(asset.IPv4) > 0 {
			ipv4 = asset.IPv4[0]
		}
		sb.WriteString(fmt.Sprintf("IPv4=%s\n", ipv4))

		ipv6 := svc.IPv6
		if ipv6 == "" && len(asset.IPv6) > 0 {
			ipv6 = asset.IPv6[0]
		}
		sb.WriteString(fmt.Sprintf("IPv6=%s\n", ipv6))

		hostname := svc.Hostname
		if hostname == "" {
			hostname = asset.Hostname
		}
		sb.WriteString(fmt.Sprintf("Hostname=%s\n", hostname))

		ttl := svc.TTL
		if ttl == 0 {
			ttl = asset.TTL
		}
		sb.WriteString(fmt.Sprintf("TTL=%d\n", ttl))

		// Raw formatted banner if present
		if svc.Banner != "" {
			sb.WriteString(svc.Banner + "\n")
		}
	}

	sb.WriteString("answers:\n")
	sb.WriteString("PTR:\n")
	for _, ptr := range asset.Answers {
		sb.WriteString(ptr + "\n")
	}

	_, err := fmt.Fprint(f.w, sb.String())
	return err
}
