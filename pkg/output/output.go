package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"mdns-scanner/pkg/parser"
)

// Formatter formats and outputs discovered DeviceAssets
type Formatter struct {
	w      io.Writer
	asJSON bool
}

// NewFormatter creates a new output Formatter
func NewFormatter(w io.Writer, asJSON bool) *Formatter {
	if w == nil {
		w = os.Stdout
	}
	return &Formatter{
		w:      w,
		asJSON: asJSON,
	}
}

// PrintDeviceAsset formats and outputs a single DeviceAsset matching the required template
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

	// Top-level services:
	sb.WriteString("services:\n")

	// Sort service keys for deterministic order
	serviceKeys := make([]string, 0, len(asset.Services))
	for k := range asset.Services {
		serviceKeys = append(serviceKeys, k)
	}
	sort.Strings(serviceKeys)

	for _, k := range serviceKeys {
		svc := asset.Services[k]
		sb.WriteString(fmt.Sprintf("  %s\n", svc.FormatTag()))

		name := svc.Name
		if name == "" {
			name = asset.Name
		}
		sb.WriteString(fmt.Sprintf("    Name: %s\n", name))

		ipv4 := svc.IPv4
		if ipv4 == "" && len(asset.IPv4) > 0 {
			ipv4 = asset.IPv4[0]
		}
		sb.WriteString(fmt.Sprintf("    IPv4: %s\n", ipv4))

		ipv6 := svc.IPv6
		if ipv6 == "" && len(asset.IPv6) > 0 {
			ipv6 = asset.IPv6[0]
		}
		sb.WriteString(fmt.Sprintf("    IPv6: %s\n", ipv6))

		hostname := svc.Hostname
		if hostname == "" {
			hostname = asset.Hostname
		}
		sb.WriteString(fmt.Sprintf("    Hostname: %s\n", hostname))

		ttl := svc.TTL
		if ttl == 0 {
			ttl = asset.TTL
		}
		sb.WriteString(fmt.Sprintf("    TTL: %d\n", ttl))

		// When TXT is empty, safe ignore and do not print empty line
		if svc.Banner != "" {
			sb.WriteString(fmt.Sprintf("    Banner: %s\n", svc.Banner))
		}
	}

	// Tail answers:\nPTR:
	sb.WriteString("answers:\nPTR:\n")
	if len(asset.Answers) > 0 {
		sort.Strings(asset.Answers)
		for _, ptr := range asset.Answers {
			sb.WriteString(fmt.Sprintf("  %s\n", ptr))
		}
	}

	_, err := fmt.Fprint(f.w, sb.String())
	return err
}
