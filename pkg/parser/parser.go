package parser

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/miekg/dns"
	"mdns-scanner/pkg/probe"
)

// ServiceEntry represents an exposed service discovered on a port
type ServiceEntry struct {
	Port     int    `json:"port"`
	Proto    string `json:"proto"`   // tcp, udp
	Service  string `json:"service"` // http, qdiscover, smb, workstation, etc.
	FullName string `json:"full_name"`
	Target   string `json:"target,omitempty"`
	Name     string `json:"name,omitempty"`
	IPv4     string `json:"ipv4,omitempty"`
	IPv6     string `json:"ipv6,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	TTL      uint32 `json:"ttl,omitempty"`
	Banner   string `json:"banner,omitempty"` // Formatted as "model=TS-X64,fwVer=5.2.9"
}

// FormatTag returns tag like "5000/tcp http:"
func (s ServiceEntry) FormatTag() string {
	proto := strings.ToLower(s.Proto)
	if proto == "" {
		proto = "tcp"
	}
	svc := strings.ToLower(s.Service)
	if svc == "" {
		svc = "unknown"
	}
	return fmt.Sprintf("%d/%s %s:", s.Port, proto, svc)
}

// DeviceAsset aggregates all discovered services and metadata for an asset (IP + Hostname)
type DeviceAsset struct {
	IP       string                  `json:"ip"`
	Hostname string                  `json:"hostname"`
	Name     string                  `json:"name"`
	IPv4     []string                `json:"ipv4"`
	IPv6     []string                `json:"ipv6"`
	TTL      uint32                  `json:"ttl"`
	Answers  []string                `json:"answers"`  // answers: PTR:
	Services map[string]ServiceEntry `json:"services"` // key: "port/proto service"
	Banner   string                  `json:"banner"`   // Merged banner
}

// FormatTXTBanner parses TXT slice into "k1=v1,k2=v2" or "k1=v1,tag" safely without panic
func FormatTXTBanner(txtSlice []string) string {
	if len(txtSlice) == 0 {
		return ""
	}

	cleanItems := make([]string, 0, len(txtSlice))
	for _, raw := range txtSlice {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		// strings.SplitN with 2 avoids index out of range panic
		parts := strings.SplitN(raw, "=", 2)
		if len(parts) == 2 {
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			if k != "" {
				cleanItems = append(cleanItems, fmt.Sprintf("%s=%s", k, v))
			}
		} else {
			// Single tag without '='
			cleanItems = append(cleanItems, raw)
		}
	}

	return strings.Join(cleanItems, ",")
}

// Aggregator aggregates responses from mDNS packets by (IP, Hostname)
type Aggregator struct {
	assets map[string]*DeviceAsset
}

// NewAggregator creates an aggregator instance
func NewAggregator() *Aggregator {
	return &Aggregator{
		assets: make(map[string]*DeviceAsset),
	}
}

// ProcessRawResponse merges a probe response into aggregated DeviceAssets
func (a *Aggregator) ProcessRawResponse(raw *probe.RawResponse) *DeviceAsset {
	if raw == nil || raw.Msg == nil {
		return nil
	}

	allRRs := append([]dns.RR{}, raw.Msg.Answer...)
	allRRs = append(allRRs, raw.Msg.Extra...)
	allRRs = append(allRRs, raw.Msg.Ns...)

	var (
		discoveredHostname string
		discoveredName     string
		discoveredTTL      uint32
		ipv4List           []string
		ipv6List           []string
		answersPTR         []string
		srvList            []*dns.SRV
		txtByService       = make(map[string]string)
	)

	for _, rr := range allRRs {
		header := rr.Header()
		if discoveredTTL == 0 && header.Ttl > 0 {
			discoveredTTL = header.Ttl
		}

		switch v := rr.(type) {
		case *dns.PTR:
			ptrVal := strings.TrimSuffix(v.Ptr, ".")
			answersPTR = appendUnique(answersPTR, ptrVal)

		case *dns.SRV:
			srvList = append(srvList, v)
			targetHost := strings.TrimSuffix(v.Target, ".")
			if discoveredHostname == "" {
				discoveredHostname = targetHost
			}

		case *dns.TXT:
			bannerStr := FormatTXTBanner(v.Txt)
			if bannerStr != "" {
				txtByService[strings.TrimSuffix(header.Name, ".")] = bannerStr
			}

		case *dns.A:
			ipStr := v.A.String()
			ipv4List = appendUnique(ipv4List, ipStr)
			if discoveredHostname == "" {
				discoveredHostname = strings.TrimSuffix(header.Name, ".")
			}

		case *dns.AAAA:
			ipStr := v.AAAA.String()
			ipv6List = appendUnique(ipv6List, ipStr)
			if discoveredHostname == "" {
				discoveredHostname = strings.TrimSuffix(header.Name, ".")
			}
		}
	}

	// Fallback IPv4 to probe target IP if A record is missing
	if len(ipv4List) == 0 && raw.Target.IP != "" {
		if ip := net.ParseIP(raw.Target.IP); ip != nil && ip.To4() != nil {
			ipv4List = append(ipv4List, raw.Target.IP)
		}
	}

	if discoveredHostname == "" {
		if len(answersPTR) > 0 {
			discoveredHostname = answersPTR[0]
		} else {
			discoveredHostname = raw.Target.IP
		}
	}

	if discoveredName == "" {
		parts := strings.Split(discoveredHostname, ".")
		discoveredName = parts[0]
	}

	// Asset key: IP + Hostname
	assetKey := fmt.Sprintf("%s_%s", raw.Target.IP, discoveredHostname)
	asset, exists := a.assets[assetKey]
	if !exists {
		asset = &DeviceAsset{
			IP:       raw.Target.IP,
			Hostname: discoveredHostname,
			Name:     discoveredName,
			TTL:      discoveredTTL,
			IPv4:     ipv4List,
			IPv6:     ipv6List,
			Answers:  make([]string, 0),
			Services: make(map[string]ServiceEntry),
		}
		a.assets[assetKey] = asset
	}

	// Merge basic fields
	if asset.Name == "" || asset.Name == asset.IP {
		asset.Name = discoveredName
	}
	if asset.TTL == 0 && discoveredTTL > 0 {
		asset.TTL = discoveredTTL
	}
	for _, ip := range ipv4List {
		asset.IPv4 = appendUnique(asset.IPv4, ip)
	}
	for _, ip := range ipv6List {
		asset.IPv6 = appendUnique(asset.IPv6, ip)
	}
	for _, ptr := range answersPTR {
		asset.Answers = appendUnique(asset.Answers, ptr)
	}

	primaryIPv4 := ""
	if len(asset.IPv4) > 0 {
		primaryIPv4 = asset.IPv4[0]
	}
	primaryIPv6 := ""
	if len(asset.IPv6) > 0 {
		primaryIPv6 = asset.IPv6[0]
	}

	// Build & merge SRV services
	for _, srv := range srvList {
		svcName, proto := parseServiceNameAndProto(srv.Hdr.Name)
		port := int(srv.Port)
		if port == 0 {
			port = raw.Target.Port
		}
		entryKey := fmt.Sprintf("%d/%s %s:", port, proto, svcName)

		banner := ""
		srvFullName := strings.TrimSuffix(srv.Hdr.Name, ".")
		if b, ok := txtByService[srvFullName]; ok {
			banner = b
		} else {
			for name, b := range txtByService {
				if strings.Contains(srvFullName, name) || strings.Contains(name, srvFullName) {
					banner = b
					break
				}
			}
		}

		targetHost := strings.TrimSuffix(srv.Target, ".")
		if targetHost == "" {
			targetHost = asset.Hostname
		}

		asset.Services[entryKey] = ServiceEntry{
			Port:     port,
			Proto:    proto,
			Service:  svcName,
			FullName: srvFullName,
			Target:   targetHost,
			Name:     asset.Name,
			IPv4:     primaryIPv4,
			IPv6:     primaryIPv6,
			Hostname: asset.Hostname,
			TTL:      asset.TTL,
			Banner:   banner,
		}

		if banner != "" {
			if asset.Banner == "" {
				asset.Banner = banner
			} else if !strings.Contains(asset.Banner, banner) {
				asset.Banner += "," + banner
			}
		}
	}

	// Fallback services from PTR answers if no SRV records found
	if len(asset.Services) == 0 {
		for _, ptr := range asset.Answers {
			svcName, proto := parseServiceNameAndProto(ptr)
			if svcName != "" && svcName != "dns-sd" && svcName != "services" {
				entryKey := fmt.Sprintf("%d/%s %s:", raw.Target.Port, proto, svcName)
				banner := ""
				if b, ok := txtByService[ptr]; ok {
					banner = b
				}
				asset.Services[entryKey] = ServiceEntry{
					Port:     raw.Target.Port,
					Proto:    proto,
					Service:  svcName,
					FullName: ptr,
					Target:   asset.Hostname,
					Name:     asset.Name,
					IPv4:     primaryIPv4,
					IPv6:     primaryIPv6,
					Hostname: asset.Hostname,
					TTL:      asset.TTL,
					Banner:   banner,
				}
			}
		}
	}

	return asset
}

// GetAllAssets returns a list of all aggregated device assets
func (a *Aggregator) GetAllAssets() []*DeviceAsset {
	list := make([]*DeviceAsset, 0, len(a.assets))
	for _, asset := range a.assets {
		list = append(list, asset)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].IP < list[j].IP
	})
	return list
}

func parseServiceNameAndProto(name string) (string, string) {
	name = strings.TrimSuffix(name, ".")
	tokens := strings.Split(name, ".")
	var svc, proto string
	for _, t := range tokens {
		if strings.HasPrefix(t, "_") {
			clean := strings.TrimPrefix(t, "_")
			if clean == "tcp" || clean == "udp" {
				proto = clean
			} else if svc == "" && clean != "dns-sd" && clean != "services" {
				svc = clean
			}
		}
	}
	if proto == "" {
		proto = "tcp"
	}
	if svc == "" {
		svc = "workstation"
	}
	return svc, proto
}

func appendUnique(slice []string, val string) []string {
	for _, item := range slice {
		if item == val {
			return slice
		}
	}
	return append(slice, val)
}
