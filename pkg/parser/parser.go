package parser

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
	"mdns-scanner/pkg/probe"
)

// ServiceEntry represents an exposed service discovered on a port
type ServiceEntry struct {
	Port     int    `json:"port"`
	Proto    string `json:"proto"`   // tcp, udp
	Service  string `json:"service"` // workstation, http, smb, qdiscover, device-info, afpovertcp
	FullName string `json:"full_name"`
	Target   string `json:"target,omitempty"`
	Name     string `json:"name,omitempty"`
	IPv4     string `json:"ipv4,omitempty"`
	IPv6     string `json:"ipv6,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	TTL      uint32 `json:"ttl,omitempty"`
	Banner   string `json:"banner,omitempty"` // e.g. "path=/" or "accessType=https,accessPort=86,model=TS-X64..."
}

// FormatTag returns the service title tag, e.g. "9/tcp workstation:" or "device-info:"
func (s ServiceEntry) FormatTag() string {
	svc := strings.ToLower(s.Service)
	if svc == "device-info" || s.Port == 0 {
		return "device-info:"
	}
	proto := strings.ToLower(s.Proto)
	if proto == "" {
		proto = "tcp"
	}
	return fmt.Sprintf("%d/%s %s:", s.Port, proto, svc)
}

// DeviceAsset aggregates all services and metadata for an asset
type DeviceAsset struct {
	IP          string                  `json:"ip"`
	Hostname    string                  `json:"hostname"`
	DefaultName string                  `json:"name"`
	IPv4        []string                `json:"ipv4"`
	IPv6        []string                `json:"ipv6"`
	TTL         uint32                  `json:"ttl"`
	Answers     []string                `json:"answers"`  // answers: PTR:
	Services    map[string]ServiceEntry `json:"services"` // key: tag string
	ServiceKeys []string                `json:"service_keys"`
}

// FormatTXTBanner parses TXT records into comma-separated key=value or tag string
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
		parts := strings.SplitN(raw, "=", 2)
		if len(parts) == 2 {
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			if k != "" {
				cleanItems = append(cleanItems, fmt.Sprintf("%s=%s", k, v))
			}
		} else {
			cleanItems = append(cleanItems, raw)
		}
	}

	return strings.Join(cleanItems, ",")
}

// Aggregator aggregates responses from mDNS packets by IP
type Aggregator struct {
	assets map[string]*DeviceAsset
}

func NewAggregator() *Aggregator {
	return &Aggregator{
		assets: make(map[string]*DeviceAsset),
	}
}

func DefaultPortForService(svc string) int {
	switch strings.ToLower(svc) {
	case "workstation":
		return 9
	case "smb", "microsoft-ds":
		return 445
	case "afpovertcp":
		return 548
	case "http":
		return 80
	case "qdiscover":
		return 5000
	case "https":
		return 443
	case "device-info":
		return 0
	case "ssh":
		return 22
	default:
		return 0
	}
}

// ProcessRawResponse parses and aggregates mDNS packets
func (a *Aggregator) ProcessRawResponse(raw *probe.RawResponse) *DeviceAsset {
	if raw == nil || raw.Msg == nil {
		return nil
	}

	allRRs := append([]dns.RR{}, raw.Msg.Answer...)
	allRRs = append(allRRs, raw.Msg.Extra...)
	allRRs = append(allRRs, raw.Msg.Ns...)

	var (
		discoveredHostname string
		discoveredTTL      uint32
		ipv4List           []string
		ipv6List           []string
		answersPTR         []string
		srvList            []*dns.SRV
		txtByService       = make(map[string]string)
		instanceNames      = make(map[string]string) // svcType -> instance Name
	)

	for _, rr := range allRRs {
		header := rr.Header()
		if discoveredTTL == 0 && header.Ttl > 0 {
			discoveredTTL = header.Ttl
		}

		cleanHeaderName := strings.TrimSuffix(header.Name, ".")

		switch v := rr.(type) {
		case *dns.PTR:
			ptrVal := strings.TrimSuffix(v.Ptr, ".")
			answersPTR = appendUnique(answersPTR, ptrVal)

			// If PTR points to an instance like "slw-nas._http._tcp.local"
			instName, svcType := extractInstanceAndService(ptrVal)
			if instName != "" && svcType != "" {
				instanceNames[svcType] = instName
			}

		case *dns.SRV:
			srvList = append(srvList, v)
			targetHost := strings.TrimSuffix(v.Target, ".")
			if discoveredHostname == "" {
				discoveredHostname = targetHost
			}
			instName, svcType := extractInstanceAndService(cleanHeaderName)
			if instName != "" && svcType != "" {
				instanceNames[svcType] = instName
			}

		case *dns.TXT:
			bannerStr := FormatTXTBanner(v.Txt)
			if bannerStr != "" {
				txtByService[cleanHeaderName] = bannerStr
				_, svcType := extractInstanceAndService(cleanHeaderName)
				if svcType != "" {
					txtByService[svcType] = bannerStr
				}
			}

		case *dns.A:
			ipStr := v.A.String()
			ipv4List = appendUnique(ipv4List, ipStr)
			if discoveredHostname == "" {
				discoveredHostname = cleanHeaderName
			}

		case *dns.AAAA:
			ipStr := v.AAAA.String()
			ipv6List = appendUnique(ipv6List, ipStr)
			if discoveredHostname == "" {
				discoveredHostname = cleanHeaderName
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

	// Extract clean host name (e.g. slw-nas from slw-nas.local)
	cleanDefaultName := strings.TrimSuffix(discoveredHostname, ".local")
	if strings.Contains(cleanDefaultName, ".") {
		cleanDefaultName = strings.Split(cleanDefaultName, ".")[0]
	}

	assetKey := raw.Target.IP
	asset, exists := a.assets[assetKey]
	if !exists {
		asset = &DeviceAsset{
			IP:          raw.Target.IP,
			Hostname:    discoveredHostname,
			DefaultName: cleanDefaultName,
			TTL:         discoveredTTL,
			IPv4:        ipv4List,
			IPv6:        ipv6List,
			Answers:     make([]string, 0),
			Services:    make(map[string]ServiceEntry),
			ServiceKeys: make([]string, 0),
		}
		a.assets[assetKey] = asset
	}

	if asset.Hostname == "" || asset.Hostname == asset.IP {
		asset.Hostname = discoveredHostname
	}
	if asset.DefaultName == "" || asset.DefaultName == asset.IP {
		asset.DefaultName = cleanDefaultName
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

	// Process SRVs
	for _, srv := range srvList {
		svcName, proto := parseServiceNameAndProto(srv.Hdr.Name)
		port := int(srv.Port)
		if port == 0 {
			port = DefaultPortForService(svcName)
		}
		if port == 0 {
			port = raw.Target.Port
		}

		instName, svcType := extractInstanceAndService(srv.Hdr.Name)
		serviceName := instName
		if serviceName == "" {
			serviceName = instanceNames[svcType]
		}
		if serviceName == "" {
			serviceName = asset.DefaultName
		}
		serviceName = unescapeDNS(serviceName)

		banner := getBanner(txtByService, srv.Hdr.Name, svcType)

		entry := ServiceEntry{
			Port:     port,
			Proto:    proto,
			Service:  svcName,
			FullName: strings.TrimSuffix(srv.Hdr.Name, "."),
			Target:   asset.Hostname,
			Name:     serviceName,
			IPv4:     primaryIPv4,
			IPv6:     primaryIPv6,
			Hostname: asset.Hostname,
			TTL:      asset.TTL,
			Banner:   banner,
		}

		tag := entry.FormatTag()
		if _, exists := asset.Services[tag]; !exists {
			asset.ServiceKeys = append(asset.ServiceKeys, tag)
		}
		asset.Services[tag] = entry
	}

	// Also ensure all PTR services exist in Services list (e.g. smb, workstation, device-info, afpovertcp)
	for _, ptr := range asset.Answers {
		svcName, proto := parseServiceNameAndProto(ptr)
		if svcName == "" || svcName == "dns-sd" || svcName == "services" {
			continue
		}

		// If this service type is already covered by an SRV record, skip fallback
		alreadyCovered := false
		for _, s := range asset.Services {
			if strings.EqualFold(s.Service, svcName) {
				alreadyCovered = true
				break
			}
		}
		if alreadyCovered {
			continue
		}

		port := DefaultPortForService(svcName)
		if port == 0 && svcName != "device-info" {
			port = raw.Target.Port
		}

		dummyEntry := ServiceEntry{
			Port:    port,
			Proto:   proto,
			Service: svcName,
		}
		tag := dummyEntry.FormatTag()

		if _, exists := asset.Services[tag]; !exists {
			instName, svcType := extractInstanceAndService(ptr)
			serviceName := instName
			if serviceName == "" {
				serviceName = instanceNames[svcType]
			}
			if serviceName == "" {
				if svcName == "device-info" || svcName == "afpovertcp" {
					if afpName, ok := instanceNames["afpovertcp"]; ok {
						serviceName = afpName
					} else {
						serviceName = asset.DefaultName + "(AFP)"
					}
				} else {
					serviceName = asset.DefaultName
				}
			}
			serviceName = unescapeDNS(serviceName)

			banner := getBanner(txtByService, ptr, svcType)

			entry := ServiceEntry{
				Port:     port,
				Proto:    proto,
				Service:  svcName,
				FullName: ptr,
				Target:   asset.Hostname,
				Name:     serviceName,
				IPv4:     primaryIPv4,
				IPv6:     primaryIPv6,
				Hostname: asset.Hostname,
				TTL:      asset.TTL,
				Banner:   banner,
			}

			asset.ServiceKeys = append(asset.ServiceKeys, tag)
			asset.Services[tag] = entry
		}
	}

	return asset
}

func unescapeDNS(s string) string {
	s = strings.ReplaceAll(s, `\ `, " ")
	s = strings.ReplaceAll(s, `\(`, "(")
	s = strings.ReplaceAll(s, `\)`, ")")
	s = strings.ReplaceAll(s, `\[`, "[")
	s = strings.ReplaceAll(s, `\]`, "]")
	s = strings.ReplaceAll(s, `\:`, ":")
	s = strings.ReplaceAll(s, `\.`, ".")
	s = strings.ReplaceAll(s, `\\`, `\`)
	return s
}

func getBanner(txtMap map[string]string, names ...string) string {
	for _, name := range names {
		clean := strings.TrimSuffix(name, ".")
		if b, ok := txtMap[clean]; ok && b != "" {
			return b
		}
	}
	for _, name := range names {
		clean := strings.TrimSuffix(name, ".")
		for k, b := range txtMap {
			if strings.Contains(k, clean) || strings.Contains(clean, k) {
				return b
			}
		}
	}
	return ""
}

func (a *Aggregator) GetAllAssets() []*DeviceAsset {
	list := make([]*DeviceAsset, 0, len(a.assets))
	for _, asset := range a.assets {
		list = append(list, asset)
	}
	return list
}

func extractInstanceAndService(fullName string) (string, string) {
	fullName = strings.TrimSuffix(fullName, ".")
	tokens := strings.Split(fullName, ".")
	var instParts []string
	var svcType string
	for _, t := range tokens {
		if strings.HasPrefix(t, "_") {
			if svcType == "" {
				svcType = strings.TrimPrefix(t, "_")
			}
		} else if svcType == "" && t != "local" {
			instParts = append(instParts, t)
		}
	}
	inst := strings.Join(instParts, ".")
	return inst, svcType
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
