package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

var ipv4Re = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)

// selfIPs is the set of IPs that mean "this gov_layer host". A receiver
// co-located with gov_layer is reached via loopback (a VM cannot reach its own
// public IP — no hairpin NAT on most clouds), so an IP in this set is rewritten
// to 127.0.0.1. Mirrors the SELF_IPS logic in governance.routes.js.
type selfIPs struct {
	mu  sync.RWMutex
	set map[string]struct{}
}

// newSelfIPs seeds the set with loopback aliases, every local interface address,
// and any IPs from OWNER_SELF_IPS (CSV).
func newSelfIPs(ownerSelfIPsCSV string) *selfIPs {
	s := &selfIPs{set: map[string]struct{}{}}
	for _, ip := range []string{"localhost", "127.0.0.1", "0.0.0.0", "::1"} {
		s.add(ip)
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				s.add(ipnet.IP.String())
			}
		}
	}
	for _, ip := range strings.Split(ownerSelfIPsCSV, ",") {
		if t := strings.TrimSpace(ip); t != "" {
			s.add(t)
		}
	}
	return s
}

func (s *selfIPs) add(ip string) {
	s.mu.Lock()
	s.set[ip] = struct{}{}
	s.mu.Unlock()
}

func (s *selfIPs) has(ip string) bool {
	s.mu.RLock()
	_, ok := s.set[ip]
	s.mu.RUnlock()
	return ok
}

// reachableHost rewrites an IP that names this host to loopback; remote IPs pass
// through unchanged. Mirrors reachableHost().
func (s *selfIPs) reachableHost(ip string) string {
	if s.has(ip) {
		return "127.0.0.1"
	}
	return ip
}

// discoverPublicIPAsync best-effort discovers this host's public IP at startup
// and treats it as self too, so a public IP entered on a form "just works".
// Fire-and-forget: tries Azure IMDS first, then generic public-IP services.
// Mirrors the IIFE in governance.routes.js.
func (s *selfIPs) discoverPublicIPAsync() {
	go func() {
		client := &http.Client{}

		addIP := func(ip string) {
			ip = strings.TrimSpace(ip)
			if ipv4Re.MatchString(ip) {
				s.add(ip)
			}
		}

		// Azure IMDS (may report empty when the public IP lives on the LB).
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet,
				"http://169.254.169.254/metadata/instance/network/interface?api-version=2021-02-01", nil)
			if err != nil {
				return
			}
			req.Header.Set("Metadata", "true")
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				return
			}
			var ifaces []struct {
				IPv4 struct {
					IPAddress []struct {
						PublicIPAddress string `json:"publicIpAddress"`
					} `json:"ipAddress"`
				} `json:"ipv4"`
			}
			body, _ := io.ReadAll(resp.Body)
			if json.Unmarshal(body, &ifaces) == nil {
				for _, iface := range ifaces {
					for _, cfg := range iface.IPv4.IPAddress {
						addIP(cfg.PublicIPAddress)
					}
				}
			}
		}()

		// Generic public-IP services (work off-Azure / when IMDS returns nothing).
		for _, url := range []string{"https://api.ipify.org", "https://ifconfig.me/ip"} {
			ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				cancel()
				continue
			}
			resp, err := client.Do(req)
			if err != nil {
				cancel()
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			ok := resp.StatusCode >= 200 && resp.StatusCode < 300
			resp.Body.Close()
			cancel()
			if ok {
				addIP(string(body))
				break
			}
		}
	}()
}
