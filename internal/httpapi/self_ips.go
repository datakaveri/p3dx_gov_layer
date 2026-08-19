package httpapi

import (
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// selfIPs tracks IP addresses that refer to this governance-layer instance
// itself, so a public IP entered on a data-provider form can be recognised as
// "self" rather than as a remote peer. Seeded from OWNER_SELF_IPS and, best
// effort, this instance's own discovered public IP.
type selfIPs struct {
	mu  sync.RWMutex
	set map[string]struct{}
}

// newSelfIPs seeds the set from a CSV list of IPs (e.g. config.OwnerSelfIPs).
func newSelfIPs(csv string) *selfIPs {
	s := &selfIPs{set: map[string]struct{}{"127.0.0.1": {}, "::1": {}}}
	for _, ip := range strings.Split(csv, ",") {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			s.set[ip] = struct{}{}
		}
	}
	return s
}

// Contains reports whether ip is a known self address.
func (s *selfIPs) Contains(ip string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.set[ip]
	return ok
}

// discoverPublicIPAsync best-effort fetches this instance's public IP in the
// background and adds it to the self set, so self-recognition works even when
// OWNER_SELF_IPS isn't configured. Failures are logged and otherwise ignored.
func (s *selfIPs) discoverPublicIPAsync() {
	go func() {
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get("https://api.ipify.org")
		if err != nil {
			log.Printf("[selfIPs] public IP discovery failed: %v", err)
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
		if err != nil {
			log.Printf("[selfIPs] public IP discovery failed: %v", err)
			return
		}
		ip := strings.TrimSpace(string(body))
		if ip == "" {
			return
		}
		s.mu.Lock()
		s.set[ip] = struct{}{}
		s.mu.Unlock()
		log.Printf("[selfIPs] discovered public IP: %s", ip)
	}()
}
