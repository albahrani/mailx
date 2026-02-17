package federation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ServerInfo contains information about a remote server
type ServerInfo struct {
	Domain     string
	PublicKey  []byte
	Endpoint   string
	CachedAt   time.Time
	TTL        time.Duration
}

// Discovery handles server discovery
type Discovery struct {
	cache map[string]*ServerInfo
	mu    sync.RWMutex
}

// WellKnownResponse is the response from /.well-known/mailx-server
type WellKnownResponse struct {
	Version   string `json:"version"`
	Domain    string `json:"domain"`
	PublicKey string `json:"publicKey"`
	Endpoints struct {
		GRPC string `json:"grpc"`
	} `json:"endpoints"`
	Created string `json:"created"`
}

// NewDiscovery creates a new Discovery instance
func NewDiscovery() *Discovery {
	return &Discovery{
		cache: make(map[string]*ServerInfo),
	}
}

// DiscoverServer discovers a server's information
func (d *Discovery) DiscoverServer(ctx context.Context, domain string) (*ServerInfo, error) {
	// Check cache first
	d.mu.RLock()
	if info, ok := d.cache[domain]; ok {
		if time.Since(info.CachedAt) < info.TTL {
			d.mu.RUnlock()
			return info, nil
		}
	}
	d.mu.RUnlock()

	// Fetch from well-known endpoint
	info, err := d.fetchWellKnown(ctx, domain)
	if err != nil {
		return nil, err
	}

	// Cache the result
	d.mu.Lock()
	d.cache[domain] = info
	d.mu.Unlock()

	return info, nil
}

// fetchWellKnown fetches server info from /.well-known/mailx-server
func (d *Discovery) fetchWellKnown(ctx context.Context, domain string) (*ServerInfo, error) {
	url := fmt.Sprintf("https://%s/.well-known/mailx-server", domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch well-known: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("well-known returned status %d", resp.StatusCode)
	}

	var wellKnown WellKnownResponse
	if err := json.NewDecoder(resp.Body).Decode(&wellKnown); err != nil {
		return nil, fmt.Errorf("failed to decode well-known: %w", err)
	}

	// Decode the public key from base64
	// For demo purposes, we'll store it as-is
	publicKey := []byte(wellKnown.PublicKey)

	return &ServerInfo{
		Domain:    wellKnown.Domain,
		PublicKey: publicKey,
		Endpoint:  wellKnown.Endpoints.GRPC,
		CachedAt:  time.Now(),
		TTL:       1 * time.Hour,
	}, nil
}

// ParseAddress parses an email-style address into username and domain
func ParseAddress(address string) (username, domain string, err error) {
	parts := strings.Split(address, "@")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid address format: %s", address)
	}
	return parts[0], parts[1], nil
}

// FormatAddress formats a username and domain into an address
func FormatAddress(username, domain string) string {
	return fmt.Sprintf("%s@%s", username, domain)
}
