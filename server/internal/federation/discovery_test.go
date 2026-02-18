package federation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestParseAddress(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		user    string
		domain  string
		wantErr bool
	}{
		{name: "ok", in: "alice@example.test", user: "alice", domain: "example.test"},
		{name: "missing-at", in: "alice.example.test", wantErr: true},
		{name: "two-ats", in: "a@b@c", wantErr: true},
		{name: "empty", in: "", wantErr: true},
		{name: "leading-at", in: "@example.test", user: "", domain: "example.test"},
		{name: "trailing-at", in: "alice@", user: "alice", domain: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, d, err := ParseAddress(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if u != tt.user || d != tt.domain {
				t.Fatalf("unexpected parse: user=%q domain=%q", u, d)
			}
		})
	}
}

func TestFormatAddress(t *testing.T) {
	got := FormatAddress("alice", "example.test")
	if got != "alice@example.test" {
		t.Fatalf("unexpected address: %q", got)
	}
}

func TestDiscoverServer_ReturnsCachedEntry(t *testing.T) {
	d := NewDiscovery()
	info := &ServerInfo{Domain: "example.test", PublicKey: []byte{1, 2, 3}, Endpoint: "example.test:8443", CachedAt: time.Now(), TTL: time.Hour}

	d.mu.Lock()
	d.cache["example.test"] = info
	d.mu.Unlock()

	got, err := d.DiscoverServer(context.Background(), "example.test")
	if err != nil {
		t.Fatalf("DiscoverServer: %v", err)
	}
	if got != info {
		t.Fatalf("expected cached pointer")
	}
}

func TestDiscoverServer_FetchesWellKnownAndCaches(t *testing.T) {
	// Create a deterministic signing key payload (32 bytes).
	signKey := make([]byte, 32)
	for i := range signKey {
		signKey[i] = byte(i)
	}

	reqCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount++
		if r.URL.Path != "/.well-known/mailx-server" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(WellKnownResponse{
			Version: "1.0",
			Domain:  "example.test",
			SignKey: base64.StdEncoding.EncodeToString(signKey),
			Endpoints: struct {
				GRPC string `json:"grpc"`
			}{GRPC: "example.test:8443"},
			Created: time.Now().Format(time.RFC3339),
		})
	}))
	defer ts.Close()

	d := NewDiscovery()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// fetchWellKnown tries https, then http, then :8080. We provide host:port.
	domain := ts.Listener.Addr().String()
	info, err := d.DiscoverServer(ctx, domain)
	if err != nil {
		t.Fatalf("DiscoverServer: %v", err)
	}
	if info.Endpoint != "example.test:8443" {
		t.Fatalf("unexpected endpoint: %q", info.Endpoint)
	}
	if string(info.PublicKey) != string(signKey) {
		t.Fatalf("unexpected public key")
	}

	// Second call returns cached without new requests.
	info2, err := d.DiscoverServer(ctx, domain)
	if err != nil {
		t.Fatalf("DiscoverServer(2): %v", err)
	}
	if info2 != info {
		t.Fatalf("expected cached pointer")
	}
	if reqCount != 1 {
		t.Fatalf("expected 1 request, got %d", reqCount)
	}
}

func TestDiscoverServer_WellKnownMissingSignKey(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"version": "1.0", "domain": "x", "endpoints": map[string]string{"grpc": "x:1"}})
	}))
	defer ts.Close()

	d := NewDiscovery()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := d.DiscoverServer(ctx, ts.Listener.Addr().String()); err == nil {
		t.Fatalf("expected error")
	}
}
