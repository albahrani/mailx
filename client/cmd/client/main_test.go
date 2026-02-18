package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseAddress(t *testing.T) {
	user, domain, err := parseAddress("alice@example.test")
	if err != nil {
		t.Fatalf("parseAddress: %v", err)
	}
	if user != "alice" || domain != "example.test" {
		t.Fatalf("unexpected parse: %q %q", user, domain)
	}
	if _, _, err := parseAddress("bad"); err == nil {
		t.Fatalf("expected error")
	}
}

func TestKeyAttestationPayload_Golden(t *testing.T) {
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i)
	}
	addr := "alice@example.test"
	created := int64(1700000000)
	got := string(keyAttestationPayload(addr, pub, created))
	want := "mailx-key-attestation-v1\n" + addr + "\n" + base64.StdEncoding.EncodeToString(pub) + "\n1700000000"
	if got != want {
		t.Fatalf("unexpected payload\n got: %q\nwant: %q", got, want)
	}
}

func TestHTTPClient_TLSFlag(t *testing.T) {
	old := os.Getenv("MAILX_CLIENT_TLS")
	t.Cleanup(func() { _ = os.Setenv("MAILX_CLIENT_TLS", old) })

	_ = os.Unsetenv("MAILX_CLIENT_TLS")
	c := &Client{}
	hc := c.httpClient()
	tr, _ := hc.Transport.(*http.Transport)
	if tr == nil || tr.TLSClientConfig != nil {
		t.Fatalf("expected nil TLS config when flag unset")
	}

	_ = os.Setenv("MAILX_CLIENT_TLS", "1")
	hc2 := c.httpClient()
	tr2, _ := hc2.Transport.(*http.Transport)
	if tr2 == nil || tr2.TLSClientConfig == nil {
		t.Fatalf("expected TLS config when flag set")
	}
	if tr2.TLSClientConfig.InsecureSkipVerify != true {
		t.Fatalf("expected InsecureSkipVerify=true")
	}
}

func TestFetchSigningKey_Caches(t *testing.T) {
	// Serve well-known over HTTP.
	key := make([]byte, 32)
	for i := range key {
		key[i] = 7
	}
	b64 := base64.StdEncoding.EncodeToString(key)

	reqCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount++
		if r.URL.Path != "/.well-known/mailx-server" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version": "1.0",
			"domain":  "example.test",
			"signKey": b64,
		})
	}))
	defer ts.Close()

	c := &Client{}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Ensure TLS env doesn't interfere.
	old := os.Getenv("MAILX_CLIENT_TLS")
	t.Cleanup(func() { _ = os.Setenv("MAILX_CLIENT_TLS", old) })
	_ = os.Unsetenv("MAILX_CLIENT_TLS")

	// The fetcher builds URLs from the provided domain string. Use the test server's host:port.
	domain := ts.Listener.Addr().String()
	got1, err := c.fetchSigningKey(ctx, domain)
	if err != nil {
		t.Fatalf("fetchSigningKey: %v", err)
	}
	got2, err := c.fetchSigningKey(ctx, domain)
	if err != nil {
		t.Fatalf("fetchSigningKey(2): %v", err)
	}
	if string(got1) != string(key) || string(got2) != string(key) {
		t.Fatalf("unexpected key")
	}
	if reqCount != 1 {
		t.Fatalf("expected 1 http request due to cache, got %d", reqCount)
	}
}

func TestNewClient_ConfigFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client_config.json")

	// Create client with no serverAddr: should not try to connect.
	c, err := NewClient(path)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.config.Username = "alice"
	c.config.Domain = "example.test"
	if err := c.saveConfig(path); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}

	c2, err := NewClient(path)
	if err != nil {
		t.Fatalf("NewClient(2): %v", err)
	}
	if c2.config.Username != "alice" || c2.config.Domain != "example.test" {
		t.Fatalf("unexpected loaded config: %+v", *c2.config)
	}
}

func TestNewClient_InvalidJSON_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client_config.json")
	if err := os.WriteFile(path, []byte("{not-json"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := NewClient(path); err == nil {
		t.Fatalf("expected error")
	}
}

func TestClient_Close_NoConn(t *testing.T) {
	var c Client
	c.Close()
}

func TestSaveConfig_FailsForDirPath(t *testing.T) {
	dir := t.TempDir()
	c := &Client{config: &ClientConfig{Username: "alice"}}
	if err := c.saveConfig(dir); err == nil {
		t.Fatalf("expected error")
	}
}

func TestFetchSigningKey_HTTPStatusError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer ts.Close()

	c := &Client{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := c.fetchSigningKey(ctx, ts.Listener.Addr().String()); err == nil {
		t.Fatalf("expected error")
	}
}

func TestDbg_NoDebugDoesNothing(t *testing.T) {
	old := debugLogging
	debugLogging = false
	t.Cleanup(func() { debugLogging = old })
	dbg("hello %s", "world")
}

func TestClient_HTTPClient_UsesTimeout(t *testing.T) {
	c := &Client{}
	hc := c.httpClient()
	if hc.Timeout <= 0 {
		t.Fatalf("expected timeout")
	}
}

func TestFetchSigningKey_ContextCancel(t *testing.T) {
	old := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = old })
	http.DefaultTransport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	})

	c := &Client{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.fetchSigningKey(ctx, "example.test")
	if err == nil {
		t.Fatalf("expected error")
	}
	if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("expected canceled error, got %v", err)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestFetchSigningKey_EmptyDomain(t *testing.T) {
	c := &Client{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := c.fetchSigningKey(ctx, ""); err == nil {
		t.Fatalf("expected error")
	}
}

func TestFetchSigningKey_MissingSignKey(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"version": "1.0", "domain": "x"})
	}))
	defer ts.Close()

	c := &Client{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := c.fetchSigningKey(ctx, ts.Listener.Addr().String()); err == nil {
		t.Fatalf("expected error")
	}
}

func TestFetchSigningKey_InvalidSignKeyBase64(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"version": "1.0", "domain": "x", "signKey": "!!!"})
	}))
	defer ts.Close()

	c := &Client{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := c.fetchSigningKey(ctx, ts.Listener.Addr().String()); err == nil {
		t.Fatalf("expected error")
	}
}

func TestFetchSigningKey_InvalidSignKeySize(t *testing.T) {
	// 3 bytes -> base64, but signing pubkey must be 32 bytes.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"version": "1.0", "domain": "x", "signKey": "AQID"})
	}))
	defer ts.Close()

	c := &Client{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := c.fetchSigningKey(ctx, ts.Listener.Addr().String()); err == nil {
		t.Fatalf("expected error")
	}
}
