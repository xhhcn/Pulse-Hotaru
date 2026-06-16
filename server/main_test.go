package main

import (
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func resetTrustedProxiesForTest(t *testing.T, env string) {
	t.Helper()
	t.Setenv("TRUSTED_PROXIES", env)
	trustedProxyOnce = sync.Once{}
	trustedProxyNets = nil
}

func TestGetClientIPIgnoresForwardedHeadersFromUntrustedPeer(t *testing.T) {
	resetTrustedProxiesForTest(t, "")
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "198.51.100.10:4321"
	req.Header.Set("X-Forwarded-For", "203.0.113.99")
	req.Header.Set("X-Real-IP", "203.0.113.98")

	if got, want := getClientIP(req), "198.51.100.10"; got != want {
		t.Fatalf("getClientIP() = %q, want %q", got, want)
	}
}

func TestGetClientIPTrustsLoopbackProxy(t *testing.T) {
	resetTrustedProxiesForTest(t, "")
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:4321"
	req.Header.Set("X-Forwarded-For", "203.0.113.99, 10.0.0.20")

	if got, want := getClientIP(req), "203.0.113.99"; got != want {
		t.Fatalf("getClientIP() = %q, want %q", got, want)
	}
}

func TestGetClientIPTrustsConfiguredProxyCIDR(t *testing.T) {
	resetTrustedProxiesForTest(t, "10.10.0.0/16")
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.10.5.20:4321"
	req.Header.Set("X-Real-IP", "203.0.113.77")

	if got, want := getClientIP(req), "203.0.113.77"; got != want {
		t.Fatalf("getClientIP() = %q, want %q", got, want)
	}
}

func resetTCPingCacheForTest(t *testing.T) {
	t.Helper()
	tcpingCacheMu.Lock()
	defer tcpingCacheMu.Unlock()
	tcpingCache = make(map[tcpingCacheKey]*tcpingCacheEntry)
	tcpingCacheBytes = 0
}

func TestTCPingCacheIsTargetScoped(t *testing.T) {
	resetTCPingCacheForTest(t)
	response := TCPingHistoryResponse{
		Results: []TCPingResult{{
			ClientID:  "client-a",
			Target:    "example.com",
			Timestamp: time.Now().UTC(),
		}},
	}

	cacheTCPingResults("client-a", "example.com", response)

	if _, ok := getCachedTCPingResultsJSON("client-a", "example.com"); !ok {
		t.Fatal("expected exact client+target cache hit")
	}
	if _, ok := getCachedTCPingResultsJSON("client-a", "other.example"); ok {
		t.Fatal("unexpected cache hit for different target")
	}
	if _, ok := getCachedTCPingResultsJSON("client-a", ""); ok {
		t.Fatal("unexpected cache hit for all-target history")
	}
}

func TestTCPingCacheSkipsAllTargetHistory(t *testing.T) {
	resetTCPingCacheForTest(t)

	cacheTCPingResults("client-a", "", TCPingHistoryResponse{})

	if _, ok := getCachedTCPingResultsJSON("client-a", ""); ok {
		t.Fatal("all-target history responses should not be cached")
	}
}

func TestTCPingCacheSkipsOversizedResponseWithoutPartialEntry(t *testing.T) {
	resetTCPingCacheForTest(t)
	oldMaxBytes := tcpingCacheMaxBytes
	tcpingCacheMaxBytes = 128
	t.Cleanup(func() {
		tcpingCacheMaxBytes = oldMaxBytes
	})

	response := TCPingHistoryResponse{
		Results: []TCPingResult{{
			ClientID:  "client-a",
			Target:    "very-long-target-name-that-makes-the-json-body-larger-than-the-test-cache-limit.example.com:443",
			Timestamp: time.Now().UTC(),
		}},
	}

	cacheTCPingResults("client-a", "example.com", response)

	if _, ok := getCachedTCPingResultsJSON("client-a", "example.com"); ok {
		t.Fatal("oversized TCPing history responses should skip cache instead of storing partial data")
	}
	if tcpingCacheBytes != 0 {
		t.Fatalf("tcpingCacheBytes = %d, want 0", tcpingCacheBytes)
	}
}
