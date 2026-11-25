package server

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestSameOrigin(t *testing.T) {
	for _, tc := range []struct {
		name   string
		url    string
		origin string
		want   bool
	}{
		{"same origin", "http://example.test/path", "http://example.test", true},
		{"different scheme", "http://example.test/path", "https://example.test", false},
		{"different port", "http://example.test:8080/path", "http://example.test:8081", false},
		{"different host", "http://example.test/path", "http://attacker.test", false},
		{"invalid origin", "http://example.test/path", "not-an-origin", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", tc.url, nil)
			r.Header.Set("Origin", tc.origin)
			if got := sameOrigin(r); got != tc.want {
				t.Errorf("sameOrigin() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestUIAuthLoginRateLimit(t *testing.T) {
	manager := &uiAuthManager{loginAttempts: make(map[string][]time.Time)}
	for i := 0; i < 5; i++ {
		if !manager.allowLogin("192.0.2.1:1234") {
			t.Fatalf("attempt %d unexpectedly blocked", i+1)
		}
	}
	if manager.allowLogin("192.0.2.1:5678") {
		t.Fatal("sixth attempt from the same address was allowed")
	}
	if !manager.allowLogin("192.0.2.2:1234") {
		t.Fatal("attempt from a different address was blocked")
	}
}
