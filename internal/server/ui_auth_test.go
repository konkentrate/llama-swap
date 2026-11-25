package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mostlygeek/llama-swap/internal/config"
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

func TestServer_UIAuthAPIKeyLogin(t *testing.T) {
	cfg := config.Config{RequiredAPIKeys: []string{"secret"}}
	s := newTestServerWithConfig(cfg, newStubRouter(nil, ""), newStubRouter(nil, ""))

	login := httptest.NewRequest(http.MethodPost, "http://example.test/api/ui-auth/login", strings.NewReader(`{"apiKey":"secret"}`))
	login.Header.Set("Content-Type", "application/json")
	login.Header.Set("Origin", "http://example.test")
	loginResponse := httptest.NewRecorder()
	s.ServeHTTP(loginResponse, login)
	if loginResponse.Code != http.StatusOK {
		t.Fatalf("login status = %d, want 200: %s", loginResponse.Code, loginResponse.Body.String())
	}
	cookie := loginResponse.Result().Cookies()[0]

	status := httptest.NewRequest(http.MethodGet, "http://example.test/api/ui-auth/status", nil)
	status.AddCookie(cookie)
	statusResponse := httptest.NewRecorder()
	s.ServeHTTP(statusResponse, status)
	if !strings.Contains(statusResponse.Body.String(), `"authenticated":true`) {
		t.Fatalf("status = %s, want authenticated session", statusResponse.Body.String())
	}

	logout := httptest.NewRequest(http.MethodPost, "http://example.test/api/ui-auth/logout", nil)
	logout.Header.Set("Origin", "http://example.test")
	logout.AddCookie(cookie)
	logoutResponse := httptest.NewRecorder()
	s.ServeHTTP(logoutResponse, logout)
	if logoutResponse.Code != http.StatusOK {
		t.Fatalf("logout status = %d, want 200", logoutResponse.Code)
	}

	status = httptest.NewRequest(http.MethodGet, "http://example.test/api/ui-auth/status", nil)
	status.AddCookie(cookie)
	statusResponse = httptest.NewRecorder()
	s.ServeHTTP(statusResponse, status)
	if !strings.Contains(statusResponse.Body.String(), `"authenticated":false`) {
		t.Fatalf("status after logout = %s, want unauthenticated", statusResponse.Body.String())
	}
}

func TestUIAuthValidAPIKey(t *testing.T) {
	manager := newUIAuthManager([]string{"key-one", "key-two"})
	if !manager.validAPIKey("key-two") {
		t.Fatal("configured API key was rejected")
	}
	if manager.validAPIKey("wrong-key") {
		t.Fatal("unconfigured API key was accepted")
	}
}

func TestUIAuthSessionCookie(t *testing.T) {
	manager := newUIAuthManager(nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "http://example.test/api/ui-auth/login", nil)
	if !manager.issue(w, r) {
		t.Fatal("failed to issue session")
	}
	cookie := w.Result().Cookies()[0]
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie flags = HttpOnly:%v SameSite:%v", cookie.HttpOnly, cookie.SameSite)
	}
	req := httptest.NewRequest("GET", "http://example.test/api/ui-auth/status", nil)
	req.AddCookie(cookie)
	if !manager.session(req) {
		t.Fatal("issued session was rejected")
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
