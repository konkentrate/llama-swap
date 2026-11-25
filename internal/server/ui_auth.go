package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/mostlygeek/llama-swap/internal/chain"
	"github.com/mostlygeek/llama-swap/internal/store"
	"golang.org/x/crypto/bcrypt"
)

const uiSessionCookie = "llama_swap_ui_session"
const uiSessionTTL = 12 * time.Hour

type uiSession struct{ expires time.Time }
type uiAuthManager struct {
	store         store.Store
	mu            sync.Mutex
	sessions      map[[32]byte]uiSession
	loginAttempts map[string][]time.Time
}

func newUIAuthManager(st store.Store) *uiAuthManager {
	return &uiAuthManager{store: st, sessions: make(map[[32]byte]uiSession), loginAttempts: make(map[string][]time.Time)}
}

func (m *uiAuthManager) revokeSessions() {
	m.mu.Lock()
	m.sessions = make(map[[32]byte]uiSession)
	m.mu.Unlock()
}

func (m *uiAuthManager) session(r *http.Request) bool {
	c, err := r.Cookie(uiSessionCookie)
	if err != nil {
		return false
	}
	token, err := hex.DecodeString(c.Value)
	if err != nil || len(token) != 32 {
		return false
	}
	hash := sha256.Sum256(token)
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[hash]
	if !ok {
		return false
	}
	if time.Now().After(s.expires) {
		delete(m.sessions, hash)
		return false
	}
	return true
}

func (m *uiAuthManager) middleware(apiKey chain.Middleware, apiKeyRequired bool) chain.Middleware {
	return func(next http.Handler) http.Handler {
		keyHandler := apiKey(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if m == nil || m.store == nil {
				keyHandler.ServeHTTP(w, r)
				return
			}
			_, _, enabled, err := m.store.UIAuth().Get(r.Context())
			if err == nil && enabled && r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/ui/") {
				next.ServeHTTP(w, r)
				return
			}
			if err == nil && enabled && m.session(r) {
				if (isMutation(r.Method) || r.Header.Get("Origin") != "") && !sameOrigin(r) {
					http.Error(w, "invalid origin", http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			if err == nil && enabled && !apiKeyRequired {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			keyHandler.ServeHTTP(w, r)
		})
	}
}

func isMutation(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

func sameOrigin(r *http.Request) bool {
	origin, err := url.Parse(r.Header.Get("Origin"))
	if err != nil || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return false
	}
	if origin.Scheme != "http" && origin.Scheme != "https" {
		return false
	}
	requestScheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		requestScheme = "https"
	}
	if origin.Scheme != requestScheme {
		return false
	}
	request := &url.URL{Scheme: requestScheme, Host: r.Host}
	return strings.EqualFold(origin.Hostname(), request.Hostname()) && effectivePort(origin) == effectivePort(request)
}

func secureRequest(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

func writeUIJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (s *Server) handleUIAuthStatus(w http.ResponseWriter, r *http.Request) {
	_, _, enabled, err := s.store.UIAuth().Get(r.Context())
	if err != nil {
		http.Error(w, "auth status unavailable", http.StatusInternalServerError)
		return
	}
	writeUIJSON(w, http.StatusOK, map[string]bool{"enabled": enabled, "authenticated": enabled && s.uiAuth.session(r), "available": !s.store.IsInMemory()})
}

type uiAuthRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func decodeUIAuthRequest(w http.ResponseWriter, r *http.Request) (uiAuthRequest, bool) {
	var req uiAuthRequest
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if dec.Decode(&req) != nil || strings.TrimSpace(req.Username) != req.Username || len(req.Username) < 1 || len(req.Username) > 128 || len(req.Password) < 12 || len(req.Password) > 72 {
		http.Error(w, "invalid username or password", http.StatusBadRequest)
		return req, false
	}
	return req, true
}

func (s *Server) handleUIAuthSetup(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" && !sameOrigin(r) {
		http.Error(w, "invalid origin", http.StatusForbidden)
		return
	}
	if len(s.cfg.RequiredAPIKeys) == 0 {
		http.Error(w, "UI auth setup requires configured API keys", http.StatusForbidden)
		return
	}
	if s.store.IsInMemory() {
		http.Error(w, "UI auth requires a persistent store", http.StatusConflict)
		return
	}
	req, ok := decodeUIAuthRequest(w, r)
	if !ok {
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if err != nil {
		http.Error(w, "could not configure UI auth", http.StatusInternalServerError)
		return
	}
	if err = s.store.UIAuth().Set(r.Context(), req.Username, string(hash)); err != nil {
		http.Error(w, "UI auth is already configured or unavailable", http.StatusConflict)
		return
	}
	s.uiAuth.revokeSessions()
	if !s.uiAuth.issue(w, r) {
		return
	}
	writeUIJSON(w, http.StatusCreated, map[string]bool{"enabled": true, "authenticated": true})
}

func (m *uiAuthManager) allowLogin(remoteAddr string) bool {
	ip := remoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		ip = host
	}
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	for address, recent := range m.loginAttempts {
		kept := recent[:0]
		for _, at := range recent {
			if now.Sub(at) < time.Minute {
				kept = append(kept, at)
			}
		}
		if len(kept) == 0 {
			delete(m.loginAttempts, address)
		} else {
			m.loginAttempts[address] = kept
		}
	}
	attempts := m.loginAttempts[ip]
	if _, known := m.loginAttempts[ip]; !known && len(m.loginAttempts) >= 4096 {
		return false
	}
	if len(attempts) >= 5 {
		m.loginAttempts[ip] = attempts
		return false
	}
	m.loginAttempts[ip] = append(attempts, now)
	return true
}

func (m *uiAuthManager) clearLoginAttempts(remoteAddr string) {
	ip := remoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		ip = host
	}
	m.mu.Lock()
	delete(m.loginAttempts, ip)
	m.mu.Unlock()
}

func (s *Server) handleUIAuthLogin(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" && !sameOrigin(r) {
		http.Error(w, "invalid origin", http.StatusForbidden)
		return
	}
	if !s.uiAuth.allowLogin(r.RemoteAddr) {
		http.Error(w, "too many login attempts", http.StatusTooManyRequests)
		return
	}
	req, ok := decodeUIAuthRequest(w, r)
	if !ok {
		return
	}
	username, hash, enabled, err := s.store.UIAuth().Get(r.Context())
	if err != nil {
		http.Error(w, "auth unavailable", http.StatusInternalServerError)
		return
	}
	if !enabled || bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil || username != req.Username {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	s.uiAuth.clearLoginAttempts(r.RemoteAddr)
	if !s.uiAuth.issue(w, r) {
		return
	}
	writeUIJSON(w, http.StatusOK, map[string]bool{"authenticated": true})
}

func (s *Server) handleUIAuthLogout(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		http.Error(w, "invalid origin", http.StatusForbidden)
		return
	}
	if c, err := r.Cookie(uiSessionCookie); err == nil {
		if token, err := hex.DecodeString(c.Value); err == nil && len(token) == 32 {
			h := sha256.Sum256(token)
			s.uiAuth.mu.Lock()
			delete(s.uiAuth.sessions, h)
			s.uiAuth.mu.Unlock()
		}
	}
	http.SetCookie(w, &http.Cookie{Name: uiSessionCookie, Value: "", Path: "/", HttpOnly: true, Secure: secureRequest(r), SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeUIJSON(w, http.StatusOK, map[string]bool{"authenticated": false})
}

func (m *uiAuthManager) issue(w http.ResponseWriter, r *http.Request) bool {
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		http.Error(w, "session unavailable", http.StatusInternalServerError)
		return false
	}
	hash := sha256.Sum256(token[:])
	expires := time.Now().Add(uiSessionTTL)
	m.mu.Lock()
	for k, v := range m.sessions {
		if time.Now().After(v.expires) {
			delete(m.sessions, k)
		}
	}
	m.sessions[hash] = uiSession{expires: expires}
	m.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: uiSessionCookie, Value: hex.EncodeToString(token[:]), Path: "/", HttpOnly: true, Secure: secureRequest(r), SameSite: http.SameSiteStrictMode, Expires: expires, MaxAge: int(uiSessionTTL.Seconds())})
	return true
}
