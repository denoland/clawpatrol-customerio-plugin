package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/pluginsdk"
)

func TestCustomerIOBuildDefaultsReadOnlyEUEnv(t *testing.T) {
	out, err := customerIOServiceAccountDef().Build(pluginsdk.BuildRequest{ConfigJSON: []byte(`{"region":"eu"}`)})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	res := out.(pluginsdk.CredentialBuildResult)
	cfg := res.Canonical.(customerIOConfig)
	if cfg.Region != "eu" || !cfg.ReadOnly || cfg.BaseURL != "https://eu.fly.customer.io" {
		t.Fatalf("cfg = %#v", cfg)
	}
	vars := map[string]string{}
	for _, ev := range res.Metadata.EnvVars {
		vars[ev.Name] = ev.Value
	}
	for _, name := range []string{"CUSTOMERIO_TOKEN", "CIO_ACCESS_TOKEN", "CIO_TOKEN"} {
		if vars[name] != phCustomerIOAccess {
			t.Fatalf("%s = %q, want placeholder", name, vars[name])
		}
	}
	if vars["CUSTOMER_IO_BASE_URL"] != "https://eu.fly.customer.io" || vars["CIO_API_URL"] != "https://eu.fly.customer.io" {
		t.Fatalf("base URL env vars = %#v", vars)
	}
	if !res.Metadata.HTTPInject || len(res.Metadata.SecretSlots) != 1 {
		t.Fatalf("metadata = %#v", res.Metadata)
	}
}

func TestCustomerIOExchangeCachesTokenAndSendsReadOnlyScope(t *testing.T) {
	var calls int
	jwt := testJWT(time.Now().Add(time.Hour))
	useCustomerIOTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
			http.Error(w, "bad method", http.StatusInternalServerError)
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
			http.Error(w, "bad form", http.StatusInternalServerError)
			return
		}
		if got := r.Form.Get("grant_type"); got != "client_credentials" {
			t.Errorf("grant_type = %q", got)
			http.Error(w, "bad grant", http.StatusInternalServerError)
			return
		}
		if got := r.Form.Get("client_secret"); got != "sa_live_test_secret" {
			t.Errorf("client_secret = %q", got)
			http.Error(w, "bad secret", http.StatusInternalServerError)
			return
		}
		if got := r.Form.Get("scope"); got != "read_only" {
			t.Errorf("scope = %q", got)
			http.Error(w, "bad scope", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(customerIOTokenResponse{AccessToken: jwt, TokenType: "Bearer", ExpiresIn: 3600})
	}))

	cache := &customerIOTokenCache{tokens: map[string]cachedCustomerIOToken{}}
	cfg := customerIOConfig{Region: "eu", ReadOnly: true, BaseURL: "https://eu.fly.customer.io"}
	for i := 0; i < 2; i++ {
		got, err := cache.accessToken(context.Background(), cfg, "sa_live_test_secret")
		if err != nil {
			t.Fatalf("accessToken: %v", err)
		}
		if got != jwt {
			t.Fatalf("accessToken = %q, want jwt", got)
		}
	}
	if calls != 1 {
		t.Fatalf("token exchange calls = %d, want 1", calls)
	}
}

func TestCustomerIORejectsNonCustomerIOExchangeBaseURL(t *testing.T) {
	cases := []customerIOConfig{
		{Region: "eu", ReadOnly: true, BaseURL: "http://eu.fly.customer.io"},
		{Region: "eu", ReadOnly: true, BaseURL: "https://example.invalid"},
		{Region: "eu", ReadOnly: true, BaseURL: "https://us.fly.customer.io"},
		{Region: "eu", ReadOnly: true, BaseURL: "https://eu.fly.customer.io/path"},
	}
	for _, cfg := range cases {
		if _, _, err := exchangeCustomerIOServiceToken(context.Background(), cfg, "sa_live_test_secret"); err == nil {
			t.Fatalf("exchangeCustomerIOServiceToken(%#v) succeeded, want validation error", cfg)
		}
	}
}

func TestCustomerIOCacheKeyIncludesBaseURL(t *testing.T) {
	left := customerIOCacheKey(customerIOConfig{Region: "eu", ReadOnly: true, BaseURL: "https://eu.fly.customer.io"}, "sa_live_test_secret")
	right := customerIOCacheKey(customerIOConfig{Region: "eu", ReadOnly: true, BaseURL: "https://us.fly.customer.io"}, "sa_live_test_secret")
	if left == right {
		t.Fatalf("cache key did not include base URL: %q", left)
	}
}

func TestCustomerIOInjectHTTPSetsBearerJWT(t *testing.T) {
	jwt := testJWT(time.Now().Add(time.Hour))
	useCustomerIOTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
			http.Error(w, "bad form", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(customerIOTokenResponse{AccessToken: jwt, TokenType: "Bearer", ExpiresIn: 3600})
	}))

	cfg := customerIOConfig{Region: "eu", ReadOnly: true, BaseURL: "https://eu.fly.customer.io"}
	cfgJSON, _ := json.Marshal(cfg)
	oldCache := customerIOTokens
	customerIOTokens = &customerIOTokenCache{tokens: map[string]cachedCustomerIOToken{}}
	t.Cleanup(func() { customerIOTokens = oldCache })

	out, err := injectCustomerIOHTTP(context.Background(), pluginsdk.HTTPInjectRequest{
		CredentialCanonicalConfig: cfgJSON,
		CredentialSecret:          []byte("sa_live_test_secret"),
	})
	if err != nil {
		t.Fatalf("InjectHTTP: %v", err)
	}
	if len(out.Headers) != 1 || out.Headers[0].Name != "Authorization" || out.Headers[0].Values[0] != "Bearer "+jwt {
		t.Fatalf("headers = %#v", out.Headers)
	}
	if len(out.Redactions) != 1 || out.Redactions[0] != jwt {
		t.Fatalf("redactions = %#v", out.Redactions)
	}
}

func useCustomerIOTestServer(t *testing.T, handler http.Handler) {
	t.Helper()
	ts := httptest.NewTLSServer(handler)
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, ts.Listener.Addr().String())
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	oldClient := customerIOHTTPClient
	customerIOHTTPClient = &http.Client{Transport: tr}
	t.Cleanup(func() {
		customerIOHTTPClient = oldClient
		tr.CloseIdleConnections()
		ts.Close()
	})
}

func testJWT(exp time.Time) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":` + strconv.FormatInt(exp.Unix(), 10) + `}`))
	return header + "." + payload + ".sig"
}
