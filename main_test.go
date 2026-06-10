package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	defer ts.Close()

	cache := &customerIOTokenCache{tokens: map[string]cachedCustomerIOToken{}}
	cfg := customerIOConfig{Region: "eu", ReadOnly: true, BaseURL: ts.URL}
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

func TestCustomerIOInjectHTTPSetsBearerJWT(t *testing.T) {
	jwt := testJWT(time.Now().Add(time.Hour))
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
			http.Error(w, "bad form", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(customerIOTokenResponse{AccessToken: jwt, TokenType: "Bearer", ExpiresIn: 3600})
	}))
	defer ts.Close()

	cfg := customerIOConfig{Region: "eu", ReadOnly: true, BaseURL: ts.URL}
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

func testJWT(exp time.Time) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":` + strconv.FormatInt(exp.Unix(), 10) + `}`))
	return header + "." + payload + ".sig"
}
