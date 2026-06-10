package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/denoland/clawpatrol/pluginsdk"
)

const (
	pluginName             = "customerio"
	pluginVersion          = "0.1.0"
	phCustomerIOAccess     = "PH_customerio_access"
	customerIOTokenTimeout = 30 * time.Second
	customerIOBodyLimit    = 64 << 10
)

type customerIOConfigInput struct {
	Region   string `json:"region"`
	ReadOnly *bool  `json:"read_only"`
}

type customerIOConfig struct {
	Region   string `json:"region"`
	ReadOnly bool   `json:"read_only"`
	BaseURL  string `json:"base_url"`
}

type customerIOTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

type cachedCustomerIOToken struct {
	accessToken string
	expiresAt   time.Time
}

type customerIOTokenCache struct {
	mu     sync.Mutex
	tokens map[string]cachedCustomerIOToken
}

var (
	customerIOTokens     = &customerIOTokenCache{tokens: map[string]cachedCustomerIOToken{}}
	customerIOHTTPClient = http.DefaultClient
)

func main() {
	pluginsdk.Run(&pluginsdk.Plugin{
		Name:        pluginName,
		Version:     pluginVersion,
		Credentials: []pluginsdk.CredentialDef{customerIOServiceAccountDef()},
	})
}

func customerIOServiceAccountDef() pluginsdk.CredentialDef {
	return pluginsdk.CredentialDef{
		TypeName:       "customerio_service_account",
		Disambiguators: []string{"placeholder"},
		HTTPInject:     true,
		Schema: pluginsdk.Schema{Fields: []pluginsdk.SchemaField{
			{Name: "region", TypeString: "string"},
			{Name: "read_only", TypeString: "bool"},
		}},
		Build: func(req pluginsdk.BuildRequest) (any, error) {
			cfg, err := buildCustomerIOConfig(req.ConfigJSON)
			if err != nil {
				return nil, err
			}
			return pluginsdk.CredentialBuildResult{
				Canonical: cfg,
				Metadata: pluginsdk.CredentialMetadata{
					Disambiguators: []string{"placeholder"},
					SecretSlots: []pluginsdk.SecretSlot{{
						Label:       "Customer.io Service Account token",
						Description: "sa_live_… service account token. Stored on the gateway and exchanged for short-lived JWTs.",
					}},
					EnvVars:    customerIOEnvVars(cfg),
					HTTPInject: true,
				},
			}, nil
		},
		InjectHTTP: injectCustomerIOHTTP,
	}
}

func buildCustomerIOConfig(raw []byte) (customerIOConfig, error) {
	var in customerIOConfigInput
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &in); err != nil {
			return customerIOConfig{}, err
		}
	}
	region := strings.ToLower(strings.TrimSpace(in.Region))
	if region == "" {
		region = "us"
	}
	if region != "us" && region != "eu" {
		return customerIOConfig{}, fmt.Errorf(`region must be "us" or "eu"`)
	}
	readOnly := true
	if in.ReadOnly != nil {
		readOnly = *in.ReadOnly
	}
	return customerIOConfig{
		Region:   region,
		ReadOnly: readOnly,
		BaseURL:  customerIOBaseURL(region),
	}, nil
}

func customerIOBaseURL(region string) string {
	if region == "eu" {
		return "https://eu.fly.customer.io"
	}
	return "https://us.fly.customer.io"
}

func decodeCustomerIOCanonicalConfig(raw []byte) (customerIOConfig, error) {
	var cfg customerIOConfig
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return customerIOConfig{}, err
		}
	}
	cfg.Region = strings.ToLower(strings.TrimSpace(cfg.Region))
	if cfg.Region == "" {
		cfg.Region = "us"
	}
	if cfg.Region != "us" && cfg.Region != "eu" {
		return customerIOConfig{}, fmt.Errorf(`region must be "us" or "eu"`)
	}
	if strings.TrimSpace(cfg.BaseURL) == "" {
		cfg.BaseURL = customerIOBaseURL(cfg.Region)
	}
	cfg.BaseURL = strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	return cfg, nil
}

func validateCustomerIOBaseURL(baseURL, region string) error {
	u, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("parse Customer.io base URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("Customer.io base URL must use https")
	}
	expectedHost := "us.fly.customer.io"
	if region == "eu" {
		expectedHost = "eu.fly.customer.io"
	}
	if !strings.EqualFold(u.Host, expectedHost) || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("Customer.io base URL must be https://%s", expectedHost)
	}
	return nil
}

func customerIOEnvVars(cfg customerIOConfig) []pluginsdk.EnvVar {
	return []pluginsdk.EnvVar{
		{Name: "CUSTOMERIO_TOKEN", Value: phCustomerIOAccess, Description: "Customer.io access-token placeholder for customer-io-pp-cli"},
		{Name: "CUSTOMER_IO_BASE_URL", Value: cfg.BaseURL, Description: "Customer.io API base URL for customer-io-pp-cli"},
		{Name: "CUSTOMERIO_REGION", Value: cfg.Region, Description: "Customer.io region"},
		{Name: "CIO_ACCESS_TOKEN", Value: phCustomerIOAccess, Description: "Customer.io access-token placeholder for the official cio CLI"},
		{Name: "CIO_TOKEN", Value: phCustomerIOAccess, Description: "Customer.io token placeholder; CIO_ACCESS_TOKEN makes official cio skip local token exchange"},
		{Name: "CIO_API_URL", Value: cfg.BaseURL, Description: "Customer.io API base URL for the official cio CLI"},
		{Name: "CIO_REGION", Value: cfg.Region, Description: "Customer.io region for the official cio CLI"},
		{Name: "CIO_AGENT", Value: "1", Description: "Mark official cio traffic as agent-originated"},
	}
}

func injectCustomerIOHTTP(ctx context.Context, req pluginsdk.HTTPInjectRequest) (*pluginsdk.HTTPInjectResponse, error) {
	cfg, err := decodeCustomerIOCanonicalConfig(req.CredentialCanonicalConfig)
	if err != nil {
		return nil, err
	}
	serviceToken := strings.TrimSpace(string(req.CredentialSecret))
	if !looksLikeCustomerIOServiceToken(serviceToken) {
		return nil, fmt.Errorf("Customer.io service account token must start with sa_live_, sa_sandbox_, or sa_test_")
	}
	accessToken, err := customerIOTokens.accessToken(ctx, cfg, serviceToken)
	if err != nil {
		return nil, err
	}
	return &pluginsdk.HTTPInjectResponse{
		Headers: []pluginsdk.HeaderMutation{{
			Op:     pluginsdk.HeaderSet,
			Name:   "Authorization",
			Values: []string{"Bearer " + accessToken},
		}},
		Redactions: []string{accessToken},
	}, nil
}

func looksLikeCustomerIOServiceToken(tok string) bool {
	return strings.HasPrefix(tok, "sa_live_") || strings.HasPrefix(tok, "sa_sandbox_") || strings.HasPrefix(tok, "sa_test_")
}

func (c *customerIOTokenCache) accessToken(ctx context.Context, cfg customerIOConfig, serviceToken string) (string, error) {
	key := customerIOCacheKey(cfg, serviceToken)
	now := time.Now()
	c.mu.Lock()
	if tok, ok := c.tokens[key]; ok && now.Before(tok.expiresAt.Add(-60*time.Second)) {
		c.mu.Unlock()
		return tok.accessToken, nil
	}
	c.mu.Unlock()

	accessToken, expiresAt, err := exchangeCustomerIOServiceToken(ctx, cfg, serviceToken)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	c.tokens[key] = cachedCustomerIOToken{accessToken: accessToken, expiresAt: expiresAt}
	c.mu.Unlock()
	return accessToken, nil
}

func customerIOCacheKey(cfg customerIOConfig, serviceToken string) string {
	h := sha256.Sum256([]byte(serviceToken))
	return cfg.Region + "|" + strings.TrimRight(cfg.BaseURL, "/") + "|" + fmt.Sprint(cfg.ReadOnly) + "|" + hex.EncodeToString(h[:])
}

func exchangeCustomerIOServiceToken(ctx context.Context, cfg customerIOConfig, serviceToken string) (string, time.Time, error) {
	if err := validateCustomerIOBaseURL(cfg.BaseURL, cfg.Region); err != nil {
		return "", time.Time{}, err
	}

	ctx, cancel := context.WithTimeout(ctx, customerIOTokenTimeout)
	defer cancel()

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_secret", serviceToken)
	if cfg.ReadOnly {
		form.Set("scope", "read_only")
	}
	requestURL := strings.TrimRight(cfg.BaseURL, "/") + "/v1/service_accounts/oauth/token"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, err
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", "clawpatrol-customerio/"+pluginVersion)

	resp, err := customerIOHTTPClient.Do(httpReq)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("Customer.io token exchange: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, customerIOBodyLimit))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", time.Time{}, fmt.Errorf("Customer.io token exchange HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var tr customerIOTokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", time.Time{}, fmt.Errorf("decode Customer.io token response: %w", err)
	}
	if strings.TrimSpace(tr.AccessToken) == "" {
		return "", time.Time{}, fmt.Errorf("Customer.io token exchange returned empty access_token")
	}
	expiresAt := customerIOTokenExpiry(tr.AccessToken, tr.ExpiresIn)
	return tr.AccessToken, expiresAt, nil
}

func customerIOTokenExpiry(accessToken string, expiresIn int) time.Time {
	if exp, ok := jwtExpiry(accessToken); ok {
		return exp
	}
	if expiresIn > 0 {
		return time.Now().Add(time.Duration(expiresIn) * time.Second)
	}
	return time.Now().Add(55 * time.Minute)
}

func jwtExpiry(tok string) (time.Time, bool) {
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp <= 0 {
		return time.Time{}, false
	}
	return time.Unix(claims.Exp, 0), true
}
