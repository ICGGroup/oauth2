// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package jwt implements the OAuth 2.0 JSON Web Token flow, commonly
// known as "two-legged OAuth 2.0".
//
// See: https://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-12
package jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jfcote87/ctxclient"
	"github.com/jfcote87/oauth2"
	"github.com/jfcote87/oauth2/jws"
)

var (
	defaultGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

const (
	defaultTokenExpiration = 3600 //time.Hour
	defaultIatOffset       = 10   //time.Duration(10 * time.Second)
)

// DefaultExpiration returns a new Expiration settings with default values. Use
// this to create an expiration setting and change individual fields.
func DefaultExpiration() *ExpirationSetting {
	return &ExpirationSetting{
		expires:     defaultTokenExpiration,
		expiryDelta: oauth2.DefaultExpiryDelta,
		iatOffset:   defaultIatOffset,
	}
}

// Config is the configuration for using JWT to fetch tokens,
// commonly known as "two-legged OAuth 2.0".
type Config struct {
	// Signer is the func used to sign the JWT header and payload
	Signer jws.Signer

	// Issuer is the OAuth client identifier used when communicating with
	// the configured OAuth provider.
	Issuer string `json:"email,omitempty"`

	// Subject is the optional user to impersonate.
	Subject string `json:"subject,omitempty"`

	// TokenURL is the endpoint required to complete the 2-legged JWT flow.
	TokenURL string `json:"token_url,omitempty"`

	// Audience fills the claimset's aud parameter.  For Google Client API
	// this should be set to the TokenURL value.
	Audience string `json:"audience,omitempty"`

	// Scopes optionally specifies a list of requested permission scopes
	// which will be included as private claims named scopes in the
	// JWT claimset payload.
	Scopes []string `json:"scopes,omitempty"`

	// Leave nil to use default values
	Expiration *ExpirationSetting `json:"expiration,omitempty"`

	// additional options for creating and sending claimset payload
	Options *ConfigOptions `json:"options,omitempty"`

	// HTTPClientFunc (Optional) specifies a function specifiying
	// the *http.Client used on Token calls to the oauth2
	// server.
	HTTPClientFunc ctxclient.Func `json:"-"`
}

// ExpirationSetting determines how a long a token will be valid. Default
// values are:
// Expires: 3600 - time.Hour
// ExpiryDelta: 10
// IatOffset: 10
type ExpirationSetting struct {
	// Expires optionally specifies the number of seconds a token is valid.
	// Defaults to 3600 (1 hour).  Server may return an expiration
	// value less than the requested duration.
	expires int64

	// ExpiryDelta determines how man seconds sooner a token should
	// expire than the delivered expiration time. If zero, defaults
	// to oauth2.DefaultExpiryDelta.
	expiryDelta int64

	// IatOffset is the number of seconds subtracted from the current time to
	// set the iat claim. Used for machines whose time is not perfectly in sync.
	// Google servers and others will not issue a token if the issued at time(iat)
	// is in the future.
	// Defaults to 10
	iatOffset int64
}

// MarshalJSON allows for exporting an ExpirationSetting
func (ex *ExpirationSetting) MarshalJSON() ([]byte, error) {
	m := make(map[string]int64)
	if ex.expires != defaultTokenExpiration {
		m["expires"] = ex.expires
	}
	if ex.expiryDelta != oauth2.DefaultExpiryDelta {
		m["expiryDelta"] = ex.expiryDelta
	}
	if ex.iatOffset != defaultIatOffset {
		m["iatOffset"] = ex.iatOffset
	}
	return json.Marshal(m)
}

// UnmarshalJSON allows ExpirationSetting to be decoded from JSON
func (ex *ExpirationSetting) UnmarshalJSON(b []byte) error {
	m := make(map[string]int64)
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	defaultExp := DefaultExpiration()
	for k, v := range m {
		switch k {
		case "expires":
			defaultExp.expires = v
		case "expiryDelta":
			defaultExp.expiryDelta = v
		case "iatOffset":
			defaultExp.iatOffset = v
		}
	}
	ex.expires, ex.expiryDelta, ex.iatOffset = defaultExp.expires, defaultExp.expiryDelta, defaultExp.iatOffset
	return nil
}

// Duration sets the number of seconds a JWT will be valid.  This overrides the
// default setting of 3600 (1 hour)
func (ex *ExpirationSetting) Duration(numOfSeconds int64) *ExpirationSetting {
	if ex == nil {
		return DefaultExpiration().Duration(numOfSeconds)
	}
	ex.expires = numOfSeconds
	return ex
}

// ExpiryDelta determines how many seconds sooner a token should
// expire before the server's expiration time.  This will override the
// default of oauth2.ExpiryDelta
func (ex *ExpirationSetting) ExpiryDelta(delta int64) *ExpirationSetting {
	if ex == nil {
		return DefaultExpiration().ExpiryDelta(delta)
	}
	ex.expiryDelta = delta
	return ex
}

// IatOffset sets the number of seconds subtracted from the current time
// used for the iat claim. Use for machines whose time is not in sync. Google
// servers and others will not issue a token if the issued at time(iat) is
// in the future.  Overrides the default of 10 seconds
func (ex *ExpirationSetting) IatOffset(numOfSeconds int64) *ExpirationSetting {
	if ex == nil {
		return DefaultExpiration().IatOffset(numOfSeconds)
	}
	ex.iatOffset = numOfSeconds
	return ex
}

// ConfigOptions provide additional (rarely used options for the config)
type ConfigOptions struct {
	// PrivateClaims(Optional) adds additional private claims to add
	// to the request
	PrivateClaims map[string]interface{} `json:"private_claims,omitempty"`

	// FormValues(Optional) adds addional form fields to request body
	FormValues url.Values `json:"form_values,omitempty"`
}

// Values returns the expiration values.  Used for testing
func (ex *ExpirationSetting) Values() (int64, int64, int64) {
	if ex == nil {
		ex = DefaultExpiration()
	}
	return ex.expires, ex.expiryDelta, ex.iatOffset
}

// TokenExpiry returns the token expiration offset
func (ex *ExpirationSetting) TokenExpiry() time.Duration {
	if ex == nil {
		ex = DefaultExpiration()
	}
	return time.Duration(ex.expiryDelta) * -time.Second
}

// TokenSource returns a JWT TokenSource using the configuration
// in c and the HTTP client from the provided context.
func (c *Config) TokenSource(t *oauth2.Token) oauth2.TokenSource {
	return oauth2.ReuseTokenSource(t, c)
}

// Client returns an HTTP client wrapping the context's
// HTTP transport and adding Authorization headers with tokens
// obtained from c.
//
// The returned client and its Transport should not be modified.
func (c *Config) Client(t *oauth2.Token) (*http.Client, error) {
	return oauth2.Client(c.TokenSource(t), c.HTTPClientFunc), nil
}

// payload returns the body of a token request
func (c *Config) payload() (url.Values, error) {
	privateClaims := make(map[string]interface{})
	if len(c.Scopes) > 0 {
		privateClaims["scope"] = strings.Join(c.Scopes, " ")
	}

	ex := c.Expiration
	if ex == nil {
		ex = DefaultExpiration()
	}
	iat, exp, err := jws.ExpirationClaims(time.Duration(ex.iatOffset)*time.Second, time.Duration(ex.expires)*time.Second)
	if err != nil {
		return nil, err
	}

	formValues := url.Values{
		"grant_type": {defaultGrantType},
	}

	claimSet := &jws.ClaimSet{
		Issuer:        c.Issuer,
		Audience:      c.Audience,
		Subject:       c.Subject,
		IssuedAt:      iat,
		ExpiresAt:     exp,
		PrivateClaims: privateClaims,
	}

	// check options for custom claim set handling
	if c.Options != nil {
		for k, v := range c.Options.PrivateClaims {
			privateClaims[k] = v
		}
		for k, v := range c.Options.FormValues {
			formValues[k] = v
		}
	}

	tokenString, err := claimSet.JWT(c.Signer)
	if err != nil {
		return nil, err
	}
	formValues.Set("assertion", tokenString)

	return formValues, nil
}

// Token performs a signed JWT request to obtain a new token.
func (c *Config) Token(ctx context.Context) (*oauth2.Token, error) {
	payload, err := c.payload()
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTPClientFunc.PostForm(ctx, c.TokenURL, payload)
	if err != nil {
		return nil, fmt.Errorf("oauth2/jwt: cannot fetch token: %v", err)
	}
	defer resp.Body.Close()
	raw := make(map[string]interface{})
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&raw); err != nil {
		return nil, fmt.Errorf("oauth2/jwt: unable to decode token: %v", err)
	}

	token := &oauth2.Token{}
	for k, v := range raw {
		switch val := v.(type) {
		case string:
			switch k {
			case "access_token":
				token.AccessToken = val
			case "token_type":
				token.TokenType = val
			case "id_token":
				claimSet, err := jws.DecodePayload(val)
				if err != nil {
					return nil, fmt.Errorf("oauth2/jwt: error decoding JWT token: %v", err)
				}
				// always use idToken time
				token.Expiry = time.Unix(claimSet.ExpiresAt, 0).Add(c.Expiration.TokenExpiry())
			case "expires_in":
				return nil, fmt.Errorf("oauth2/jwt: expires_in must be a number not a string")
			}
		default:
			switch k {
			case "expires_in":
				expiresIn, ok := val.(float64)
				if !ok {
					return nil, fmt.Errorf("oauth2/jwt: expires_in must be a number")
				}
				if token.Expiry.IsZero() { // do not override idToken time
					token.Expiry = time.Now().Add((time.Duration(expiresIn) * time.Second) - c.Expiration.TokenExpiry())
				}

			case "access_token", "token_type", "id_token":
				return nil, fmt.Errorf("oauth2/jwt: %s must be a string", k)
			}
		}
	}
	return token.WithExtra(raw), nil
}
