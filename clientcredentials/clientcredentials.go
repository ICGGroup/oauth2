// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package clientcredentials implements the OAuth2.0 "client credentials" token flow,
// also known as the "two-legged OAuth 2.0".
//
// This should be used when the client is acting on its own behalf or when the client
// is the resource owner. It may also be used when requesting access to protected
// resources based on an authorization previously arranged with the authorization
// server.
//
// See https://tools.ietf.org/html/rfc6749#section-4.4
package clientcredentials // import "github.com/jfcote87/oauth2/clientcredentials"

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/jfcote87/ctxclient"
	"github.com/jfcote87/oauth2"
)

// Config describes a 2-legged OAuth2 flow, with both the
// client application information and the server's endpoint URLs.
type Config struct {
	// ClientID is the application's ID.
	ClientID string

	// ClientSecret is the application's secret.
	ClientSecret string

	// TokenURL is the resource server's token endpoint
	// URL. This is a constant specific to each server.
	TokenURL string

	// Scope specifies optional requested permissions.
	Scopes []string

	// EndpointParams specifies additional parameters for requests to the token endpoint.
	EndpointParams url.Values

	// ExpiryDelta determines how man seconds sooner a token should
	// expire than the delivered expiration time.
	ExpiryDelta int64

	// HTTPClientFunc specifies a function specifiying
	// the *http.Client used on Token calls to the oauth2
	// server.  If nil,
	HTTPClientFunc ctxclient.Func
}

// Client returns an HTTP client using the provided token.
// The token will auto-refresh as necessary. The underlying
// HTTP transport by requests contexts.
// The returned client and its Transport should not be modified.
func (c *Config) Client(t *oauth2.Token) (*http.Client, error) {
	return oauth2.Client(c.TokenSource(t), nil), nil
}

// TokenSource returns a TokenSource that returns t until t expires,
// automatically refreshing it as necessary using the provided context and the
// client ID and client secret.
//
// Most users will use Config.Client instead.
func (c *Config) TokenSource(t *oauth2.Token) oauth2.TokenSource {
	return oauth2.ReuseTokenSource(t, c)
}

// Token refreshes the token by using a new client credentials request.
// tokens received this way do not include a refresh token.
// Do not call this function directly unless creating own
// caching tokensource.  Use the tokensource create by
// Config.TokenSource.
func (c *Config) Token(ctx context.Context) (*oauth2.Token, error) {
	v := url.Values{
		"grant_type": {"client_credentials"},
	}
	if len(c.Scopes) > 0 {
		v["scope"] = []string{strings.Join(c.Scopes, " ")}
	}
	for k, p := range c.EndpointParams {
		if _, ok := v[k]; ok {
			return nil, fmt.Errorf("oauth2: cannot overwrite parameter %q", k)
		}
		v[k] = p
	}
	return oauth2.RetrieveToken(ctx, c.HTTPClientFunc, c.ClientID, c.ClientSecret, c.TokenURL, v, c.ExpiryDelta)

}
