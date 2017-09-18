// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oauth2

// build +go1.7

import (
	"errors"
	"net/http"
	"net/url"
	"sync"

	"github.com/jfcote87/oauth2/internal"
	"golang.org/x/net/context"
)

// CtxTokenSource replaces TokenSource.  This *http.Client used in
// Token(context.Context) is determined by the CtxTokenSource.
type CtxTokenSource interface {
	// Token returns a token or an error.
	// Token must be safe for concurrent use by multiple goroutines.
	// The returned Token must not be modified.
	Token(context.Context) (*Token, error)
}

type codeGrantRefresher struct {
	conf         *Config
	refreshToken string
}

// RefreshToken retrieves a Token using the Config's HTTPClient.  It may be used
// to construct caching TokenSources.
func (c *Config) RefreshToken(ctx context.Context, refreshToken string) (*Token, error) {
	return c.retrieveToken(ctx, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	})
}

func (c *Config) retrieveToken(ctx context.Context, v url.Values) (*Token, error) {
	tk, err := internal.RetrieveToken(ctx, c.HTTPClient,
		c.ClientID, c.ClientSecret, c.Endpoint.TokenURL, v)
	return tokenFromInternal(tk), err
}

func (c *Config) AccessTokenRequest(ctx context.Context, code string) (*Token, error) {
	return c.retrieveToken(ctx, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": internal.CondVal(c.RedirectURL),
	})
}

func (c *Config) AccessTokenRequestProofKey(ctx context.Context, code, verifier string) (*Token, error) {
	return c.retrieveToken(ctx, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  internal.CondVal(c.RedirectURL),
		"code_verifier": {verifier},
	})
}

// ctxReuseTokenSource is a CtxTokenSource that holds a single token in memory
// and validates its expiry before each call to retrieve it with
// Token. If it's expired, it will be auto-refreshed using the
// new TokenSource.
type cachedSource struct {
	new CtxTokenSource // called when t is expired.

	mu sync.Mutex // guards t
	t  *Token
}

// WARNING: Token is not safe for concurrent access, as it
// updates the tokenRefresher's refreshToken field.
// Within this package, it is used by reuseTokenSource which
// synchronizes calls to this method with its own mutex.
func (cg *codeGrantRefresher) Token(ctx context.Context) (*Token, error) {
	if cg.refreshToken == "" {
		return nil, errors.New("oauth2: token expired and refresh token is not set")
	}
	tk, err := cg.conf.RefreshToken(ctx, cg.refreshToken)
	if err == nil && cg.refreshToken != tk.RefreshToken {
		cg.refreshToken = tk.RefreshToken
	}
	return tk, err
}

// ResuseCtxTokenSource returns a CtxTokenSource which repeatedly returns
// the same token as long as it's valid, starting with t.
// When its cached token is invalid, a new token is obtained from src.
//
// ResuseCtxTokenSource is typically used to reuse tokens from a cache
// (such as a file on disk) between runs of a program, rather than
// obtaining new tokens unnecessarily.
//
// The initial token t may be nil, in which case the TokenSource is
// wrapped in a caching version if it isn't one already. This also
// means it's always safe to wrap ReuseTokenSource around any other
// TokenSource without adverse effects.
func ResuseCtxTokenSource(t *Token, src CtxTokenSource) CtxTokenSource {
	// Don't wrap a reuseTokenSource in itself. That would work,
	// but cause an unnecessary number of mutex operations.
	// Just build the equivalent one.
	if rt, ok := src.(*cachedSource); ok {
		if t == nil {
			// Just use it directly.
			return rt
		}
		src = rt.new
	}
	return &cachedSource{
		t:   t,
		new: src,
	}
}

// Token returns the current token if it's still valid, else will
// refresh the current token and return the new one.
func (s *cachedSource) Token(ctx context.Context) (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.t.Valid() {
		return s.t, nil
	}
	t, err := s.new.Token(ctx)
	if err != nil {
		return nil, err
	}
	s.t = t
	return t, nil
}

// CtxTokenSource returns a CtxTokenSource that returns t until t expires,
// automatically refreshing it as necessary.
//
// Most users will use Config.CtxClient instead.
func (c *Config) CtxTokenSource(t *Token) CtxTokenSource {
	var refreshToken string
	if t != nil {
		refreshToken = t.RefreshToken
	}
	return ResuseCtxTokenSource(t, &codeGrantRefresher{
		conf:         c,
		refreshToken: refreshToken,
	})
}

// CtxClient returns an HTTP client using the provided token.
// The token will auto-refresh as necessary. The underlying
// Client returns an HTTP client using the provided token.
// HTTP transport will be obtained using Config.HTTPClient.
// The returned client and its Transport should not be modified.
func (c *Config) CtxClient(t *Token) *http.Client {
	return NewCtxClient(c.HTTPClient, c.CtxTokenSource(t))
}

var errNilClient = errors.New("oauth2: nil client specified")

// NewCtxClient creates an *http.Client from an *http.Client and
// CtxTokenSource.
func NewCtxClient(client *http.Client, ts CtxTokenSource) *http.Client {
	if client == nil {
		return &http.Client{
			Transport: &internal.ErrorTransport{Err: errNilClient},
		}
	}
	return &http.Client{
		Transport: &CtxTransport{
			Base:   client.Transport,
			Source: ts,
		},
	}
}

// CtxTransport is an http.RoundTripper that makes OAuth 2.0 HTTP requests,
// wrapping a base RoundTripper and adding an Authorization header
// with a token from the supplied Sources.
//
// Transport is a low-level mechanism. Most code will use the
// higher-level Config.Client method instead.
type CtxTransport struct {
	// Source supplies the token to add to outgoing requests'
	// Authorization headers.
	Source CtxTokenSource

	// Base is the base RoundTripper used to make HTTP requests.
	// If nil, http.DefaultTransport is used.
	Base http.RoundTripper
}

// RoundTrip authorizes and authenticates the request with an
// access token. If no token exists or token is expired,
// it fetches a new token passing along the request's context.
func (t *CtxTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Source == nil {
		return nil, errors.New("oauth2: Transport's Source is nil")
	}
	tk, err := t.Source.Token(req.Context())
	if err != nil {
		return nil, err
	}

	req2 := cloneRequest(req) // per RoundTripper contract
	tk.SetAuthHeader(req2)

	if t.Base == nil {
		return http.DefaultTransport.RoundTrip(req2)
	}
	return t.Base.RoundTrip(req2)
}
