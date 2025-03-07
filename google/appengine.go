// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package google

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ICGGroup/oauth2"
)

// appengineFlex is set at init time by appengineflex_hook.go. If true, we are on App Engine Flex.
var appengineFlex bool

// Set at init time by appengine_hook.go. If nil, we're not on App Engine.
var appengineTokenFunc func(c context.Context, scopes ...string) (token string, expiry time.Time, err error)

// Set at init time by appengine_hook.go. If nil, we're not on App Engine.
var appengineAppIDFunc func(c context.Context) string

// aeTokens helps the fetched tokens to be reused until their expiration.
var (
	aeTokensMu sync.Mutex
	aeTokens   = make(map[string]*tokenLock) // key is space-separated scopes
)

type tokenLock struct {
	mu sync.Mutex // guards t; held while fetching or updating t
	t  *oauth2.Token
}

func appEngineToken(ctx context.Context, key string, scopes []string) (*oauth2.Token, error) {
	aeTokensMu.Lock()
	tok, ok := aeTokens[key]
	if !ok {
		tok = &tokenLock{}
		aeTokens[key] = tok
	}
	aeTokensMu.Unlock()

	tok.mu.Lock()
	defer tok.mu.Unlock()
	if tok.t.Valid() {
		return tok.t, nil
	}
	access, exp, err := appengineTokenFunc(ctx, scopes...)
	if err != nil {
		return nil, err
	}
	tok.t = &oauth2.Token{
		AccessToken: access,
		Expiry:      exp,
	}
	return tok.t, nil
}

// AppEngineTokenSource returns a token source that fetches tokens
// issued to the current App Engine application's service account.
// If you are implementing a 3-legged OAuth 2.0 flow on App Engine
// that involves user accounts, see oauth2.Config instead.
func AppEngineTokenSource(scope ...string) oauth2.TokenSource {
	if appengineTokenFunc == nil {
		panic("google: AppEngineTokenSource can only be used on App Engine.")
	}
	scopes := append([]string{}, scope...)
	sort.Strings(scopes)
	return &appEngineTokenSource{
		scopes: scopes,
		key:    strings.Join(scopes, " "),
	}
}

type appEngineTokenSource struct {
	scopes []string
	key    string // to aeTokens map; space-separated scopes
}

func (ts *appEngineTokenSource) Token(ctx context.Context) (*oauth2.Token, error) {
	return appEngineToken(ctx, ts.key, ts.scopes)
}
