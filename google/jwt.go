// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package google

import (
	"context"
	"fmt"
	"time"

	"github.com/ICGGroup/oauth2"
	"github.com/ICGGroup/oauth2/jws"
)

// JWTAccessTokenSourceFromJSON uses a Google Developers service account JSON
// key file to read the credentials that authorize and authenticate the
// requests, and returns a TokenSource that does not use any OAuth2 flow but
// instead creates a JWT and sends that as the access token.
// The audience is typically a URL that specifies the scope of the credentials.
//
// Note that this is not a standard OAuth flow, but rather an
// optimization supported by a few Google services.
// Unless you know otherwise, you should use JWTConfigFromJSON instead.
func JWTAccessTokenSourceFromJSON(jsonKey []byte, audience string) (oauth2.TokenSource, error) {
	cfg, err := JWTConfigFromJSON(jsonKey)
	if err != nil {
		return nil, fmt.Errorf("google: could not parse JSON key: %v", err)
	}
	ts := &jwtAccessTokenSource{
		email:    cfg.Issuer,
		audience: audience,
		signer:   cfg.Signer,
	}
	tok, err := ts.Token(context.Background())
	if err != nil {
		return nil, err
	}
	return oauth2.ReuseTokenSource(tok, ts), nil
}

type jwtAccessTokenSource struct {
	email, audience string
	signer          jws.Signer
}

func (ts *jwtAccessTokenSource) Token(ctx context.Context) (*oauth2.Token, error) {
	iat := time.Now()
	exp := iat.Add(time.Hour)
	cs := &jws.ClaimSet{
		Issuer:    ts.email,
		Subject:   ts.email,
		Audience:  ts.audience,
		IssuedAt:  iat.Unix(),
		ExpiresAt: exp.Unix(),
	}
	cs.JWT(ts.signer)
	msg, err := cs.JWT(ts.signer)
	if err != nil {
		return nil, fmt.Errorf("google: could not encode JWT: %v", err)
	}
	return &oauth2.Token{AccessToken: msg, TokenType: "Bearer", Expiry: exp}, nil
}
