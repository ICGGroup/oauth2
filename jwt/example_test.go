// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package jwt_test

import (
	"context"
	"errors"
	"log"
	"sync"

	"github.com/jfcote87/oauth2"
	"github.com/jfcote87/oauth2/jws"
	"github.com/jfcote87/oauth2/jwt"
)

func ExampleConfig() {
	// The contents of your RSA private key or your PEM file
	// that contains a private key.
	// If you have a p12 file instead, you
	// can use `openssl` to export the private key into a pem file.
	//
	//    $ openssl pkcs12 -in key.p12 -out key.pem -nodes
	//
	// It only supports PEM containers with no passphrase.
	signer, err := jws.RS256FromPEM([]byte("-----BEGIN RSA PRIVATE KEY-----..."), "")
	if err != nil {
		log.Fatalf("Invalid key: %v", err)
	}
	conf := &jwt.Config{
		Issuer: "xxx@developer.com",

		Signer:   signer,
		Subject:  "user@example.com",
		TokenURL: "https://provider.com/o/oauth2/token",
	}
	// Initiate an http.Client, the following GET request will be
	// authorized and authenticated on the behalf of user@example.com.

	client, _ := conf.Client(nil)
	client.Get("...")
}

func ExampleConfig_Options() {
	// The contents of your RSA private key or your PEM file
	// that contains a private key.
	// If you have a p12 file instead, you
	// can use `openssl` to export the private key into a pem file.
	//
	//    $ openssl pkcs12 -in key.p12 -out key.pem -nodes
	//
	// It only supports PEM containers with no passphrase.
	signer, err := jws.RS256FromPEM([]byte("-----BEGIN RSA PRIVATE KEY-----..."), "")
	if err != nil {
		log.Fatalf("Invalid key: %v", err)
	}
	conf := &jwt.Config{
		Issuer: "xxx@developer.com",

		Signer:   signer,
		Subject:  "user@example.com",
		TokenURL: "https://provider.com/o/oauth2/token",
		// set token duration to 30 minutes and iat to 20 seconds.  ExpiryDelta remains
		// oauth2.DefaultExpiryDelta
		Options: jwt.DefaultCfgOptions().SetExpiresIn(1800).SetIatOffset(20),
	}
	// Initiate an http.Client, the following GET request will be
	// authorized and authenticated on the behalf of user@example.com.
	client, _ := conf.Client(nil)
	client.Get("...")
}

type userEmailCtx struct{}

var UserEmailKey userEmailCtx

func ExampleConfig_TokenSource() {
	signer, err := jws.RS256FromPEM([]byte("-----BEGIN RSA PRIVATE KEY-----..."), "")
	if err != nil {
		log.Fatalf("Invalid key: %v", err)
	}
	conf := &jwt.Config{
		Issuer:   "xxx@developer.com",
		Signer:   signer,
		TokenURL: "https://provider.com/o/oauth2/token",
		Options:  jwt.DefaultCfgOptions().SetExpiryDelta(20),
	}

	ts := NewCustomCachingTokenSource(conf)
	client := oauth2.Client(ts, nil)
	client.Get("...")
}

func NewCustomCachingTokenSource(cfg *jwt.Config) *CustomCachingTokenSource {
	return &CustomCachingTokenSource{
		refresher: cfg,
		tokenMap:  make(map[string]*oauth2.Token),
	}
}

type CustomCachingTokenSource struct {
	refresher *jwt.Config
	mu        sync.Mutex               // guards t
	tokenMap  map[string]*oauth2.Token // token cache
}

func (cts *CustomCachingTokenSource) Token(ctx context.Context) (*oauth2.Token, error) {
	email, _ := ctx.Value(UserEmailKey).(string)
	if email == "" {
		return nil, errors.New("no user email passed in context")
	}
	if token := cts.GetCachedValidToken(ctx, email); token.Valid() {
		return token, nil
	}
	cfgWithEmail := *cts.refresher
	cfgWithEmail.Subject = email
	newToken, err := (&cfgWithEmail).Token(ctx)
	if err != nil {
		return nil, err
	}
	cts.Save(email, newToken)
	return newToken, nil
}

func (cts *CustomCachingTokenSource) Save(email string, t *oauth2.Token) {
	cts.mu.Lock()
	defer cts.mu.Unlock()
	// could also save to db, memcache, etc.
	cts.tokenMap[email] = t
	return
}

func (cts *CustomCachingTokenSource) GetCachedValidToken(ctx context.Context, email string) *oauth2.Token {
	cts.mu.Lock()
	defer cts.mu.Unlock()
	// could also read from db, memcache, etc.
	return cts.tokenMap[email]
}
