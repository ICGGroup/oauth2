// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package jwt_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jfcote87/oauth2"
	"github.com/jfcote87/oauth2/jws"
	"github.com/jfcote87/oauth2/jwt"
)

var dummyPrivateKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAx4fm7dngEmOULNmAs1IGZ9Apfzh+BkaQ1dzkmbUgpcoghucE
DZRnAGd2aPyB6skGMXUytWQvNYav0WTR00wFtX1ohWTfv68HGXJ8QXCpyoSKSSFY
fuP9X36wBSkSX9J5DVgiuzD5VBdzUISSmapjKm+DcbRALjz6OUIPEWi1Tjl6p5RK
1w41qdbmt7E5/kGhKLDuT7+M83g4VWhgIvaAXtnhklDAggilPPa8ZJ1IFe31lNlr
k4DRk38nc6sEutdf3RL7QoH7FBusI7uXV03DC6dwN1kP4GE7bjJhcRb/7jYt7CQ9
/E9Exz3c0yAp0yrTg0Fwh+qxfH9dKwN52S7SBwIDAQABAoIBAQCaCs26K07WY5Jt
3a2Cw3y2gPrIgTCqX6hJs7O5ByEhXZ8nBwsWANBUe4vrGaajQHdLj5OKfsIDrOvn
2NI1MqflqeAbu/kR32q3tq8/Rl+PPiwUsW3E6Pcf1orGMSNCXxeducF2iySySzh3
nSIhCG5uwJDWI7a4+9KiieFgK1pt/Iv30q1SQS8IEntTfXYwANQrfKUVMmVF9aIK
6/WZE2yd5+q3wVVIJ6jsmTzoDCX6QQkkJICIYwCkglmVy5AeTckOVwcXL0jqw5Kf
5/soZJQwLEyBoQq7Kbpa26QHq+CJONetPP8Ssy8MJJXBT+u/bSseMb3Zsr5cr43e
DJOhwsThAoGBAPY6rPKl2NT/K7XfRCGm1sbWjUQyDShscwuWJ5+kD0yudnT/ZEJ1
M3+KS/iOOAoHDdEDi9crRvMl0UfNa8MAcDKHflzxg2jg/QI+fTBjPP5GOX0lkZ9g
z6VePoVoQw2gpPFVNPPTxKfk27tEzbaffvOLGBEih0Kb7HTINkW8rIlzAoGBAM9y
1yr+jvfS1cGFtNU+Gotoihw2eMKtIqR03Yn3n0PK1nVCDKqwdUqCypz4+ml6cxRK
J8+Pfdh7D+ZJd4LEG6Y4QRDLuv5OA700tUoSHxMSNn3q9As4+T3MUyYxWKvTeu3U
f2NWP9ePU0lV8ttk7YlpVRaPQmc1qwooBA/z/8AdAoGAW9x0HWqmRICWTBnpjyxx
QGlW9rQ9mHEtUotIaRSJ6K/F3cxSGUEkX1a3FRnp6kPLcckC6NlqdNgNBd6rb2rA
cPl/uSkZP42Als+9YMoFPU/xrrDPbUhu72EDrj3Bllnyb168jKLa4VBOccUvggxr
Dm08I1hgYgdN5huzs7y6GeUCgYEAj+AZJSOJ6o1aXS6rfV3mMRve9bQ9yt8jcKXw
5HhOCEmMtaSKfnOF1Ziih34Sxsb7O2428DiX0mV/YHtBnPsAJidL0SdLWIapBzeg
KHArByIRkwE6IvJvwpGMdaex1PIGhx5i/3VZL9qiq/ElT05PhIb+UXgoWMabCp84
OgxDK20CgYAeaFo8BdQ7FmVX2+EEejF+8xSge6WVLtkaon8bqcn6P0O8lLypoOhd
mJAYH8WU+UAy9pecUnDZj14LAGNVmYcse8HFX71MoshnvCTFEPVo4rZxIAGwMpeJ
5jgQ3slYLpqrGlcbLgUXBUgzEO684Wk/UV9DFPlHALVqCfXQ9dpJPg==
-----END RSA PRIVATE KEY-----`)

func TestJWTFetch_JSONResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"access_token": "90d64460d14870c08c81352a05dedd3465940a7c",
			"scope": "user",
			"token_type": "bearer",
			"expires_in": 3600
		}`))
	}))
	defer ts.Close()

	signer, _ := jws.RS256FromPEM(dummyPrivateKey, "")
	conf := &jwt.Config{
		Issuer:   "aaa@xxx.com",
		Signer:   signer,
		TokenURL: ts.URL,
	}
	tok, err := conf.TokenSource(nil).Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !tok.Valid() {
		log.Printf("%#v", tok)
		t.Errorf("got invalid token: %v", tok)
	}
	if got, want := tok.AccessToken, "90d64460d14870c08c81352a05dedd3465940a7c"; got != want {
		t.Errorf("access token = %q; want %q", got, want)
	}
	if got, want := tok.TokenType, "bearer"; got != want {
		t.Errorf("token type = %q; want %q", got, want)
	}
	if got := tok.Expiry.IsZero(); got {
		t.Errorf("token expiry = %v, want none", got)
	}
	scope := tok.Extra("scope")
	if got, want := scope, "user"; got != want {
		t.Errorf("scope = %q; want %q", got, want)
	}
}

func TestJWTFetch_BadResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"scope": "user", "token_type": "bearer"}`))
	}))
	defer ts.Close()

	signer, _ := jws.RS256FromPEM(dummyPrivateKey, "")
	conf := &jwt.Config{
		Issuer:   "aaa@xxx.com",
		Signer:   signer,
		TokenURL: ts.URL,
	}
	tok, err := conf.TokenSource(nil).Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok == nil {
		t.Fatalf("got nil token; want token")
	}
	if tok.Valid() {
		t.Errorf("got invalid token: %v", tok)
	}
	if got, want := tok.AccessToken, ""; got != want {
		t.Errorf("access token = %q; want %q", got, want)
	}
	if got, want := tok.TokenType, "bearer"; got != want {
		t.Errorf("token type = %q; want %q", got, want)
	}
	scope := tok.Extra("scope")
	if got, want := scope, "user"; got != want {
		t.Errorf("token scope = %q; want %q", got, want)
	}
}

func TestJWTFetch_BadResponseType(t *testing.T) {
	responses := []string{
		`{"access_token":123, "scope": "user", "token_type": "bearer"}`,
		`{"access_token":"123", "scope": "user", "token_type": true}`,
		`{"access_token":"123", "scope": "user", "id_token": "abcdef", "token_type": "bearer"}`,
		`{"access_token":"123", "scope": "user", "token_type": "bearer", "expires_in": "60"}`,
		`{"access_token":"123", "scope": "user", "token_type": "mac", "expires_in": {}}`,
	}
	counter := 0

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(responses[counter]))
		//`{"access_token":123, "scope": "user", "token_type": "bearer"}`))
	}))
	defer ts.Close()
	signer, _ := jws.RS256FromPEM(dummyPrivateKey, "")
	conf := &jwt.Config{
		Issuer:   "aaa@xxx.com",
		Signer:   signer,
		TokenURL: ts.URL,
	}
	for counter = 0; counter < len(responses); counter++ {
		_, err := conf.TokenSource(nil).Token(context.Background())
		if err == nil {
			t.Error("got a token; expected error")
		}
	}
}

func TestJWTFetch_Assertion(t *testing.T) {
	var assertion string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		assertion = r.Form.Get("assertion")

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"access_token": "90d64460d14870c08c81352a05dedd3465940a7c",
			"scope": "user",
			"token_type": "bearer",
			"expires_in": 3600
		}`))
	}))
	defer ts.Close()

	signer, _ := jws.RS256FromPEM(dummyPrivateKey, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	conf := &jwt.Config{
		Issuer:   "aaa@xxx.com",
		Signer:   signer,
		TokenURL: ts.URL,
	}

	_, err := conf.TokenSource(nil).Token(context.Background())
	if err != nil {
		t.Fatalf("Failed to fetch token: %v", err)
	}

	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		t.Fatalf("assertion = %q; want 3 parts", assertion)
	}
	gotjson, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("invalid token header; err = %v", err)
	}

	got := make(map[string]interface{})
	if err := json.Unmarshal(gotjson, &got); err != nil {
		t.Errorf("failed to unmarshal json token header = %q; err = %v", gotjson, err)
	}

	want := map[string]interface{}{
		"alg": "RS256",
		"typ": "JWT",
		"kid": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	}
	for k, v := range got {
		if v != want[k] {
			t.Errorf("jwt header claim %s = %q; want %q", k, got, want[k])
		}
	}
}

func TestJWTIDToken_ExpiryDetail(t *testing.T) {
	tm := time.Now().Add(time.Hour)

	payload := &jws.ClaimSet{
		Issuer:    "http://google.com/",
		Audience:  "",
		ExpiresAt: tm.Unix(),
		IssuedAt:  10,
	}
	tm = time.Unix(tm.Unix(), 0)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	encodedClaimSet, err := payload.JWT(jws.RS256(privateKey, ""))
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"123", "scope": "user", "id_token":"%s", "token_type": "bearer"}`, encodedClaimSet)
	}))

	conf := &jwt.Config{
		Issuer:     "aaa@xxx.com",
		Signer:     jws.RS256(privateKey, ""),
		TokenURL:   ts.URL,
		Expiration: jwt.DefaultExpiration().ExpiryDelta(60),
		// &jwt.ExpirationSetting{
		//	ExpiryDelta: 60,
		//},
	}
	tok, err := conf.TokenSource(nil).Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if tm.Sub(tok.Expiry) != time.Minute {
		t.Errorf("token expiry = %v; want %v", tok.Expiry, tm.Add(-time.Minute))
	}
}

func TestConfigOptions(t *testing.T) {
	tm := time.Now().Add(time.Hour)

	payload := &jws.ClaimSet{
		Issuer:    "http://google.com/",
		Audience:  "",
		ExpiresAt: tm.Unix(),
		IssuedAt:  10,
	}
	tm = time.Unix(tm.Unix(), 0)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	encodedClaimSet, err := payload.JWT(jws.RS256(privateKey, ""))
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("extra") != "value" {
			t.Errorf("expected extra = value; got %s", r.Form.Get("extra"))
		}
		if cl, err := jws.DecodePayload(r.Form.Get("assertion")); err != nil {
			t.Errorf("expected private claim map[pv:pval scope:s1 s2]; got %v", err)

		} else if cl.PrivateClaims == nil || cl.PrivateClaims["pc"] != "pval" || cl.PrivateClaims["scope"] != "s1 s2" {
			t.Errorf("expected private claim map[pv:pval scope:s1 s2]; got %v", cl.PrivateClaims)
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"123", "scope": "user", "id_token":"%s", "token_type": "bearer"}`, encodedClaimSet)
	}))

	conf := &jwt.Config{
		Issuer:     "aaa@xxx.com",
		Signer:     jws.RS256(privateKey, ""),
		TokenURL:   ts.URL,
		Expiration: jwt.DefaultExpiration().ExpiryDelta(60),
		//&jwt.ExpirationSetting{
		//	ExpiryDelta: 60,
		//},
		Scopes: []string{"s1", "s2"},
		Options: &jwt.ConfigOptions{
			PrivateClaims: map[string]interface{}{
				"pc": "pval",
			},
			FormValues: url.Values{
				"extra": {"value"},
			},
		},
	}
	tok, err := conf.TokenSource(nil).Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if tm.Sub(tok.Expiry) != time.Minute {
		t.Errorf("token expiry = %v; want %v", tok.Expiry, tm.Add(-time.Minute))
	}
}

func TestServiceAccount(t *testing.T) {
	cfg := jwt.ServiceAccount{
		Email:        "abc@example.com",
		PrivateKey:   []byte("bad key"),
		PrivateKeyID: "KEY ID",
		Scopes:       []string{"scope1", "scope2"},
		TokenURL:     "https://www.example.com/token",
		Expires:      30 * time.Minute,
	}
	newcfg, err := cfg.Config()
	if err == nil {
		t.Errorf("ServiceAccount expected invalid key; got success")
		return
	}
	cfg.PrivateKey = dummyPrivateKey
	if newcfg, err = cfg.Config(); err != nil {
		t.Errorf("ServiceAccount.Config() expected success; got %v", err)
		return
	}
	exp, _, iat := newcfg.Expiration.Values()
	if newcfg.Expiration == nil || exp != int64(cfg.Expires/time.Second) || iat != 10 {
		t.Errorf("ServiceAccount.Config expected &jwt.ExpirationSetting{Expires:1800000000000, ExpiryDelta:0, IatOffset:10000000000}; got %#v", newcfg.Expiration)
	}
}

func TestExpirationSettings(t *testing.T) {
	var expPtr *jwt.ExpirationSetting
	if expires, delta, iatOff := expPtr.Values(); expires != 3600 || delta != oauth2.DefaultExpiryDelta || iatOff != 10 {
		t.Errorf("nil ExpirationSettings expected default of %d, %d, %d; got %d, %d, %d",
			time.Hour, oauth2.DefaultExpiryDelta, 10*time.Second, expires, delta, iatOff)
	}
	if expires, delta, iatOff := expPtr.Duration(60).Values(); expires != 60 || delta != oauth2.DefaultExpiryDelta || iatOff != 10 {
		t.Errorf("ExpirationSettings Duration expected %d, %d, %d; got %d, %d, %d",
			60, oauth2.DefaultExpiryDelta, 10, expires, delta, iatOff)
	}
	if expires, delta, iatOff := expPtr.ExpiryDelta(5).Values(); expires != 3600 || delta != 5 || iatOff != 10 {
		t.Errorf("ExpirationSettings ExpiryDelta expected %d, %d, %d; got %d, %d, %d",
			3600, 5, 10, expires, delta, iatOff)
	}
	if expires, delta, iatOff := expPtr.IatOffset(60).Values(); expires != 3600 || delta != oauth2.DefaultExpiryDelta || iatOff != 60 {
		t.Errorf("ExpirationSettings IatOffset expected %d, %d, %d; got %d, %d, %d",
			3600, oauth2.DefaultExpiryDelta, 60, expires, delta, iatOff)
	}

	expPtr = jwt.DefaultExpiration().Duration(60).ExpiryDelta(5).IatOffset(1)
	b, err := json.Marshal(expPtr)
	if err != nil {
		t.Errorf("ExpirationSetting marshal: %v", err)
		return
	}
	expPtr = nil
	if err = json.Unmarshal(b, &expPtr); err != nil {
		t.Errorf("ExpirationSetting unmarshal: %v", err)
		return
	}
	if expires, delta, iatOff := expPtr.Values(); expires != 60 || delta != 5 || iatOff != 1 {
		t.Errorf("Marshal/Unmarshal ExpirationSettings expected %d, %d, %d; got %d, %d, %d",
			60, 5, 1, expires, delta, iatOff)
	}
	b = []byte(`{"expiryDelta": 20}`)
	expPtr = nil
	if err = json.Unmarshal(b, &expPtr); err != nil {
		t.Errorf("ExpirationSetting unmarshal: %v", err)
		return
	}
	if expires, delta, iatOff := expPtr.Values(); expires != 3600 || delta != 20 || iatOff != 10 {
		t.Errorf("Marshal/Unmarshal ExpirationSettings expiryDelta expected %d, %d, %d; got %d, %d, %d",
			3600, 20, 10, expires, delta, iatOff)
	}

}
