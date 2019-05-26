// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/jfcote87/oauth2"
)

type mockTransport struct {
	rt func(req *http.Request) (resp *http.Response, err error)
}

func (t *mockTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	return t.rt(req)
}

func newConf(url string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     "CLIENT_ID",
		ClientSecret: "CLIENT_SECRET",
		RedirectURL:  "REDIRECT_URL",
		Scopes:       []string{"scope1", "scope2"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  url + "/auth",
			TokenURL: url + "/token",
		},
	}
}

func TestAuthCodeURL(t *testing.T) {
	conf := newConf("server")
	url := conf.AuthCodeURL("foo", oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	const want = "server/auth?access_type=offline&client_id=CLIENT_ID&prompt=consent&redirect_uri=REDIRECT_URL&response_type=code&scope=scope1+scope2&state=foo"
	if got := url; got != want {
		t.Errorf("got auth code URL = %q; want %q", got, want)
	}
}

func TestAuthCodeURL_CustomParam(t *testing.T) {
	conf := newConf("server")
	param := oauth2.SetAuthURLParam("foo", "bar")
	url := conf.AuthCodeURL("baz", param)
	const want = "server/auth?client_id=CLIENT_ID&foo=bar&redirect_uri=REDIRECT_URL&response_type=code&scope=scope1+scope2&state=baz"
	if got := url; got != want {
		t.Errorf("got auth code = %q; want %q", got, want)
	}
}

func TestAuthCodeURL_Optional(t *testing.T) {
	conf := &oauth2.Config{
		ClientID: "CLIENT_ID",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "/auth-url",
			TokenURL: "/token-url",
		},
	}
	url := conf.AuthCodeURL("")
	const want = "/auth-url?client_id=CLIENT_ID&response_type=code"
	if got := url; got != want {
		t.Fatalf("got auth code = %q; want %q", got, want)
	}
}

func TestURLUnsafeClientConfig(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Authorization"), "Basic Q0xJRU5UX0lEJTNGJTNGOkNMSUVOVF9TRUNSRVQlM0YlM0Y="; got != want {
			t.Errorf("Authorization header = %q; want %q", got, want)
		}

		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		w.Write([]byte("access_token=90d64460d14870c08c81352a05dedd3465940a7c&scope=user&token_type=bearer"))
	}))
	defer ts.Close()
	conf := newConf(ts.URL)
	conf.ClientID = "CLIENT_ID??"
	conf.ClientSecret = "CLIENT_SECRET??"
	_, err := conf.Exchange(context.Background(), "exchange-code")
	if err != nil {
		t.Error(err)
	}
}

func TestExchangeRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != "/token" {
			t.Errorf("Unexpected exchange request URL, %v is found.", r.URL)
		}
		headerAuth := r.Header.Get("Authorization")
		if headerAuth != "Basic Q0xJRU5UX0lEOkNMSUVOVF9TRUNSRVQ=" {
			t.Errorf("Unexpected authorization header, %v is found.", headerAuth)
		}
		headerContentType := r.Header.Get("Content-Type")
		if headerContentType != "application/x-www-form-urlencoded" {
			t.Errorf("Unexpected Content-Type header, %v is found.", headerContentType)
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed reading request body: %s.", err)
		}
		if string(body) != "code=exchange-code&grant_type=authorization_code&redirect_uri=REDIRECT_URL" {
			t.Errorf("Unexpected exchange payload, %v is found.", string(body))
		}
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		w.Write([]byte("access_token=90d64460d14870c08c81352a05dedd3465940a7c&scope=user&token_type=bearer"))
	}))
	defer ts.Close()
	conf := newConf(ts.URL)
	tok, err := conf.Exchange(context.Background(), "exchange-code")
	if err != nil {
		t.Error(err)
	}
	if !tok.Valid() {
		t.Fatalf("Token invalid. Got: %#v", tok)
	}
	if tok.AccessToken != "90d64460d14870c08c81352a05dedd3465940a7c" {
		t.Errorf("Unexpected access token, %#v.", tok.AccessToken)
	}
	if tok.TokenType != "bearer" {
		t.Errorf("Unexpected token type, %#v.", tok.TokenType)
	}
	scope := tok.Extra("scope")
	if scope != "user" {
		t.Errorf("Unexpected value for scope: %v", scope)
	}
}

func TestExchangeRequest_CustomParam(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != "/token" {
			t.Errorf("Unexpected exchange request URL, %v is found.", r.URL)
		}
		headerAuth := r.Header.Get("Authorization")
		if headerAuth != "Basic Q0xJRU5UX0lEOkNMSUVOVF9TRUNSRVQ=" {
			t.Errorf("Unexpected authorization header, %v is found.", headerAuth)
		}
		headerContentType := r.Header.Get("Content-Type")
		if headerContentType != "application/x-www-form-urlencoded" {
			t.Errorf("Unexpected Content-Type header, %v is found.", headerContentType)
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed reading request body: %s.", err)
		}
		if string(body) != "code=exchange-code&foo=bar&grant_type=authorization_code&redirect_uri=REDIRECT_URL" {
			t.Errorf("Unexpected exchange payload, %v is found.", string(body))
		}
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		w.Write([]byte("access_token=90d64460d14870c08c81352a05dedd3465940a7c&scope=user&token_type=bearer"))
	}))
	defer ts.Close()
	conf := newConf(ts.URL)

	param := oauth2.SetAuthURLParam("foo", "bar")
	tok, err := conf.Exchange(context.Background(), "exchange-code", param)
	if err != nil {
		t.Error(err)
	}
	if !tok.Valid() {
		t.Fatalf("Token invalid. Got: %#v", tok)
	}
	if tok.AccessToken != "90d64460d14870c08c81352a05dedd3465940a7c" {
		t.Errorf("Unexpected access token, %#v.", tok.AccessToken)
	}
	if tok.TokenType != "bearer" {
		t.Errorf("Unexpected token type, %#v.", tok.TokenType)
	}
	scope := tok.Extra("scope")
	if scope != "user" {
		t.Errorf("Unexpected value for scope: %v", scope)
	}
}

func TestExchangeRequest_JSONResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != "/token" {
			t.Errorf("Unexpected exchange request URL, %v is found.", r.URL)
		}
		headerAuth := r.Header.Get("Authorization")
		if headerAuth != "Basic Q0xJRU5UX0lEOkNMSUVOVF9TRUNSRVQ=" {
			t.Errorf("Unexpected authorization header, %v is found.", headerAuth)
		}
		headerContentType := r.Header.Get("Content-Type")
		if headerContentType != "application/x-www-form-urlencoded" {
			t.Errorf("Unexpected Content-Type header, %v is found.", headerContentType)
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed reading request body: %s.", err)
		}
		if string(body) != "code=exchange-code&grant_type=authorization_code&redirect_uri=REDIRECT_URL" {
			t.Errorf("Unexpected exchange payload, %v is found.", string(body))
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token": "90d64460d14870c08c81352a05dedd3465940a7c", "scope": "user", "token_type": "bearer", "expires_in": 86400}`))
	}))
	defer ts.Close()
	conf := newConf(ts.URL)
	tok, err := conf.Exchange(context.Background(), "exchange-code")
	if err != nil {
		t.Error(err)
	}
	if !tok.Valid() {
		t.Fatalf("Token invalid. Got: %#v", tok)
	}
	if tok.AccessToken != "90d64460d14870c08c81352a05dedd3465940a7c" {
		t.Errorf("Unexpected access token, %#v.", tok.AccessToken)
	}
	if tok.TokenType != "bearer" {
		t.Errorf("Unexpected token type, %#v.", tok.TokenType)
	}
	scope := tok.Extra("scope")
	if scope != "user" {
		t.Errorf("Unexpected value for scope: %v", scope)
	}
	expiresIn := tok.Extra("expires_in")
	if fval, ok := expiresIn.(float64); !ok || fval != 86400 {
		t.Errorf("expected 86400 value for expires_in, got %v", expiresIn)
	}
}

func TestExtraValueRetrieval(t *testing.T) {
	values := url.Values{}
	kvmap := map[string]string{
		"scope": "user", "token_type": "bearer", "expires_in": "86400.92",
		"server_time": "1443571905.5606415", "referer_ip": "10.0.0.1",
		"etag": "\"afZYj912P4alikMz_P11982\"", "request_id": "86400",
		"untrimmed": "  untrimmed  ",
	}
	for key, value := range kvmap {
		values.Set(key, value)
	}

	tok := &oauth2.Token{}
	tok = tok.WithExtra(values)
	scope := tok.Extra("scope")
	if got, want := scope, "user"; got != want {
		t.Errorf("got scope = %q; want %q", got, want)
	}
	serverTime := tok.Extra("server_time")
	if got, want := serverTime, 1443571905.5606415; got != want {
		t.Errorf("got server_time value = %v; want %v", got, want)
	}
	refererIP := tok.Extra("referer_ip")
	if got, want := refererIP, "10.0.0.1"; got != want {
		t.Errorf("got referer_ip value = %v, want %v", got, want)
	}
	expiresIn := tok.Extra("expires_in")
	if got, want := expiresIn, 86400.92; got != want {
		t.Errorf("got expires_in value = %v, want %v", got, want)
	}
	requestID := tok.Extra("request_id")
	if got, want := requestID, int64(86400); got != want {
		t.Errorf("got request_id value = %v, want %v", got, want)
	}
	untrimmed := tok.Extra("untrimmed")
	if got, want := untrimmed, "  untrimmed  "; got != want {
		t.Errorf("got untrimmed = %q; want %q", got, want)
	}
}

const day = 24 * time.Hour

func TestExchangeRequest_JSONResponse_Expiry(t *testing.T) {
	var expiryStr string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(fmt.Sprintf(`{"access_token": "90d", "scope": "user", "token_type": "bearer", %s}`, expiryStr)))
	}))
	defer ts.Close()
	conf := newConf(ts.URL)
	conf.ExpiryDelta = 1

	for _, c := range []struct {
		expires string
		want    bool
	}{
		{fmt.Sprintf(`"expires_in": %d`, 3600), true},
		{fmt.Sprintf(`"expires_in": "%d"`, 3600), true}, // PayPal case
		{`"expires_in": false`, false},                  // wrong type
		{`"expires_in": {}`, false},                     // wrong type
		{`"expires_in": "zzz"`, false},                  // wrong value
	} {
		expiryStr = c.expires
		if err := testExchangeRequestJSONResponseexpiry(conf, c.expires, c.want); err != nil {
			t.Errorf("%v", err)
		}
	}
}

func testExchangeRequestJSONResponseexpiry(conf *oauth2.Config, exp string, want bool) error {

	t1 := time.Now().Add(3599 * time.Second) // subtract 10 seconds
	tok, err := conf.Exchange(context.Background(), "exchange-code")
	t2 := time.Now().Add(3599 * time.Second)

	if got := (err == nil); got != want {
		if want {
			return fmt.Errorf("%s: got %v", exp, err)
		}
		return fmt.Errorf("%s wanted error; got success", exp)
	}
	if !want {
		return nil
	}
	if !tok.Valid() {
		return fmt.Errorf("Token invalid. Got: %#v", tok)
	}
	expiry := tok.Expiry
	if expiry.Before(t1) || expiry.After(t2) {
		return fmt.Errorf("Unexpected value for Expiry: %v (shold be between %v and %v)", expiry, t1, t2)
	}
	return nil
}

func TestExchangeRequest_BadResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"scope": "user", "token_type": "bearer"}`))
	}))
	defer ts.Close()
	conf := newConf(ts.URL)
	tok, err := conf.Exchange(context.Background(), "code")
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "" {
		t.Errorf("Unexpected access token, %#v.", tok.AccessToken)
	}
}

func TestExchangeRequest_BadResponseType(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":123,  "scope": "user", "token_type": "bearers"}`))
	}))
	defer ts.Close()
	conf := newConf(ts.URL)
	_, err := conf.Exchange(context.Background(), "exchange-code")
	if err == nil {
		t.Error("expected error from invalid access_token type")
	}
}

func TestExchangeRequest_NonBasicAuth(t *testing.T) {
	tr := &mockTransport{
		rt: func(r *http.Request) (w *http.Response, err error) {
			headerAuth := r.Header.Get("Authorization")
			if headerAuth != "" {
				t.Errorf("Unexpected authorization header, %v is found.", headerAuth)
			}
			return nil, errors.New("no response")
		},
	}

	conf := &oauth2.Config{
		ClientID: "CLIENT_ID",
		Endpoint: oauth2.Endpoint{
			AuthURL:        "https://accounts.google.com/auth",
			TokenURL:       "https://accounts.google.com/token",
			IDSecretInBody: true,
		},
		HTTPClientFunc: func(ctx context.Context) (*http.Client, error) {
			return &http.Client{Transport: tr}, nil
		},
	}

	ctx := context.Background()
	conf.Exchange(ctx, "code")
}

func TestPasswordCredentialsTokenRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		expected := "/token"
		if r.URL.String() != expected {
			t.Errorf("URL = %q; want %q", r.URL, expected)
		}
		headerAuth := r.Header.Get("Authorization")
		expected = "Basic Q0xJRU5UX0lEOkNMSUVOVF9TRUNSRVQ="
		if headerAuth != expected {
			t.Errorf("Authorization header = %q; want %q", headerAuth, expected)
		}
		headerContentType := r.Header.Get("Content-Type")
		expected = "application/x-www-form-urlencoded"
		if headerContentType != expected {
			t.Errorf("Content-Type header = %q; want %q", headerContentType, expected)
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed reading request body: %s.", err)
		}
		expected = "grant_type=password&password=password1&scope=scope1+scope2&username=user1"
		if string(body) != expected {
			t.Errorf("res.Body = %q; want %q", string(body), expected)
		}
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		w.Write([]byte("access_token=90d64460d14870c08c81352a05dedd3465940a7c&scope=user&token_type=bearer"))
	}))
	defer ts.Close()
	conf := newConf(ts.URL)

	tsrc := conf.FromOptions(oauth2.SetAuthURLParam("grant_type", "password"),
		oauth2.SetAuthURLParam("username", "user1"),
		oauth2.SetAuthURLParam("password", "password1"))
	tok, err := tsrc.Token(context.Background())
	if err != nil {
		t.Error(err)
	}
	if !tok.Valid() {
		t.Fatalf("Token invalid. Got: %#v", tok)
	}
	expected := "90d64460d14870c08c81352a05dedd3465940a7c"
	if tok.AccessToken != expected {
		t.Errorf("AccessToken = %q; want %q", tok.AccessToken, expected)
	}
	expected = "bearer"
	if tok.TokenType != expected {
		t.Errorf("TokenType = %q; want %q", tok.TokenType, expected)
	}
}

func TestTokenRefreshRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() == "/somethingelse" {
			return
		}
		if r.URL.String() != "/token" {
			t.Errorf("Unexpected token refresh request URL, %v is found.", r.URL)
		}
		headerContentType := r.Header.Get("Content-Type")
		if headerContentType != "application/x-www-form-urlencoded" {
			t.Errorf("Unexpected Content-Type header, %v is found.", headerContentType)
		}
		body, _ := ioutil.ReadAll(r.Body)
		if string(body) != "grant_type=refresh_token&refresh_token=REFRESH_TOKEN" {
			t.Errorf("Unexpected refresh token payload, %v is found.", string(body))
		}

	}))
	defer ts.Close()
	conf := newConf(ts.URL)
	c := conf.Client(&oauth2.Token{RefreshToken: "REFRESH_TOKEN"})
	c.Get(ts.URL + "/somethingelse")
}

func TestFetchWithNoRefreshToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() == "/somethingelse" {
			return
		}
		if r.URL.String() != "/token" {
			t.Errorf("Unexpected token refresh request URL, %v is found.", r.URL)
		}
		headerContentType := r.Header.Get("Content-Type")
		if headerContentType != "application/x-www-form-urlencoded" {
			t.Errorf("Unexpected Content-Type header, %v is found.", headerContentType)
		}
		body, _ := ioutil.ReadAll(r.Body)
		if string(body) != "client_id=CLIENT_ID&grant_type=refresh_token&refresh_token=REFRESH_TOKEN" {
			t.Errorf("Unexpected refresh token payload, %v is found.", string(body))
		}
	}))
	defer ts.Close()
	conf := newConf(ts.URL)
	c := conf.Client(nil)
	_, err := c.Get(ts.URL + "/somethingelse")
	if err == nil {
		t.Errorf("Fetch should return an error if no refresh token is set")
	}
}

func TestRefreshToken_RefreshTokenReplacement(t *testing.T) {
	// checks that refresh token is reset when passed new refresh_token and preserved when not sent
	expectedRefreshTokens := []string{"OLD_REFRESH_TOKEN", "NEW_REFRESH_TOKEN", "NEW_REFRESH_TOKEN"}
	sendRefreshTokens := []string{"NEW_REFRESH_TOKEN", "", ""}
	counter := 0

	ctx := context.Background()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		access_token := "OK"

		if r.Form.Get("refresh_token") != expectedRefreshTokens[counter] {
			access_token = fmt.Sprintf("test #%d expected %s; got %s", counter, expectedRefreshTokens[counter], r.Form.Get("refresh_token"))
		}
		w.Header().Set("Content-Type", "application/json")

		json.NewEncoder(w).Encode(struct {
			AccessToken  string `json:"access_token"`
			Scope        string `json:"scope"`
			TokenType    string `json:"bearer"`
			Expires      int    `json:"expires_in"`
			RefreshToken string `json:"refresh_token,omitempty"`
		}{
			AccessToken:  access_token,
			Scope:        "user",
			TokenType:    "bearer",
			Expires:      1, //  1 will force refresh due to expiry delta
			RefreshToken: sendRefreshTokens[counter],
		})
		return
	}))
	defer ts.Close()
	conf := newConf(ts.URL)
	tkr := conf.TokenSource(&oauth2.Token{RefreshToken: expectedRefreshTokens[0]})
	for counter < 3 {
		tk, err := tkr.Token(ctx)
		if err != nil {
			t.Errorf("got err = %v; want none", err)
			return
		}
		if tk.AccessToken != "OK" {
			t.Errorf(tk.AccessToken)
		}
		counter++
	}
}

func TestConfigClientWithToken(t *testing.T) {
	tok := &oauth2.Token{
		AccessToken: "abc123",
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Authorization"), fmt.Sprintf("Bearer %s", tok.AccessToken); got != want {
			t.Errorf("Authorization header = %q; want %q", got, want)
		}
		return
	}))
	defer ts.Close()
	conf := newConf(ts.URL)

	c := conf.Client(tok)
	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Error(err)
	}
	_, err = c.Do(req)
	if err != nil {
		t.Error(err)
	}
}
