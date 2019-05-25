// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oauth2

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/jfcote87/ctxclient"
)

// Token represents the crendentials used to authorize
// the requests to access protected resources on the OAuth 2.0
// provider's backend.
//
// Most users of this package should not access fields of Token
// directly. They're exported mostly for use by related packages
// implementing derivative OAuth2 flows.
type Token struct {
	// AccessToken is the token that authorizes and authenticates
	// the requests.
	AccessToken string `json:"access_token"`

	// TokenType is the type of token.
	// The Type method returns either this or "Bearer", the default.
	TokenType string `json:"token_type,omitempty"`

	// RefreshToken is a token that's used by the application
	// (as opposed to the user) to refresh the access token
	// if it expires.
	RefreshToken string `json:"refresh_token,omitempty"`

	// Expiry is the optional expiration time of the access token.
	//
	// If zero, TokenSource implementations will reuse the same
	// token forever and RefreshToken or equivalent
	// mechanisms for that TokenSource will not be used.
	Expiry time.Time `json:"expiry,omitempty"`

	// raw optionally contains extra metadata from the server
	// when updating a token.
	raw interface{}
}

// DefaultExpiryDelta determines the number of seconds  a token should
// expire sooner than the delivered expiration time. This avoids late
// expirations due to client-server time mismatches and latency.
const DefaultExpiryDelta = 10

var intType = reflect.TypeOf(int64(0))

// FromMap returns a token from a map[string]interface{}
func FromMap(vals map[string]interface{}, expiryDelta int64) (*Token, error) {
	t := &Token{
		raw: vals,
	}
	if expiryDelta == 0 {
		expiryDelta = DefaultExpiryDelta
	}
	var expSeconds int64
	for k, v := range vals {
		switch typedVal := v.(type) {
		case string:
			switch k {
			case "access_token":
				t.AccessToken = typedVal
			case "refresh_token":
				t.RefreshToken = typedVal
			case "token_type":
				t.TokenType = typedVal
			case "expires_in": // PayPal returns string so check for it here
				dur, err := strconv.ParseInt(typedVal, 10, 64)
				if err != nil {
					return nil, err
				}
				expSeconds = dur
			}
		default:
			switch k {
			case "expires_in":
				if v == nil { // check for nil to prevent panic on reflect.Indirect
					return nil, fmt.Errorf("unable to convert %s to int64: %v", k, v)
				}
				rv := reflect.Indirect(reflect.ValueOf(v))
				if !rv.Type().ConvertibleTo(intType) {
					return nil, fmt.Errorf("unable to convert %s to int64: %v", k, v)
				}
				expSeconds = rv.Convert(intType).Int()
			case "access_token", "refresh_token", "token_type":
				return nil, fmt.Errorf("%s must be a string; got %v", k, v)
			}
		}
	}
	if expSeconds > 0 {
		t.Expiry = time.Now().Add(time.Duration(expSeconds-expiryDelta) * time.Second)
	}

	return t, nil
}

// Type returns t.TokenType if non-empty, else "Bearer".
func (t *Token) Type() string {
	if t.TokenType == "" {
		return "Bearer"
	}
	switch strings.ToLower(t.TokenType) {
	case "bearer":
		return "Bearer"
	case "mac":
		return "MAC"
	case "basic":
		return "Basic"
	}
	return t.TokenType
}

// SetAuthHeader sets the Authorization header to r using the access
// token in t.
//
// This method is unnecessary when using Transport or an HTTP Client
// returned by this package.
func (t *Token) SetAuthHeader(r *http.Request) {
	r.Header.Set("Authorization", t.Type()+" "+t.AccessToken)
}

// WithExtra returns a new Token that's a clone of t, but using the
// provided raw extra map. This is only intended for use by packages
// implementing derivative OAuth2 flows.
func (t *Token) WithExtra(extra interface{}) *Token {
	t2 := new(Token)
	if t != nil { // nil check
		*t2 = *t
	}
	t2.raw = extra
	return t2
}

// Extra returns an extra field.
// Extra fields are key-value pairs returned by the server as a
// part of the token retrieval response.
func (t *Token) Extra(key string) interface{} {
	if raw, ok := t.raw.(map[string]interface{}); ok {
		return raw[key]
	}

	vals, ok := t.raw.(url.Values)
	if !ok {
		return nil
	}

	v := vals.Get(key)
	switch s := strings.TrimSpace(v); strings.Count(s, ".") {
	case 0: // Contains no "."; try to parse as int
		if i, err := strconv.ParseInt(s, 10, 64); err == nil {
			return i
		}
	case 1: // Contains a single "."; try to parse as float
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return f
		}
	}

	return v
}

// expired reports whether the token is expired.
// t must be non-nil.
func (t *Token) expired() bool {
	if t.Expiry.IsZero() {
		return false
	}
	return t.Expiry.Before(time.Now())
}

// Valid reports whether t is non-nil, has an AccessToken, and is not expired.
func (t *Token) Valid() bool {
	return t != nil && t.AccessToken != "" && !t.expired()
}

// RetrieveToken returns a token
func RetrieveToken(ctx context.Context, hcf ctxclient.Func, clientID, clientSecret, tokenURL string, v url.Values, expiryDelta int64) (*Token, error) {
	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if clientID > "" {
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	}
	var body []byte
	r, err := hcf.Do(ctx, req)
	switch ex := err.(type) {
	case nil:
		body, err = ioutil.ReadAll(io.LimitReader(r.Body, 1<<20))
		r.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("oauth2: token body read error:  %v", err)
		}
	case ctxclient.NotSuccess:
		return nil, fmt.Errorf("oauth2: cannot fetch token: %d %s: %s", ex.StatusCode, ex.StatusMessage, string(ex.Body))
	default:
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}

	//var token *Token
	mappedValues := make(map[string]interface{})
	content, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch content {
	case "application/x-www-form-urlencoded", "text/plain":
		vals, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, err
		}
		for k := range vals {
			mappedValues[k] = vals.Get(k)
		}
	default:
		if err := json.NewDecoder(bytes.NewReader(body)).Decode(&mappedValues); err != nil {
			return nil, err
		}
	}
	return FromMap(mappedValues, expiryDelta)
}
