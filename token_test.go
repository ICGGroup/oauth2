// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"testing"
	"time"

	"github.com/jfcote87/oauth2"
)

func TestTokenExtra(t *testing.T) {
	type testCase struct {
		key  string
		val  interface{}
		want interface{}
	}
	const key = "extra-key"
	cases := []testCase{
		{key: key, val: "abc", want: "abc"},
		{key: key, val: 123, want: 123},
		{key: key, val: "", want: ""},
		{key: "other-key", val: "def", want: nil},
	}
	for _, tc := range cases {
		extra := make(map[string]interface{})
		extra[tc.key] = tc.val
		tok := &oauth2.Token{}
		tok = tok.WithExtra(extra)
		if got, want := tok.Extra(key), tc.want; got != want {
			t.Errorf("Extra(%q) = %q; want %q", key, got, want)
		}
	}
}

func TestTokenExpiry(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		tok  *oauth2.Token
		want bool
	}{
		{name: "12 seconds", tok: &oauth2.Token{AccessToken: "A", Expiry: now.Add(12 * time.Second)}, want: true},
		{name: "0", tok: &oauth2.Token{AccessToken: "A", Expiry: now}, want: false},
		{name: "-1 hour", tok: nil, want: false},
	}
	for _, tc := range cases {
		if got, want := tc.tok.Valid(), tc.want; got != want {
			t.Errorf("expired (%q) = %v; want %v", tc.name, got, want)
		}
	}
}

func TestTokenTypeMethod(t *testing.T) {
	cases := []struct {
		name string
		tok  *oauth2.Token
		want string
	}{
		{name: "bearer-mixed_case", tok: &oauth2.Token{TokenType: "beAREr"}, want: "Bearer"},
		{name: "default-bearer", tok: &oauth2.Token{}, want: "Bearer"},
		{name: "basic", tok: &oauth2.Token{TokenType: "basic"}, want: "Basic"},
		{name: "basic-capitalized", tok: &oauth2.Token{TokenType: "Basic"}, want: "Basic"},
		{name: "mac", tok: &oauth2.Token{TokenType: "mac"}, want: "MAC"},
		{name: "mac-caps", tok: &oauth2.Token{TokenType: "MAC"}, want: "MAC"},
		{name: "mac-mixed_case", tok: &oauth2.Token{TokenType: "mAc"}, want: "MAC"},
	}
	for _, tc := range cases {
		if got, want := tc.tok.Type(), tc.want; got != want {
			t.Errorf("TokenType(%q) = %v; want %v", tc.name, got, want)
		}
	}
}
