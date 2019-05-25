// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package google_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/jfcote87/oauth2/google"
	"github.com/jfcote87/oauth2/jws"
)

func TestJWTAccessTokenSourceFromJSON(t *testing.T) {
	// Generate a key we can use in the test data.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Encode the key and substitute into our example JSON.
	enc := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	enc, err = json.Marshal(string(enc))
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	jsonKey := bytes.Replace(jwtJSONKey, []byte(`"super secret key"`), enc, 1)

	ts, err := google.JWTAccessTokenSourceFromJSON(jsonKey, "audience")
	if err != nil {
		t.Fatalf("JWTAccessTokenSourceFromJSON: %v\nJSON: %s", err, string(jsonKey))
	}

	tok, err := ts.Token(context.TODO())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}

	if got, want := tok.TokenType, "Bearer"; got != want {
		t.Errorf("TokenType = %q, want %q", got, want)
	}
	if got := tok.Expiry; tok.Expiry.Before(time.Now()) {
		t.Errorf("Expiry = %v, should not be expired", got)
	}

	err = jws.Verify(tok.AccessToken, jws.RS256Verifier(&privateKey.PublicKey))
	if err != nil {
		t.Errorf("jws.Verify on AccessToken: %v", err)
	}

	claim, err := jws.DecodePayload(tok.AccessToken)
	if err != nil {
		t.Fatalf("jws.Decode on AccessToken: %v", err)
	}

	if got, want := claim.Issuer, "gopher@developer.gserviceaccount.com"; got != want {
		t.Errorf("Iss = %q, want %q", got, want)
	}
	if got, want := claim.Subject, "gopher@developer.gserviceaccount.com"; got != want {
		t.Errorf("Sub = %q, want %q", got, want)
	}
	if got, want := claim.Audience, "audience"; got != want {
		t.Errorf("Aud = %q, want %q", got, want)
	}

	// Finally, check the header private key.
	var hdrMap = struct {
		KeyID string `json:"kid"`
	}{}
	if err := jws.DecodeHeader(tok.AccessToken, &hdrMap); err != nil {
		t.Errorf("jwt header decode: %v", err)
	}
	if got, want := hdrMap.KeyID, "268f54e43a1af97cfc71731688434f45aca15c8b"; got != want {
		t.Errorf("Header KeyID = %q, want %q", got, want)
	}
}
