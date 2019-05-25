// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sync"

	"cloud.google.com/go/firestore"

	"github.com/jfcote87/oauth2"
	"github.com/jfcote87/oauth2/google"
	"github.com/jfcote87/oauth2/jws"
	"github.com/jfcote87/oauth2/jwt"

	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func Example_defaultClient() {
	client, err := google.DefaultClient(oauth2.NoContext,
		"https://www.googleapis.com/auth/devstorage.full_control")
	if err != nil {
		log.Fatal(err)
	}
	client.Get("...")
}

func Example_webServer() {
	// Your credentials should be obtained from the Google
	// Developer Console (https://console.developers.google.com).
	conf := &oauth2.Config{
		ClientID:     "YOUR_CLIENT_ID",
		ClientSecret: "YOUR_CLIENT_SECRET",
		RedirectURL:  "YOUR_REDIRECT_URL",
		Scopes: []string{
			"https://www.googleapis.com/auth/bigquery",
			"https://www.googleapis.com/auth/blogger",
		},
		Endpoint: google.Endpoint,
	}
	// Redirect user to Google's consent page to ask for permission
	// for the scopes specified above.
	url := conf.AuthCodeURL("state")
	fmt.Printf("Visit the URL for the auth dialog: %v", url)
	cxx := context.Background()
	_ = cxx

	// Handle the exchange code to initiate a transport.
	tok, err := conf.Exchange(oauth2.NoContext, "authorization-code")
	if err != nil {
		log.Fatal(err)
	}
	client := conf.Client(tok)
	client.Get("...")
}

func Example_jWTConfigFromJSON() {
	// Your credentials should be obtained from the Google
	// Developer Console (https://console.developers.google.com).
	// Navigate to your project, then see the "Credentials" page
	// under "APIs & Auth".
	// To create a service account client, click "Create new Client ID",
	// select "Service Account", and click "Create Client ID". A JSON
	// key file will then be downloaded to your computer.
	data, err := ioutil.ReadFile("/path/to/your-project-key.json")
	if err != nil {
		log.Fatal(err)
	}
	conf, err := google.JWTConfigFromJSON(data, "https://www.googleapis.com/auth/bigquery")
	if err != nil {
		log.Fatal(err)
	}
	// Initiate an http.Client. The following GET request will be
	// authorized and authenticated on the behalf of
	// your service account.
	client, _ := conf.Client(nil)
	client.Get("...")
}

func Example_sDKConfig() {
	// The credentials will be obtained from the first account that
	// has been authorized with `gcloud auth login`.
	conf, err := google.NewSDKConfig("")
	if err != nil {
		log.Fatal(err)
	}
	// Initiate an http.Client. The following GET request will be
	// authorized and authenticated on the behalf of the SDK user.
	conf.Client().Get("...")
}

func Example_googleServiceAccount() { // The contents of your RSA private key or your PEM file
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
	// Your credentials should be obtained from the Google
	// Developer Console (https://console.developers.google.com).
	conf := &jwt.Config{
		Signer: signer,
		Issuer: "xxx@developer.gserviceaccount.com",
		Scopes: []string{
			"https://www.googleapis.com/auth/bigquery",
			"https://www.googleapis.com/auth/blogger",
		},
		TokenURL: google.JWTTokenURL,
		Audience: google.JWTTokenURL,
		// If you would like to impersonate a user, you can
		// create a transport with a subject. The following GET
		// request will be made on the behalf of user@example.com.
		// Optional.
		Subject: "user@example.com",
	}
	// Initiate an http.Client, the following GET request will be
	// authorized and authenticated on the behalf of user@example.com.
	client, _ := conf.Client(nil)
	client.Get("...")
}

func Example_googleComputeTokenSource() {
	client := &http.Client{
		Transport: &oauth2.Transport{
			// Fetch from Google Compute Engine's metadata server to retrieve
			// an access token for the provided account.
			// If no account is specified, "default" is used.
			Source: google.ComputeTokenSource(""),
		},
	}
	client.Get("...")
}

func ExamplePerRPCCredentials() {
	target := "firestore.googleapis.com:443"
	ctx := context.Background()
	ts, err := getTokensourceFromFile("/path/to/your-project-key.json",
		"https://www.googleapis.com/auth/datastore", "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		log.Fatalf("%v", err)
	}
	conn, err := grpc.DialContext(ctx, target,
		grpc.WithPerRPCCredentials(&oauth2.PerRPCCredentials{
			TokenSource: ts,
		}),
		grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, "")),
	)
	if err != nil {
		log.Fatalf("dial failed to %s: %v", target, err)
	}
	cl, err := firestore.NewClient(ctx, "my-firestore-project", option.WithGRPCConn(conn))
	if err != nil {
		log.Fatalf("")
	}
	snapshot, _ := cl.Doc("/recs/12345").Get(ctx)
	for k, v := range snapshot.Data() {
		log.Printf("%s: %v", k, v)
	}

}

func getTokensourceFromFile(fn string, scopes ...string) (oauth2.TokenSource, error) {
	data, err := ioutil.ReadFile("/path/to/your-project-key.json")
	if err != nil {
		return nil, err
	}
	return google.JWTConfigFromJSON(data, scopes...)
}

func NewCustomCachingTokenSource(id string, ts oauth2.TokenSource) *CustomCachingTokenSource {
	return &CustomCachingTokenSource{
		id:        id,
		refresher: ts,
	}
}

type CustomCachingTokenSource struct {
	id        string // unique identifier for token
	refresher oauth2.TokenSource
	mu        sync.Mutex // guards t
	t         *oauth2.Token
}

func (cts *CustomCachingTokenSource) Token(ctx context.Context) (*oauth2.Token, error) {
	cts.mu.Lock()
	defer cts.mu.Unlock()
	if cts.t.Valid() {
		return cts.t, nil
	}
	var err error
	t := cts.GetCachedValidToken(ctx)
	if t == nil {
		if t, err = cts.refresher.Token(ctx); err != nil {
			return nil, err
		}
	}
	cts.Save(t) // Save new valid token to storage
	cts.t = t
	return t, nil
}

func (cts *CustomCachingTokenSource) Save(t *oauth2.Token) {
	// save to db, memcache, etc.
	return
}

func (cts *CustomCachingTokenSource) GetCachedValidToken(ctx context.Context) *oauth2.Token {
	var token *oauth2.Token
	// get from db, memchace, etc. using cts.id
	return token
}
