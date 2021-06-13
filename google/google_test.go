// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package google_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ICGGroup/oauth2/google"
	"github.com/ICGGroup/oauth2/jws"
)

var webJSONKey = []byte(`
{
    "web": {
        "auth_uri": "https://google.com/o/oauth2/auth",
        "client_secret": "3Oknc4jS_wA2r9i",
        "token_uri": "https://google.com/o/oauth2/token",
        "client_email": "222-nprqovg5k43uum874cs9osjt2koe97g8@developer.gserviceaccount.com",
        "redirect_uris": ["https://www.example.com/oauth2callback"],
        "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/222-nprqovg5k43uum874cs9osjt2koe97g8@developer.gserviceaccount.com",
        "client_id": "222-nprqovg5k43uum874cs9osjt2koe97g8.apps.googleusercontent.com",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "javascript_origins": ["https://www.example.com"]
    }
}`)

var installedJSONKey = []byte(`{
  "installed": {
      "client_id": "222-installed.apps.googleusercontent.com",
      "redirect_uris": ["https://www.example.com/oauth2callback"]
    }
}`)

var jwtJSONKey = []byte(`{
  "private_key_id": "268f54e43a1af97cfc71731688434f45aca15c8b",
  "private_key": "super secret key",
  "client_email": "gopher@developer.gserviceaccount.com",
  "client_id": "gopher.apps.googleusercontent.com",
  "token_uri": "https://accounts.google.com/o/gophers/token",
  "type": "service_account"
}`)

var jwtJSONKeyNoTokenURL = []byte(`{
  "private_key_id": "268f54e43a1af97cfc71731688434f45aca15c8b",
  "private_key": "super secret key",
  "client_email": "gopher@developer.gserviceaccount.com",
  "client_id": "gopher.apps.googleusercontent.com",
  "type": "service_account"
}`)

var dummyPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`

func TestConfigFromJSON(t *testing.T) {
	conf, err := google.ConfigFromJSON(webJSONKey, "scope1", "scope2")
	if err != nil {
		t.Error(err)
	}
	if got, want := conf.ClientID, "222-nprqovg5k43uum874cs9osjt2koe97g8.apps.googleusercontent.com"; got != want {
		t.Errorf("ClientID = %q; want %q", got, want)
	}
	if got, want := conf.ClientSecret, "3Oknc4jS_wA2r9i"; got != want {
		t.Errorf("ClientSecret = %q; want %q", got, want)
	}
	if got, want := conf.RedirectURL, "https://www.example.com/oauth2callback"; got != want {
		t.Errorf("RedictURL = %q; want %q", got, want)
	}
	if got, want := strings.Join(conf.Scopes, ","), "scope1,scope2"; got != want {
		t.Errorf("Scopes = %q; want %q", got, want)
	}
	if got, want := conf.Endpoint.AuthURL, "https://google.com/o/oauth2/auth"; got != want {
		t.Errorf("AuthURL = %q; want %q", got, want)
	}
	if got, want := conf.Endpoint.TokenURL, "https://google.com/o/oauth2/token"; got != want {
		t.Errorf("TokenURL = %q; want %q", got, want)
	}
}

func TestConfigFromJSON_Installed(t *testing.T) {
	conf, err := google.ConfigFromJSON(installedJSONKey)
	if err != nil {
		t.Error(err)
	}
	if got, want := conf.ClientID, "222-installed.apps.googleusercontent.com"; got != want {
		t.Errorf("ClientID = %q; want %q", got, want)
	}
}

func TestJWTConfigFromJSON(t *testing.T) {
	conf, err := google.JWTConfigFromJSON(jwtJSONKey, "scope1", "scope2")
	if err == nil {
		t.Fatalf("key parse successful; wanted \"private key should be a PEM...")
	}
	jwtJSONReplace := bytes.Replace(jwtJSONKey, []byte("super secret key"), []byte(strings.Replace(dummyPrivateKey, "\n", "\\n", -1)), 1)
	if conf, err = google.JWTConfigFromJSON(jwtJSONReplace, "scope1", "scope2"); err != nil {
		t.Fatal(err)
	}
	if got, want := conf.Issuer, "gopher@developer.gserviceaccount.com"; got != want {
		t.Errorf("Email = %q, want %q", got, want)
	}
	hdr := make(map[string]interface{})
	if err = jws.DecodeHeader(string(conf.Signer.Header())+".X.X", &hdr); err != nil {
		t.Fatalf("wanted header; got error %v", err)
	}
	if got, ok := hdr["kid"].(string); !ok || got != "268f54e43a1af97cfc71731688434f45aca15c8b" {
		t.Errorf("wanted kid = 268f54e43a1af97cfc71731688434f45aca15c8b; got %v", hdr["kid"])
	}

	if got, want := strings.Join(conf.Scopes, ","), "scope1,scope2"; got != want {
		t.Errorf("Scopes = %q; want %q", got, want)
	}
	if got, want := conf.TokenURL, "https://accounts.google.com/o/gophers/token"; got != want {
		t.Errorf("TokenURL = %q; want %q", got, want)
	}
}

func TestJWTConfigFromJSONNoTokenURL(t *testing.T) {
	jwtJSONReplace := bytes.Replace(jwtJSONKeyNoTokenURL, []byte("super secret key"), []byte(strings.Replace(dummyPrivateKey, "\n", "\\n", -1)), 1)
	conf, err := google.JWTConfigFromJSON(jwtJSONReplace, "scope1", "scope2")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := conf.TokenURL, "https://accounts.google.com/o/oauth2/token"; got != want {
		t.Errorf("TokenURL = %q; want %q", got, want)
	}
}
