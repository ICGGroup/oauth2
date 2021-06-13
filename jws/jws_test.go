// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package jws_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ICGGroup/oauth2/jws"
)

func TestSignAndVerify(t *testing.T) {
	payload := &jws.ClaimSet{
		Issuer:    "http://google.com/",
		Audience:  "",
		ExpiresAt: 3610,
		IssuedAt:  10,
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer := jws.RS256(privateKey, "")
	token, err := payload.JWT(signer)
	if err != nil {
		t.Fatal(err)
	}
	err = jws.Verify(token, jws.RS256Verifier(&privateKey.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyFailsOnMalformedClaim(t *testing.T) {
	err := jws.Verify("abc.def", jws.RS256Verifier(nil))
	if err == nil {
		t.Error("got no errors; want improperly formed JWT not to be verified")
	}
}

func decodeToBigInt(s string) *big.Int {
	bx, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return (&big.Int{}).SetBytes(bx)
}

func TestExpirationClaims(t *testing.T) {
	c := &jws.ClaimSet{}
	if err := c.SetExpirationClaims(0, -10*time.Second); err == nil {
		t.Errorf("jws expiration claims expected invalid Exp; got nil err")
	}
	if err := c.SetExpirationClaims(100*time.Second, 30*time.Second); err != nil || c.ExpiresAt-c.IssuedAt != 30 {
		t.Errorf("expected nil error with 30 second difference; got %v %d", err, c.ExpiresAt-c.IssuedAt)
	}
}

func TestClaimSet_Decode(t *testing.T) {
	c := &jws.ClaimSet{
		Issuer:    "ISS",
		Audience:  "AUD",
		IssuedAt:  5,
		ExpiresAt: 6,
		NotBefore: 7,
		ID:        "JTI",
		Subject:   "SUB",
		PrivateClaims: map[string]interface{}{
			"a":   "claim A",
			"prn": "PRN",
			"b":   9,
			"c": struct {
				S string
			}{"AASDF"},
		},
	}
	signer := jws.HS256([]byte("abc"))
	token, _ := c.JWT(signer)
	c, err := jws.DecodePayload(token)
	if err != nil {
		t.Errorf("jws: unexpected decode error: %v", err)
	}
	if c.IssuedAt != 5 || c.Issuer != "ISS" {
		t.Errorf("jws: expected Iat = 5 and Iss = \"ISS\"; got %d and %s", c.IssuedAt, c.Issuer)
	}
	if bval, ok := c.PrivateClaims["b"].(float64); !ok || bval != 9.0 {
		t.Errorf("jws: expected PrivateClaim[\"b\"] == 9; got %v", c.PrivateClaims["b"])
	}

	if cmap, ok := c.PrivateClaims["c"].(map[string]interface{}); !ok {
		t.Errorf("jws: expected PrivateClaim[\"c\"] as map[string]interface{}}; got %#v", c.PrivateClaims["c"])
	} else if sval, ok2 := cmap["S"].(string); !ok2 || sval != "AASDF" {
		t.Errorf("jws: expected PrivateClaim[\"c\"] == \"AASDF\"; got %v", cmap["S"])
	}

}

func TestClaimSet_JWT(t *testing.T) {
	clm := &jws.ClaimSet{
		Issuer:    "joe",
		ExpiresAt: 1300819380,
		PrivateClaims: map[string]interface{}{
			"http://example.com/is_root": true,
		},
	}
	secret, _ := base64.RawURLEncoding.DecodeString("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow")

	signer := jws.HS256(secret)
	tk, err := clm.JWT(signer)
	if err != nil {
		t.Fatalf("rs256 signing returned %v", err)
	}
	sections := strings.Split(tk, ".")
	if len(sections) != 3 {
		t.Fatalf("jwt should have 3 sections; got %d", len(sections))
	}
	expectedSig := "tu77b1J0ZCHMDd3tWZm36iolxZtBRaArSrtayOBDO34"
	if sections[2] != expectedSig {
		t.Fatalf("HS256 expected sig %s", sections[2])
	}
	// From https://tools.ietf.org/html/rfc7515#page-38
	testVector := `eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`
	if err := jws.Verify(testVector, jws.HS256Verifier(secret)); err != nil {
		t.Fatalf("verification of HS256 testVector failed: %v", err)
	}
}

func TestClaimSet_JWT_RS256(t *testing.T) {
	clm := &jws.ClaimSet{
		Issuer:    "joe",
		ExpiresAt: 1300819380,
		PrivateClaims: map[string]interface{}{
			"http://example.com/is_root": true,
		},
	}
	pk := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: decodeToBigInt("ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"),
			E: int(decodeToBigInt("AQAB").Int64()),
		},
		D: decodeToBigInt("Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ"),
		Primes: []*big.Int{
			decodeToBigInt("4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc"),
			decodeToBigInt("uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc"),
		},
	}
	//tk, err := jws.EncodeWithSigner(hdr, clm, jws.SignerRS256(pk))
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(pk),
	})
	signer, err := jws.RS256FromPEM(pemBytes, "")
	if err != nil {
		t.Fatalf("RS256FromPEM: %v", err)
	}
	tk, err := clm.JWT(signer)
	if err != nil {
		t.Fatalf("rs256 signing returned %v", err)
	}
	sections := strings.Split(tk, ".")
	if len(sections) != 3 {
		t.Fatalf("jwt should have 3 sections; got %d", len(sections))
	}
	expectedSig := "ay_52TSkn_L_xyMq2Z25_pLShgliTdCBbGR4E3jDCKsFZ9npHZ6dMiVLKSwWgXTyHJcKmmwKEwB9tuDxssKmcPK5RKNtIasLzmrjFHtGDDxbNl1ymyxBVopTzzVCBJtBxD-0Eb0pv40a-ahaqJlNTqY6HDZJ0MyuHeRcaTijIu_WVmMRlrJbNrfN4tXVh-ZMBFrT1xCwLkFKNC8yHs8PBQbyiZKCYfpxkvh8txh3S0-CzaqL5SJLSi7A4O7GUVV4CikX7PkUPeD_jE5N3FnaSojVpsufgeIs4u2QhwQIErbwXQq8N7oYFWkE0pu_5MQXXdPk9xqAqf7A3D-xm1IWBg"
	if sections[2] != expectedSig {
		t.Errorf("RS256 expected sig %s", sections[2])
	}

	// From https://tools.ietf.org/html/rfc7515#page-42
	testVector := `eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw`
	if err := jws.Verify(testVector, jws.RS256Verifier(&pk.PublicKey)); err != nil {
		t.Fatalf("verification of RS256 testVector failed: %v", err)
	}
}

type tokenTest struct {
	Type      string
	Signer    jws.Signer
	Signature string
	Verifier  jws.Verifier
}

var testPK = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC4ybreglj9WZNX
+1JzGtUqliaJ3q57xFswysEK+foClwi+ln37mZceXQ7GUim6mdsqJ1pTzv7Mpdny
xq94mWR5+ErGpb2yaEDXKrF7mDGnyumzNgJHOlLS288K33sdujAaU28Ht73/8GXw
asYmxEILY0z9nRfjVjWu0gyIPnMaUr1wCM4YSili8WD3CEjTnlX3Tmko754WCRJj
WOd7H/Dxm5P7MgAdXObuNavn9Ea1c0L+aF8c9/nzaT4PSk1hsiCaL9O4jHcWouoW
x+hzzUDwu+YapxlAXVaSmtJMhrqOMGHpfCb0haIawKp00HiOHhj6Wk4SNzHVnTGc
LInxTIM3AgMBAAECggEAW5J0jWGw8dPbBaWg5TOt4U3JSVdVxjW3LwW7BlJ8h54L
Ek+HnRAu6DgbY0JCNZubFVetFo0kjYu+5uV4/V2egib9/1URHYE2aKpai7IPIWSX
zVx9YojPlHijMHMxErk6r0Eba4qtmFCsY6i2C24EgJo0BBY+SUVmkvy6gyXXanov
yDpg29+T4ZHPvpZ/5zA9qJEwdUfaVmjVDulAL/KaqeOgBo+W7GvEoEj3QZa4FdhZ
Q8C796rug1bgOBOeKqItM07mjo51i0VjoToSYQKi9+7qkpJ4dMYJ8is/3EvfqlC7
A7mtMO76r4XhtkQOANoEftDn2kotFMPuaZPt0igO2QKBgQDtkOAKNdykDypV0sbO
Fcyj2i68JykOLR0VArT2/1syJxQI7FhJjYBrgQBQL9zwL2DkUlU9Nf7mq4AyzdSA
ySd7syXwFKjuycBdyeMLX1+U/rPAAZXxxXdqK7nowhnlUfz6ltLlqSxqnJik9HnJ
qwEgDYxN1Txk/5RgPyZhetQ9YwKBgQDHIHLgMko1ihcimMfnXWQvdHaKcD8WrsuA
lXFdTsbgaft4yO+JNLnou5pmWSWJdLwWS1MuEdS2P936/JGBGGSeyiwPmOiJehl5
Xp/EyQg7XvYF4Nc9wxEA5xH0+1gUIM5U4dNZKGFgzxTdew8lt3OrVLt4xp+q6QX2
hHkpHcjlHQKBgQCG2bLi+NoK4nTkjKW++87Sv5nBwfTjECau839nqWHJ4TbVLdub
vM/Ftk9INTMTv8EfOcEa4tiTdYxqyj2y8PwRkoqZchDGow0n796KaRPnjoDYH85O
lAmJ4dJA1lU+v8B7Ojvyk4ob5lIbaI7tM72KxUX8NGt45T8DNzWBJejuAwKBgQDF
dvo0Neq9WSlEF7n1R/m3zYhYFKObfM81vfzjiOFTXgYQa0KPD4hksNWWNUUyIF78
xMnB39DOwlsBMEGigWwWw2oaNYoz+q8UWq+ZV7ogFjVm8ua/ypcsC/kUtcNMgpPa
PO93dMHMXM7WK9iDkH7WInqedGmV9OsC4a+9BFpaSQKBgF0rLLiGRoHOtCJr4Lu1
8jdSUFr97wUleRnNA84jPp1FLTtTBfxQuqdcEbvzBpi1MNenNizMpltRs70b2Fcq
MAJg+g7yksp274mtrOA9u/uiOAiWiCwvtoTTEdhU/io4N2MlMk+4dJQCa0IyIDqU
lGroy6iP/vga3WK54fhlPnPH
-----END PRIVATE KEY-----`

func TestConfigJWT(t *testing.T) {
	pk, _ := jws.ParseRSAKey([]byte(testPK))
	// tests created from https://jwt.io
	tests := []tokenTest{
		{
			"HS256",
			jws.HS256([]byte("very secret")),
			"_LKcaN5imOf_S-hUoHNTqfZPIaupHpoaC5ska72gSWM",
			jws.HS256Verifier([]byte("very secret")),
		},
		{
			"HS384",
			jws.HS384([]byte("very secret")),
			"AN81XJrOu1S0nsZPvFiDjchNbSxXjtqmaK3MsyrU-RoioQt9zwY6f2XVYW74ohm2",
			jws.HS384Verifier([]byte("very secret")),
		},
		{
			"HS512",
			jws.HS512([]byte("very secret")),
			"JRV3jFJzZiBDwmJMDPuBur1_e5dUeF-3hQMRGlR9_YpgqPJtq32iI_yIx7FrqdGzXHln4R2Daf6Uh6DIh8Oe5g",
			jws.HS512Verifier([]byte("very secret")),
		},
		{
			"RS256",
			jws.RS256(pk, "my key"),
			"scBq-nq5YF48WLMpG9ibvQ0jplJnHKXIpoR6mJQq60I4Pt5jmpUjNQ3nlCa98AhXHZPb9BhueWxU1-GBRkhQ0y5-ktnUKS1R43UtgKhgp1roo2DDmVzkx4VhYHMvTy5JlixV_vv0vpBHfchMQaMSQGliUNgpOHqAzN79u5v6NeHVC-WXU5lnGYJUvUKV0ZWSJyxJ9mC4145bLuNTwr0yl0Vavr1wNw74mqswth-h3_ShUgKnXbjxSH4exqdH-WroTV8-hdtZprklTdBvub3BKvWWVigpanPTPjNceaveox5xujKtQdSNvKYatw-FI2Z4kuhABWGbTRIg-tmE3xEHeQ",
			jws.RS256Verifier(&pk.PublicKey),
		},
		{
			"RS384",
			jws.RS384(pk, "my key"),
			"fsOBT1n_t5GdFFgS2sqGVTMfSAeFSHgkT3Y-Z0kWchLr-c3YgS44h-MqTV-swyiyWcao6XN4NK0W_UfMyk0hH2ncixm-tgD-oTt12jfWxShchJJWflCx8e32PsyxGCoT9nGa6Fwa93cd0vOVVH3y0db6r1-M03yP2hIfzDeA7JfVvZhXO3881GMMDh-4hJm85ecaUT-f5mhlYVFSVWJ3iHXj5WYVRBvEgBssOW1KJd_RXVGuXX6r3w-LGD4KzfJa5DOqBB8BnHh2bu8NxyBSQz1p3JdEJTSNAuc_B-_Mu7uxBMbwa3-yhPFEarMIf_LWA42el7wf5_jXpsh0BEE6Nw",
			jws.RS384Verifier(&pk.PublicKey),
		},
		{
			"RS512",
			jws.RS512(pk, "my key"),
			"kTxlI8Uc9q4OpYO3CEpLTnMQ9WDyhOZgej5qmhN55_V0lC4RFSX3Inmv4Jl-ftLA_EwV11Q0V5mPPNX2vkuTIywJb83pomq-UnG2YQ7h5FV_-4VOEfqWnR_0DyZxrrDwh00J7OH7yq4Ec_FYWIv1QxB03LewZOJGQTL63YzUKWfCW3nzNnjNk9eLOawaNHQ-0Z0K8gZTFt0WFdBx8AlyrnoXRvjvx2FMT5FW_RJ7tVVbHYCznhQ3Y01TUbStizIIFHOno07mfwHg8sjXlNaU-hnivX4smnaLM4BrLBqRWl-qEKL-M-B8cosrxLciR_qWCza_Ond4qp4XKEJnNHkPCQ",
			jws.RS512Verifier(&pk.PublicKey),
		},
	}
	cs := &jws.ClaimSet{
		Issuer:   "ABCDEFG",
		Subject:  "Tom Jones",
		IssuedAt: 1516239022,
		Audience: "Audience",
	}
	for _, tv := range tests {
		tk, err := cs.JWT(tv.Signer)
		if err != nil {
			t.Errorf("claims.jwt (%s): %v", tv.Type, err)
			continue
		}
		parts := strings.Split(tk, ".")
		if len(parts) != 3 {
			t.Errorf("claims.jwt (%s): expected 3 part token; got %d parts", tv.Type, len(parts))
			continue
		}
		if tv.Signature != parts[2] {
			t.Errorf("claims.jwt (%s): wanted signature %s; got %s", tv.Type, tv.Signature, parts[2])
		}
		if err = jws.Verify(tk, tv.Verifier); err != nil {
			t.Errorf("claims.jwt (%s) verify error %v", tv.Type, err)
		}
	}

}
