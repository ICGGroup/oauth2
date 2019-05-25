// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build appengine appenginevm

package google_test

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestAppEngineToken(t *testing.T) {
	cnt := 0
	dur := time.Duration(-10)
	appengineTokenFunc = func(ctx context.Context, scopes ...string) (string, time.Time, error) {
		cnt++
		return fmt.Sprintf("val%d", cnt), time.Now().Add(dur), nil
	}
	ctx := context.Background()
	ts := AppEngineTokenSource("scope2", "scope1")

	tk, err := ts.Token(ctx)
	if err != nil {
		t.Errorf("wanted nil error on Token(ctx); got %v", err)
	} else if tk.AccessToken != "val1" {
		t.Errorf("wanted \"val1\"; got %s", tk.AccessToken)
	}
	dur = time.Hour
	tk, err = ts.Token(ctx)
	if err != nil {
		t.Errorf("wanted nil error on Token(ctx); got %v", err)
	} else if tk.AccessToken != "val2" {
		t.Errorf("wanted \"val2\"; got %s", tk.AccessToken)
	}
	tk, err = ts.Token(ctx)
	if err != nil {
		t.Errorf("wanted nil error on Token(ctx); got %v", err)
	} else if tk.AccessToken != "val2" {
		t.Errorf("wanted \"val2\"; got %s", tk.AccessToken)
	}

}
