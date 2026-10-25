// SPDX-FileCopyrightText: 2026 Sairibus contributors
// SPDX-License-Identifier: Apache-2.0

package access

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudflare/cloudflared/carrier"
)

func TestSairibusTokenCheckRetriesSameRequest(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("cf-access-token") != "synthetic-token" || r.URL.RawQuery != "cloudflared_token_check=true" {
			t.Error("token-check identity changed during retry")
		}
		if calls.Add(1) == 1 {
			<-r.Context().Done()
			return
		}
		if calls.Load() == 2 {
			w.WriteHeader(503)
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req, _ := http.NewRequest("GET", server.URL+"?cloudflared_token_check=true", nil)
	req.Header.Set("cf-access-token", "synthetic-token")
	resp, err := tokenCheckRequest(ctx, &http.Client{Timeout: 20 * time.Millisecond}, req, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || calls.Load() != 3 {
		t.Fatalf("token check stopped early: status=%d calls=%d", resp.StatusCode, calls.Load())
	}
}

func TestSairibusTokenCheckNonServerResponseIsNotRetried(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(403)
	}))
	defer server.Close()
	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := tokenCheckRequest(context.Background(), server.Client(), req, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 403 || calls.Load() != 1 {
		t.Fatal("a non-server response was retried or changed")
	}
}

func TestSairibusTokenCheckPreservesAccessRedirect(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Location", "/cdn-cgi/access/login/test")
		w.WriteHeader(302)
	}))
	defer server.Close()
	req, _ := http.NewRequest("GET", server.URL, nil)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := tokenCheckRequest(context.Background(), client, req, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if calls.Load() != 1 || !carrier.IsAccessResponse(resp) {
		t.Fatal("Access login redirect was followed or lost its denial classification")
	}
}

func TestSairibusTokenCheckDeadline(t *testing.T) {
	for _, retryDelay := range []time.Duration{time.Millisecond, time.Minute} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if retryDelay == time.Minute {
				w.WriteHeader(503)
				return
			}
			<-r.Context().Done()
		}))
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
		req, _ := http.NewRequest("GET", server.URL, nil)
		start := time.Now()
		_, err := tokenCheckRequest(ctx, server.Client(), req, retryDelay)
		cancel()
		server.Close()
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
			t.Fatalf("token-check deadline not honored: %v", err)
		}
	}
}
