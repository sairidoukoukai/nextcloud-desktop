// SPDX-FileCopyrightText: 2026 Sairibus contributors
// SPDX-License-Identifier: Apache-2.0

package token

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestSairibusMetadataRetries(t *testing.T) {
	for _, failure := range []string{"server", "transport", "request-timeout"} {
		t.Run(failure, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != "HEAD" || r.Header.Get(accessMetadataReqHeader) != "true" {
					t.Error("metadata request contract changed")
				}
				if calls.Load() == 1 {
					switch failure {
					case "server":
						w.WriteHeader(503)
					case "transport":
						connection, _, _ := w.(http.Hijacker).Hijack()
						connection.Close()
					case "request-timeout":
						<-r.Context().Done()
					}
					return
				}
				w.Header().Set(accessMetadataRespHeader, "synthetic-metadata")
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			client := &http.Client{Timeout: 20 * time.Millisecond}
			value, err := fetchMetadataJWTContext(ctx, client, server.URL, time.Millisecond)
			if err != nil || value != "synthetic-metadata" || calls.Load() != 2 {
				t.Fatalf("metadata retry: calls=%d error=%v", calls.Load(), err)
			}
		})
	}
}

func TestSairibusMetadataPreservesValidation(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusFound, http.StatusForbidden} {
		var calls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.Header().Set("Location", "/other")
			w.WriteHeader(status)
		}))
		if _, err := fetchMetadataJWT(server.URL); err == nil || calls.Load() != 1 {
			t.Fatalf("missing metadata/redirect was accepted: status=%d calls=%d", status, calls.Load())
		}
		server.Close()
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(accessMetadataRespHeader, "malformed-metadata")
	}))
	defer server.Close()
	endpoint, _ := url.Parse(server.URL)
	if _, err := GetAppInfo(endpoint); err == nil {
		t.Fatal("malformed unsigned metadata accepted")
	}
}

func TestSairibusProductionMetadataSurvivesRequestTimeout(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			<-r.Context().Done()
			return
		}
		w.Header().Set(accessMetadataRespHeader, "synthetic-metadata")
	}))
	defer server.Close()
	value, err := fetchMetadataJWT(server.URL)
	if err != nil || value != "synthetic-metadata" || calls.Load() != 2 {
		t.Fatalf("metadata sign-in ended before its retry budget: %v", err)
	}
}

func TestSairibusProductionTransferSurvivesTenPendingPolls(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= 11 {
			w.WriteHeader(404)
			return
		}
		io.WriteString(w, "approved")
	}))
	defer server.Close()
	log := zerolog.Nop()
	body, _, err := transferRequest(server.URL, &log)
	if err != nil || string(body) != "approved" {
		t.Fatalf("transfer ended before browser approval: %v", err)
	}
}

func TestSairibusTransferWaitsForBrowser(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/transfer/same-capability" {
			t.Error("transfer capability changed while browser remained open")
		}
		if calls.Load() <= 15 {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("service-public-key", "same-key")
		io.WriteString(w, "synthetic-encrypted-token")
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	log := zerolog.Nop()
	body, key, err := transferRequestContext(ctx, server.Client(), server.URL+"/transfer/same-capability", &log, time.Millisecond)
	if err != nil || string(body) != "synthetic-encrypted-token" || key != "same-key" || calls.Load() != 16 {
		t.Fatalf("browser transfer failed after %d calls: %v", calls.Load(), err)
	}
}

func TestSairibusTransferRecoversFromFailures(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		switch calls.Load() {
		case 1:
			connection, _, _ := w.(http.Hijacker).Hijack()
			connection.Close()
		case 2:
			w.WriteHeader(503)
			io.WriteString(w, "private-error-body")
		case 3:
			w.Header().Set("Content-Length", "99")
			io.WriteString(w, "partial")
		default:
			io.WriteString(w, "recovered")
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	log := zerolog.Nop()
	body, _, err := transferRequestContext(ctx, server.Client(), server.URL, &log, time.Millisecond)
	if err != nil || string(body) != "recovered" || calls.Load() < 4 {
		t.Fatalf("transport/5xx/body retry failed after %d calls: %v", calls.Load(), err)
	}
}

func TestSairibusTransferRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, strings.Repeat("x", maximumTransferResponse+1))
	}))
	defer server.Close()
	log := zerolog.Nop()
	_, _, err := transferRequestContext(context.Background(), server.Client(), server.URL, &log, time.Millisecond)
	if !errors.Is(err, errTransferTooLarge) {
		t.Fatal("oversized transfer response was not rejected")
	}
}

func TestSairibusRetryDeadlines(t *testing.T) {
	for _, stage := range []string{"metadata-request", "transfer-request", "transfer-body", "pending", "backoff"} {
		t.Run(stage, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if stage == "pending" {
					w.WriteHeader(404)
					return
				}
				if stage == "transfer-body" {
					w.WriteHeader(200)
					w.(http.Flusher).Flush()
				}
				<-r.Context().Done()
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
			defer cancel()
			start := time.Now()
			log := zerolog.Nop()
			var err error
			switch stage {
			case "metadata-request":
				_, err = fetchMetadataJWTContext(ctx, server.Client(), server.URL, time.Millisecond)
			case "backoff":
				err = waitForLoginRetry(ctx, time.Minute)
			default:
				_, _, err = transferRequestContext(ctx, server.Client(), server.URL, &log, time.Millisecond)
			}
			if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
				t.Fatalf("deadline not honored: %v", err)
			}
		})
	}
}
