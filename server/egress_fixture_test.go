package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fixtureEgress models the required host CONNECT contract for provider-only tests.
// The host repository tests the production relay and packaged provider together.
func fixtureEgress(t *testing.T, destination string) string {
	t.Helper()
	target, err := url.Parse(destination)
	require.NoError(t, err)
	var mu sync.Mutex
	var owned []net.Conn
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != target.Host {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		upstream, e := net.DialTimeout("tcp", target.Host, time.Second)
		if e != nil {
			w.WriteHeader(502)
			return
		}
		defer func() { _ = upstream.Close() }()
		child, buffer, e := http.NewResponseController(w).Hijack()
		if e != nil {
			return
		}
		defer func() { _ = child.Close() }()
		mu.Lock()
		owned = append(owned, child, upstream)
		mu.Unlock()
		_, _ = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		if buffer.Flush() != nil {
			return
		}
		done := make(chan struct{})
		go func() { _, _ = io.Copy(upstream, buffer); _ = upstream.Close(); close(done) }()
		_, _ = io.Copy(child, upstream)
		_ = child.Close()
		<-done
	}))
	t.Cleanup(func() {
		mu.Lock()
		for _, conn := range owned {
			_ = conn.Close()
		}
		mu.Unlock()
		server.Close()
	})
	endpoint, err := url.Parse(server.URL)
	require.NoError(t, err)
	return endpoint.Host
}
