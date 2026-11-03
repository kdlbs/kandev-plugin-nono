package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func runWithProxyPortCollision(t *testing.T, cmd *exec.Cmd) ([]byte, error) {
	t.Helper()
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	require.NoError(t, cmd.Start())
	waited := false
	defer func() {
		_ = stdin.Close()
		if !waited {
			_ = cmd.Cancel()
			_ = cmd.Wait()
		}
	}()
	reader := bufio.NewReader(stdout)
	line, err := reader.ReadBytes('\n')
	require.NoError(t, err)
	var ready struct {
		ProxyPort string `json:"proxy_port"`
	}
	require.NoError(t, json.Unmarshal(line, &ready))
	require.NotEmpty(t, ready.ProxyPort)
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte("port-collision-probe"))
	}))
	require.NoError(t, server.Listener.Close())
	server.Listener, err = net.Listen("tcp", net.JoinHostPort("127.0.0.2", ready.ProxyPort))
	require.NoError(t, err)
	server.Start()
	defer server.Close()
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{}}
	defer client.CloseIdleConnections()
	response, err := client.Get(server.URL)
	require.NoError(t, err, "the host must reach the forbidden listener before the child probes it")
	data, err := io.ReadAll(response.Body)
	require.NoError(t, response.Body.Close())
	require.NoError(t, err)
	require.Equal(t, "port-collision-probe", string(data))
	requests.Store(0)
	require.NoError(t, json.NewEncoder(stdin).Encode(true))
	require.NoError(t, stdin.Close())
	output, readErr := io.ReadAll(reader)
	waitErr := cmd.Wait()
	waited = true
	require.NoError(t, readErr)
	require.Zero(t, requests.Load(), "an unapproved host service on the proxy port must receive no child requests")
	if waitErr != nil {
		output = append(output, stderr.Bytes()...)
	}
	return output, waitErr
}
