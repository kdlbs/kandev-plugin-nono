package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/kandev/kandev/pkg/pluginsdk"
	"github.com/stretchr/testify/require"
)

func TestPinnedRuntimeEnforcesCompiledPolicy(t *testing.T)    { runPinnedRuntime(t, false) }
func TestPinnedRuntimeEnforcesProxyDestinations(t *testing.T) { runPinnedRuntime(t, true) }
func runPinnedRuntime(t *testing.T, withProxy bool) {
	t.Helper()
	binary := os.Getenv("NONO_ACCEPTANCE_BINARY")
	if binary == "" {
		t.Skip("set NONO_ACCEPTANCE_BINARY to the pinned executable")
	}
	content, err := os.ReadFile(binary)
	require.NoError(t, err)
	digest := sha256.Sum256(content)
	require.Equal(t, runtimeDigest, hex.EncodeToString(digest[:]))
	root := t.TempDir()
	work := filepath.Join(root, "work")
	require.NoError(t, os.Mkdir(work, 0700))
	outside := filepath.Join(root, "outside.txt")
	require.NoError(t, os.WriteFile(outside, []byte("outside-marker"), 0600))
	child := filepath.Join(root, "probe")
	build := exec.Command("go", "build", "-o", child, "./testdata/enforcement.go")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	output, err := build.CombinedOutput()
	require.NoError(t, err, string(output))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	callback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":"denied"}`))
	}))
	defer callback.Close()
	req := compileRequest(t)
	req.Policy.Grants.Filesystem = []*pluginsdk.SandboxFilesystemGrant{{Path: work, Writable: true}, {Path: child}}
	var forbiddenRequests atomic.Int32
	allowedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("permitted-destination")) }))
	defer allowedServer.Close()
	forbiddenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forbiddenRequests.Add(1)
		_, _ = w.Write([]byte("forbidden-destination"))
	}))
	defer forbiddenServer.Close()
	if withProxy {
		endpoint, err := url.Parse(allowedServer.URL)
		require.NoError(t, err)
		port, err := strconv.Atoi(endpoint.Port())
		require.NoError(t, err)
		req.Policy.Grants.Network = []*pluginsdk.SandboxNetworkGrant{{Host: endpoint.Hostname(), Port: uint32(port), Protocol: "tcp"}}
		req.Policy.Grants.KandevMcp = true
		req.Endpoints = []*pluginsdk.SandboxEndpoint{{Key: "kandev.mcp", Host: endpoint.Hostname(), Port: uint32(port), Scheme: "http", Path: "/mcp"}}
		grantRuntimeEnvDependencies(t, req)
	}
	response, err := (&nonoPlugin{}).CompileSandboxPolicy(context.Background(), req)
	require.NoError(t, err)
	var profile map[string]any
	require.NoError(t, json.Unmarshal([]byte(response.Compiled.Artifacts[0].ContentUtf8), &profile))
	profile["security"].(map[string]any)["approval_backends"].(map[string]any)["kandev"].(map[string]any)["url"] = callback.URL
	if withProxy {
		profile["network"].(map[string]any)["upstream_proxy"] = fixtureEgress(t, allowedServer.URL)
	}
	content, err = json.Marshal(profile)
	require.NoError(t, err)
	profilePath := filepath.Join(root, "profile.json")
	require.NoError(t, os.WriteFile(profilePath, content, 0600))
	args := []string{}
	for _, arg := range response.Compiled.Prefix[1:] {
		if arg.GetArtifactReference() != "" {
			args = append(args, profilePath)
		} else {
			args = append(args, arg.GetLiteral())
		}
	}
	args = append(args, child, work, outside, listener.Addr().String())
	if withProxy {
		args = append(args, allowedServer.URL, forbiddenServer.URL)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = work
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	cmd.Env = []string{"HOME=" + filepath.Join(root, "home"), "XDG_CONFIG_HOME=" + filepath.Join(root, "config"), "XDG_STATE_HOME=" + filepath.Join(root, "state"), "TMPDIR=" + filepath.Join(root, "tmp"), "PATH=/usr/bin:/bin", "FIXTURE_PRIVATE_VALUE=synthetic-secret"}
	if withProxy {
		envPath, err := exec.LookPath("env")
		require.NoError(t, err)
		cmd.Env = append(cmd.Env, "PATH="+filepath.Dir(envPath)+":/usr/bin:/bin")
	}
	for _, name := range []string{"home", "config", "state", "tmp"} {
		require.NoError(t, os.Mkdir(filepath.Join(root, name), 0700))
	}
	output, err = cmd.CombinedOutput()
	require.NoError(t, err, string(output))
	var results map[string]bool
	require.NoError(t, json.Unmarshal(output, &results), string(output))
	expected := map[string]bool{"allowed_write": true, "allowed_read": true, "denied_read": true, "denied_write": true, "implicit_read_removed": true, "denied_network": true, "secret_removed": true}
	if withProxy {
		expected["allowed_proxy"] = true
		expected["denied_proxy"] = true
		expected["proxy_bypass_removed"] = true
	}
	require.Equal(t, expected, results)
	require.Zero(t, forbiddenRequests.Load())
	audits, err := filepath.Glob(filepath.Join(root, "state", "nono", "audit", "*", "audit-events.ndjson"))
	require.NoError(t, err)
	require.Len(t, audits, 1)
	audit, err := os.ReadFile(audits[0])
	require.NoError(t, err)
	report, err := (&nonoPlugin{}).ReadSandboxReport(context.Background(), &pluginsdk.ReadSandboxReportRequest{Context: req.Context, Policy: req.Policy, Audit: audit})
	require.NoError(t, err)
	require.Equal(t, "partial", report.Integrity)
	require.False(t, report.Complete)
	require.GreaterOrEqual(t, len(report.Records), 2)

	require.NotContains(t, strings.ToLower(string(output)), "synthetic-secret")
	unchanged, err := os.ReadFile(outside)
	require.NoError(t, err)
	require.Equal(t, "outside-marker", string(unchanged))
}

func grantRuntimeEnvDependencies(t *testing.T, request *pluginsdk.CompileSandboxPolicyRequest) {
	t.Helper()
	envPath, err := exec.LookPath("env")
	require.NoError(t, err)
	canonical, err := filepath.EvalSymlinks(envPath)
	require.NoError(t, err)
	request.Policy.Grants.Filesystem = append(request.Policy.Grants.Filesystem, &pluginsdk.SandboxFilesystemGrant{Path: canonical})
	output, err := exec.Command("ldd", envPath).Output()
	require.NoError(t, err)
	for _, field := range strings.Fields(string(output)) {
		if !filepath.IsAbs(field) {
			continue
		}
		dependency, err := filepath.EvalSymlinks(field)
		require.NoError(t, err)
		request.Policy.Grants.Filesystem = append(request.Policy.Grants.Filesystem, &pluginsdk.SandboxFilesystemGrant{Path: dependency})
	}
}
