//go:build linux

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/kdlbs/kandev/pluginsdk"
	"github.com/stretchr/testify/require"
)

func TestPinnedRuntimeRefusesProxyWhenNamespacesAreUnavailable(t *testing.T) {
	binary := filepath.Join(nativeVerifierInstall(t), "runtime", "nono-linux-amd64")
	root := t.TempDir()
	helper := filepath.Join(root, "namespace-refusal")
	build := exec.Command("go", "build", "-trimpath", "-o", helper, "./testdata/namespace_refusal.go")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	output, err := build.CombinedOutput()
	require.NoError(t, err, string(output))
	callback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"decision":"denied"}`))
	}))
	defer callback.Close()
	for _, proxy := range []bool{false, true} {
		t.Run(map[bool]string{false: "blocked-network-control", true: "proxy-refusal"}[proxy], func(t *testing.T) {
			work := t.TempDir()
			request := compileRequest(t)
			request.Policy.Grants.Filesystem = []*pluginsdk.SandboxFilesystemGrant{{Path: work, Writable: true}, {Path: helper}}
			if proxy {
				request.Policy.Grants.Network = []*pluginsdk.SandboxNetworkGrant{{Host: "example.test", Port: 443, Protocol: "tcp"}}
			}
			response, err := (&nonoPlugin{}).CompileSandboxPolicy(t.Context(), request)
			require.NoError(t, err)
			var profile map[string]any
			require.NoError(t, json.Unmarshal([]byte(response.Compiled.Artifacts[0].ContentUtf8), &profile))
			profile["security"].(map[string]any)["approval_backends"].(map[string]any)["kandev"].(map[string]any)["url"] = callback.URL
			if proxy {
				profile["network"].(map[string]any)["upstream_proxy"] = "127.0.0.1:1"
			}
			content, err := json.Marshal(profile)
			require.NoError(t, err)
			profilePath := filepath.Join(t.TempDir(), "profile.json")
			require.NoError(t, os.WriteFile(profilePath, content, 0600))
			marker := filepath.Join(work, "marker")
			args := []string{binary, "run", "--silent", "--profile", profilePath, "--", helper, "child", marker}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, helper, args...)
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
			cmd.WaitDelay = time.Second
			cmd.Dir = work
			privateState := t.TempDir()
			cmd.Env = []string{"HOME=" + privateState, "XDG_STATE_HOME=" + privateState, "XDG_CONFIG_HOME=" + privateState, "PATH=/usr/bin:/bin"}
			output, err := cmd.CombinedOutput()
			if proxy {
				require.Error(t, err)
				require.Contains(t, string(output), "namespace isolation (net) is not available")
				require.NoFileExists(t, marker, "unavailable isolation must not launch an unconfined child")
			} else {
				require.NoError(t, err, string(output))
				require.FileExists(t, marker, "denying unshare must still permit the blocked-network control")
			}
		})
	}
}
