package main

import (
	"encoding/json"
	"github.com/kandev/kandev/pkg/pluginsdk"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
)

func TestCompileBindsOnlyGrantedAgentDirectories(t *testing.T) {
	req := compileRequest(t)
	home := req.Policy.Grants.Filesystem[0].Path
	req.References = []*pluginsdk.SandboxRuntimeReference{
		{Key: "sandbox.child.home", Value: home},
		{Key: "sandbox.child.config", Value: filepath.Join(home, ".config")},
		{Key: "sandbox.child.state", Value: filepath.Join(home, ".local-state")},
		{Key: "sandbox.child.tmp", Value: filepath.Join(home, ".tmp")},
	}
	compiled, err := (&nonoPlugin{}).CompileSandboxPolicy(t.Context(), req)
	require.NoError(t, err)
	var profile struct {
		Environment struct {
			AllowVars []string          `json:"allow_vars"`
			SetVars   map[string]string `json:"set_vars"`
		}
	}
	require.NoError(t, json.Unmarshal([]byte(compiled.Compiled.Artifacts[0].ContentUtf8), &profile))
	require.Equal(t, map[string]string{"HOME": "", "XDG_CONFIG_HOME": "", "XDG_STATE_HOME": "", "TMPDIR": ""}, profile.Environment.SetVars)
	for _, name := range []string{"HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "TMPDIR"} {
		require.NotContains(t, profile.Environment.AllowVars, name)
	}
	require.Len(t, compiled.Compiled.Artifacts[0].Bindings, 5)
	for _, mutate := range []func(){
		func() { req.References[0].Value = filepath.Dir(home) },
		func() { req.References = req.References[:3] },
	} {
		mutate()
		_, err = (&nonoPlugin{}).CompileSandboxPolicy(t.Context(), req)
		require.Error(t, err)
	}
}
