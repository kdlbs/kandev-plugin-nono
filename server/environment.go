package main

import (
	"slices"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func childEnvironmentKeys(approved []string) ([]string, error) {
	keys := []string{"PATH", "LANG", "LC_ALL", "TERM", "COLORTERM", "TZ"}
	if len(approved) > 128 {
		return nil, status.Error(codes.InvalidArgument, "too many sandbox environment keys")
	}
	for _, key := range approved {
		if !validCredentialKey(key) {
			return nil, status.Error(codes.InvalidArgument, "unsupported sandbox environment key")
		}
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return slices.Compact(keys), nil
}

func validCredentialKey(key string) bool {
	if key == "" || len(key) > 128 {
		return false
	}
	for i, char := range key {
		if char != '_' && !(char >= 'A' && char <= 'Z') && !(i > 0 && char >= '0' && char <= '9') {
			return false
		}
	}
	for _, prefix := range []string{"NONO_", "KANDEV_", "LD_", "DYLD_", "XDG_", "GIT_CONFIG_"} {
		if strings.HasPrefix(key, prefix) {
			return false
		}
	}
	return !slices.Contains([]string{"HOME", "TMPDIR", "TMP", "TEMP", "PATH", "BASH_ENV", "ENV", "NODE_OPTIONS", "PYTHONPATH", "PYTHONHOME", "RUBYOPT", "PERL5OPT", "SHELLOPTS", "BASHOPTS"}, key)
}
