package main

import (
	"net/url"
	"path"
	"slices"
	"strings"
	"unicode"

	"github.com/kdlbs/kandev/pluginsdk"
)

func partialAuditEndpoint(upstream, route *string, method, target string) (*pluginsdk.SandboxHTTPEndpointV2, error) {
	if !slices.Contains([]string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}, method) {
		return nil, invalidAudit()
	}
	result := &pluginsdk.SandboxHTTPEndpointV2{Method: method}
	if route != nil && *route != "" {
		if !safeReportLabel(*route) {
			return nil, invalidAudit()
		}
		result.RouteId = *route
	}
	if upstream != nil {
		parsed, err := url.Parse(*upstream)
		if err != nil {
			return nil, invalidAudit()
		}
		if parsed.User == nil && (parsed.Scheme == "https" || parsed.Scheme == "http") && parsed.Host != "" && validDestination(strings.ToLower(parsed.Hostname()), endpointReportPort(parsed)) {
			result.Origin = parsed.Scheme + "://" + strings.ToLower(parsed.Host)
		}
	}
	target, _, _ = strings.Cut(target, "?")
	if target != "" && path.IsAbs(target) && path.Clean(target) == target && len(target) <= 4096 && !strings.ContainsAny(target, "%#<>\\") && !strings.ContainsFunc(target, unicode.IsControl) {
		result.Path = target
	}
	return result, nil
}

func endpointReportPort(value *url.URL) uint32 {
	if value.Port() == "" {
		if value.Scheme == "https" {
			return 443
		}
		return 80
	}
	port := uint32(0)
	for _, digit := range value.Port() {
		if digit < '0' || digit > '9' {
			return 0
		}
		port = port*10 + uint32(digit-'0')
		if port > 65535 {
			return 0
		}
	}
	return port
}
