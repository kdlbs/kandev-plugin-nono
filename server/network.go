package main

import (
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/kandev/kandev/pkg/pluginsdk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func compileNetwork(grants *pluginsdk.SandboxGrants, endpoints []*pluginsdk.SandboxEndpoint) (map[string]any, error) {
	hosts := make([]string, 0, len(grants.Network)+len(endpoints))
	for _, grant := range grants.Network {
		if grant == nil || grant.Protocol != "tcp" || !validDestination(grant.Host, grant.Port) {
			return nil, status.Error(codes.InvalidArgument, "unsupported sandbox network destination")
		}
		hosts = append(hosts, net.JoinHostPort(grant.Host, strconv.Itoa(int(grant.Port))))
	}
	if err := appendMCPEndpoint(grants, endpoints, &hosts); err != nil {
		return nil, err
	}
	result := map[string]any{"block": len(hosts) == 0, "allow_domain": hosts, "credentials": []string{}}
	if len(hosts) > 0 {
		result["upstream_proxy"] = ""
	}
	return result, nil
}

func validDestination(host string, port uint32) bool {
	if port == 0 || port > 65535 || host == "" || host != strings.ToLower(host) || len(host) > 253 {
		return false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return !ip.IsUnspecified() && !ip.IsMulticast() && ip.Zone() == ""
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z') && !(char >= '0' && char <= '9') && char != '-' {
				return false
			}
		}
	}
	return true
}

func appendMCPEndpoint(grants *pluginsdk.SandboxGrants, endpoints []*pluginsdk.SandboxEndpoint, hosts *[]string) error {
	if !grants.KandevMcp {
		if len(endpoints) != 0 {
			return status.Error(codes.InvalidArgument, "sandbox endpoint has no logical grant")
		}
		return nil
	}
	if len(endpoints) != 1 {
		return status.Error(codes.FailedPrecondition, "sandbox MCP relay is unavailable")
	}
	endpoint := endpoints[0]
	if endpoint == nil || endpoint.Key != "kandev.mcp" || endpoint.Host != "127.0.0.1" || endpoint.Scheme != "http" || endpoint.Path != "/mcp" || !validDestination(endpoint.Host, endpoint.Port) {
		return status.Error(codes.InvalidArgument, "invalid sandbox MCP relay")
	}
	*hosts = append(*hosts, net.JoinHostPort(endpoint.Host, strconv.Itoa(int(endpoint.Port))))
	return nil
}
