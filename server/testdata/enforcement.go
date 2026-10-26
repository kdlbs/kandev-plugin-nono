// This executable runs only inside the real-runtime integration test.
package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

func main() {
	work, outside, address := os.Args[1], os.Args[2], os.Args[3]
	results := map[string]bool{}
	allowed := filepath.Join(work, "allowed.txt")
	results["allowed_write"] = os.WriteFile(allowed, []byte("permitted"), 0600) == nil
	data, err := os.ReadFile(allowed)
	results["allowed_read"] = err == nil && string(data) == "permitted"
	_, err = os.ReadFile(outside)
	results["denied_read"] = os.IsPermission(err)
	err = os.WriteFile(outside, []byte("forbidden"), 0600)
	results["denied_write"] = os.IsPermission(err)
	_, err = os.ReadFile("/etc/hosts")
	results["implicit_read_removed"] = os.IsPermission(err)
	conn, err := net.DialTimeout("tcp", address, time.Second)
	results["denied_network"] = err != nil
	if conn != nil {
		_ = conn.Close()
	}
	results["secret_removed"] = os.Getenv("FIXTURE_PRIVATE_VALUE") == ""
	if len(os.Args) > 5 {
		results["proxy_bypass_removed"] = os.Getenv("NO_PROXY") == "" && os.Getenv("no_proxy") == "" && os.Getenv("NONO_NO_PROXY") == ""
		proxy, err := url.Parse(os.Getenv("HTTP_PROXY"))
		if err == nil && proxy.Host != "" {
			client := http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}}
			response, err := client.Get(os.Args[4])
			if err == nil {
				data, _ := io.ReadAll(response.Body)
				_ = response.Body.Close()
				results["allowed_proxy"] = response.StatusCode == 200 && string(data) == "permitted-destination"
			}
			response, err = client.Get(os.Args[5])
			results["denied_proxy"] = err != nil
			if err == nil {
				results["denied_proxy"] = response.StatusCode == 403
				_ = response.Body.Close()
			}
		}
	}
	_ = json.NewEncoder(os.Stdout).Encode(results)
}
