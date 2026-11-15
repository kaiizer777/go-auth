package handler

import (
	"net"
	"net/http"
	"strings"
)

// realIP extracts the remote client IP from r.RemoteAddr, stripping the port.
// Falls back to RemoteAddr if splitting fails. Direct connection IP is used for v1.
func realIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}
