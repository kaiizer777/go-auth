package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRealIP(t *testing.T) {
	tests := []struct {
		name       string
		req        *http.Request
		remoteAddr string
		want       string
	}{
		{
			name:       "nil request",
			req:        nil,
			remoteAddr: "",
			want:       "",
		},
		{
			name:       "empty remote addr",
			remoteAddr: "",
			want:       "",
		},
		{
			name:       "ipv4 with port",
			remoteAddr: "192.168.1.100:54321",
			want:       "192.168.1.100",
		},
		{
			name:       "ipv6 with port and brackets",
			remoteAddr: "[2001:db8::1]:8080",
			want:       "2001:db8::1",
		},
		{
			name:       "localhost ipv4 with port",
			remoteAddr: "127.0.0.1:9000",
			want:       "127.0.0.1",
		},
		{
			name:       "localhost ipv6 with port",
			remoteAddr: "[::1]:12345",
			want:       "::1",
		},
		{
			name:       "raw ipv4 without port",
			remoteAddr: "192.168.1.1",
			want:       "192.168.1.1",
		},
		{
			name:       "raw ipv6 without port",
			remoteAddr: "2001:db8::1",
			want:       "2001:db8::1",
		},
		{
			name:       "whitespace trimmed fallback",
			remoteAddr: "   10.0.0.1   ",
			want:       "10.0.0.1",
		},
		{
			name:       "malformed address fallback",
			remoteAddr: "invalid-remote-addr:::foo",
			want:       "invalid-remote-addr:::foo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r *http.Request
			if tt.name == "nil request" {
				r = nil
			} else {
				r = httptest.NewRequest(http.MethodGet, "/", nil)
				r.RemoteAddr = tt.remoteAddr
			}

			got := realIP(r)
			if got != tt.want {
				t.Fatalf("realIP() = %q, want %q", got, tt.want)
			}
		})
	}
}
