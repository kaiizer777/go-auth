package config

import (
	"strings"

	"github.com/go-sql-driver/mysql"
)

// RedactMySQLDSN parses a MySQL DSN and masks the password and secret parameters.
// If the input is a valid MySQL DSN, it redacts cfg.Passwd and secret query parameters.
// If mysql.ParseDSN fails, it attempts to split on the last '@' before the network address.
func RedactMySQLDSN(rawDSN string) (string, bool) {
	if rawDSN == "" {
		return "", false
	}

	// Try standard mysql.ParseDSN first
	if cfg, err := mysql.ParseDSN(rawDSN); err == nil && (cfg.Passwd != "" || cfg.User != "") {
		if cfg.Passwd != "" {
			cfg.Passwd = "REDACTED"
		}
		for k := range cfg.Params {
			if isSecretParam(k) {
				cfg.Params[k] = "REDACTED"
			}
		}
		return cfg.FormatDSN(), true
	}

	// Fallback for partial/unparsed MySQL DSNs containing passwords with '@'
	// Split on the last '@' before the network address pattern: @tcp(...), @unix(...), @/
	if idx := findMySQLNetworkAddressPrefix(rawDSN); idx != -1 {
		userinfo := rawDSN[:idx]
		rest := rawDSN[idx:]
		if colonIdx := strings.Index(userinfo, ":"); colonIdx != -1 {
			user := userinfo[:colonIdx]
			return user + ":REDACTED" + rest, true
		}
	}

	return rawDSN, false
}

func findMySQLNetworkAddressPrefix(s string) int {
	idx := strings.Index(s, "@tcp(")
	if idx == -1 {
		idx = strings.Index(s, "@unix(")
	}
	if idx == -1 {
		idx = strings.Index(s, "@/")
	}
	return idx
}
