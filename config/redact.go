package config

import (
	"strings"

	"github.com/go-sql-driver/mysql"
)

// RedactMySQLDSN parses a MySQL DSN and masks the password and secret parameters.
// If the input is a valid MySQL DSN without embedded '@' characters, it redacts cfg.Passwd and secret query parameters.
// If multiple '@' characters are present or mysql.ParseDSN fails, it attempts to split on the last '@' before the network address.
func RedactMySQLDSN(rawDSN string) (string, bool) {
	if rawDSN == "" {
		return "", false
	}

	// Try standard mysql.ParseDSN first when there are no extra '@' symbols that could be inside the password.
	if strings.Count(rawDSN, "@") <= 1 {
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
	}

	// Fallback for partial/unparsed MySQL DSNs containing passwords with '@'
	// Split on the last '@' before the network address pattern: @tcp(...), @unix(...), @/
	if idx := findMySQLNetworkAddressPrefix(rawDSN); idx != -1 {
		userinfo := rawDSN[:idx]
		rest := rawDSN[idx:]
		if colonIdx := strings.Index(userinfo, ":"); colonIdx != -1 {
			user := userinfo[:colonIdx]
			rest = redactDSNQueryParams(rest)
			return user + ":REDACTED" + rest, true
		}
	}

	return rawDSN, false
}

func redactDSNQueryParams(rest string) string {
	qIdx := strings.Index(rest, "?")
	if qIdx == -1 {
		return dsnSecretRegex.ReplaceAllString(rest, "${1}${2}REDACTED")
	}

	base := rest[:qIdx+1]
	rawQuery := rest[qIdx+1:]

	parts := strings.Split(rawQuery, "&")
	for i, part := range parts {
		subparts := strings.Split(part, ";")
		for j, sub := range subparts {
			if k, _, ok := strings.Cut(sub, "="); ok {
				if isSecretParam(k) {
					subparts[j] = k + "=REDACTED"
				}
			}
		}
		parts[i] = strings.Join(subparts, ";")
	}

	return base + strings.Join(parts, "&")
}

func findMySQLNetworkAddressPrefix(s string) int {
	searchStr := s
	if qIdx := strings.LastIndex(s, "?"); qIdx != -1 {
		if slashIdx := strings.LastIndex(s[:qIdx], "/"); slashIdx != -1 {
			searchStr = s[:qIdx]
		}
	}
	candidates := []string{"@tcp(", "@unix(", "@/"}
	maxIdx := -1
	for _, prefix := range candidates {
		if idx := strings.LastIndex(searchStr, prefix); idx > maxIdx {
			maxIdx = idx
		}
	}
	return maxIdx
}
