# **Go-Auth** — A composable, modular authentication library for Go.

[![Go Reference](https://pkg.go.dev/badge/github.com/kaiizer777/go-auth.svg)](https://pkg.go.dev/github.com/kaiizer777/go-auth)
[![Go Report Card](https://goreportcard.com/badge/github.com/kaiizer777/go-auth)](https://goreportcard.com/report/github.com/kaiizer777/go-auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> [!WARNING]
> **Status: Early development —**
> APIs and interfaces are undergoing initial design and scaffolding.

---

## Project Structure

`go-auth` strictly enforces separation between the public API facade and internal subsystem logic.

```
go-auth/
├── goauth.go                         # Root facade (New, Config entrypoint only)
├── session/                          # Session lifecycle & cookie handling
├── crypto/                           # Hashing, token generation & constant-time crypto
├── schema/                           # Domain models & database schema types
├── oauth/                            # OAuth2 & OIDC core logic
│   └── providers/                    # Individual OAuth provider implementations
├── ratelimit/                        # Rate limiting interfaces & implementations
├── adapters/
│   └── sql/                          # SQL database adapter (Postgres, MySQL, SQLite)
├── plugins/
│   └── credential-password/          # Email/Password authentication plugin
├── examples/
│   └── basic-nethttp/                # Standard net/http integration example
└── docs/                             # Project documentation
```

### Why this layout?
1. **Zero Logic in Root**: The project root only contains `goauth.go`, serving as the clean public entry point. This eliminates package circular dependencies and prevents the root package from becoming an unmaintainable catch-all.
2. **Modular Subpackages**: Callers can import specific subsystems or plug custom implementations (e.g. custom database adapters or rate limiters) adhering to cleanly separated interfaces.

---

## Installation

```bash
# Coming soon
go get github.com/kaiizer777/go-auth
```

---

## Contributing

Please review [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines, code style, and architectural boundaries.
All contributors are expected to uphold the [Code of Conduct](CODE_OF_CONDUCT.md).

---

## License

This project is licensed under the [MIT License](LICENSE).
