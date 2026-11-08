# go-auth Roadmap

This document outlines the implementation roadmap and scope for version 1 of `go-auth`.

| Feature | Status | Target | Notes |
| :--- | :--- | :--- | :--- |
| Email/Password Auth | Planned | v1 | Secure hashing (Argon2id/bcrypt), credential validation, and password reset flows |
| Session Management | Planned | v1 | Cookie-based sessions, rotation, revocation, and expiry management |
| CSRF Protection | Planned | v1 | Double-submit cookie / state token validation for state-changing endpoints |
| Rate Limiting (basic) | Planned | v1 | IP/key-based rate limiter for brute-force protection on auth endpoints |
| OAuth - Google | Planned | v1 | OAuth2 / OIDC authorization code flow with PKCE |
| OAuth - GitHub | Planned | v1 | GitHub OAuth2 flow with email retrieval fallback |
| OAuth - Apple | Planned | v1 | Apple Sign In flow with client secret JWT generation |
| OAuth - 4th provider (TBD) | Planned | v1 | Additional standard provider (e.g., Discord or Microsoft) |
| SQL Database Adapter | Planned | v1 | Standard SQL database adapter supporting PostgreSQL, MySQL, and SQLite |
| net/http Handler | Planned | v1 | Native `net/http` router and middleware integration |
| Documentation Site | Planned | v1 | Reference documentation, architectural guides, and usage examples |
