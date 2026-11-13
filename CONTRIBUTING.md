# Contributing to go-auth

Thank you for contributing to `go-auth`!

## Architectural Rules (Strict)

[!IMPORTANT]
**No implementation logic in root.** Root contains only the public facade (`goauth.go`). All logic lives in subpackages. PRs that add non-facade `.go` files to root will be asked to relocate them.

- Package root is strictly reserved for the public facade and high-level configuration.
- Domain logic, cryptographic helpers, session handling, database adapters, and plugin modules must reside in their respective subpackages.

## Development Workflow

1. **Branching**:
   - Create a feature or fix branch from `main` (e.g. `feat/my-feature` or `fix/issue-description`).
   - Do not commit directly to `main`.

2. **Code Quality & Formatting**:
   - All Go code must be formatted using `gofmt`:
     ```bash
     gofmt -s -w .
     ```
   - Lint checks must pass cleanly with `golangci-lint`:
     ```bash
     golangci-lint run
     ```
   - Ensure all packages build cleanly:
     ```bash
     go build ./...
     ```
   - Ensure all tests pass:
     ```bash
     go test ./...
     ```

3. **Submitting a Pull Request**:
   - Write clear, concise commit messages.
   - Open a PR against `main` explaining the changes and linking relevant issues.
   - PRs must adhere to the architectural rule mentioned above.

## Code of Conduct

All contributors and participants are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md).

