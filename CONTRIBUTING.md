# Contributing to lex-internet

Thanks for taking a look at the project.

Small changes are much easier to review than broad rewrites. The codebase tries to stay portable and dependency-light, so if you want to make a bigger change, open an issue first and talk through the shape of it.

## Good Places To Start

- Add or expand `*_test.go` coverage in `pkg/`
- Improve protocol correctness with RFC references and edge-case handling
- Tighten CLI help text, examples, and README sections
- Improve Windows support and privileged-tool documentation
- Add benchmarks, fuzz tests, or packet fixtures for parsers

## Development Setup

You will need:

- Go 1.22+
- `make`
- A C toolchain for `c/`

This is the normal validation loop:

```bash
make fmt
make test
go vet ./...
make verify
```

Notes:

- Raw socket tools such as `ping`, `traceroute`, and `arp-tool` require elevated privileges when run manually.
- Routine checks should not require root or Administrator unless the change is integration-only and clearly documented.

## Change Expectations

- Keep Go packages standard-library only unless a dependency is discussed first.
- Preserve cross-platform behavior. If a command needs OS-specific handling, mirror the existing `*_unix.go` and `*_windows.go` split where appropriate.
- Prefer focused pull requests over broad refactors.
- Update `README.md`, examples, or CLI help when changing user-facing behavior.
- Add or update tests when changing behavior, parsing logic, or protocol handling.
- If a protocol change is based on an RFC or packet capture, mention that in the PR description.

## Pull Request Checklist

Before opening a PR, make sure you have:

- Run `make fmt`
- Run `make test`
- Run `go vet ./...`
- Run `make verify` if your change affects build output or the C library
- Updated docs and examples for any user-visible change
- Documented any platform-specific limitation or privileged runtime requirement

## Review Notes

In the PR description, say:

- What changed
- Why it changed
- How it was validated
- Any known limitations or follow-up work

If the scope is fuzzy, open an issue first. That usually saves time on both sides.
