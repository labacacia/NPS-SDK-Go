# Security Overview

Treat frames, manifests, certificates, URLs, and files as untrusted. Review bounds, goroutine lifetime, crypto, identity, dependencies, and logs.

## Review rules

- Validate external input and fail closed.
- Keep secrets out of source, fixtures, logs, and errors.
- Bound network, parser, file, memory, and concurrency work where applicable.
- Pin and review automation dependencies.
- Add focused tests for changed security behavior.
- Follow [SECURITY.md](../../SECURITY.md) for reports.
