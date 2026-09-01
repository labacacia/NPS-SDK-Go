# NPS Go SDK module-path compatibility decision

Status: accepted
Decision: EPIC-005-COMPAT-008
Date: 2026-09-01
Owner: NPS Go SDK maintainers

## Context

The canonical repository is `labacacia/NPS-SDK-Go`, while the published Go
module is `github.com/labacacia/NPS-sdk-go`. Go module and import paths are
case-sensitive identities embedded in downstream `go.mod` files and source
imports; a GitHub repository redirect does not change that module identity.

At decision time the public Go Proxy contains versions through
`v1.0.0-alpha.18`, and this repository contains 94 imports using the published
path. The casing difference is therefore a live package contract, not stale
repository metadata.

## Decision

- Repository links, clone commands and provenance use
  `labacacia/NPS-SDK-Go`.
- The v1 module declaration and all package imports remain
  `github.com/labacacia/NPS-sdk-go`.
- New v1 packages continue using the existing module path. Do not mix both
  casing forms inside one module graph.
- A future canonical-cased module would be a separately versioned module
  migration, not a repository rename cleanup.

## Alternatives considered

1. Change `go.mod` and imports to `NPS-SDK-Go` now — rejected because existing
   versions and downstream module graphs would resolve as a different module.
2. Publish both casing variants for v1 — rejected because it creates duplicate
   package identities and type incompatibility risks.
3. Retain the published module while canonicalizing repository metadata —
   accepted.

## Consequences and removal gate

Documentation must distinguish the canonical repository name from the exact Go
module coordinate. Any future move requires a new module/version strategy,
downstream consumer inventory, migration tooling, proxy validation, cross-path
compatibility tests, a published support window and rollback guidance.

The v1 module path has no scheduled removal date.
