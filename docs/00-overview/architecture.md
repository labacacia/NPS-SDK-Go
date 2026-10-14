# Architecture

## Purpose and lifecycle

Public Go release projection; canonical source is in NPS-Dev.

## Boundaries

core/ and internal/: primitives.

ncp/, ndp/, nip/, nop/, nwp/: protocols.

conformance/: evidence.

daemon/ and ca-server/: integration.

Keep responsibilities and dependency direction explicit. Do not add layers or cross-repository sources of truth without a concrete requirement. Record architecture-significant decisions under `docs/04-decisions/`.
