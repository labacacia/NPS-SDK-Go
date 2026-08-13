English | [中文版](./CHANGELOG.cn.md)

# Changelog — Go SDK (`github.com/labacacia/NPS-sdk-go`)

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Until NPS reaches v1.0 stable, every repository in the suite is synchronized to the same pre-release version tag.

---

## [1.0.0-alpha.18] — Unreleased

### Added

- Added official stateful LLM context DTOs, a mutex-protected process store, and a net/http Action Server coordinator with owner scoping, CAS reservations, lifecycle actions, true asynchronous execution, cancellation, and all 19 shared conformance vectors.

### Changed

- Aligned unary request correlation, LLM usage accounting, strict stateful request validation, task ownership, and cancellation-safe reservation aborts across SDK families.
- Documented and enforced the Go 1.23 minimum language baseline while retaining a security-current build toolchain.

## [1.0.0-alpha.17] — 2026-08-02

### Added

- Port the reference server surface into the Go SDK: NCP native transport, NWP action/complex/memory nodes and bidirectional bridges, NIP CA services and full verification, NOP orchestration, daemon observability, and telemetry.
- Implement the shared NCP 0.11, NWP 0.20, NIP 0.13, NDP 0.12, and NOP 0.9
  portable profiles and language-neutral conformance fixtures.

### Changed

- Require Go 1.26.5 or newer so release builds include the current standard-library security fixes.
- Apply canonical `gofmt` formatting across the SDK.

## [1.0.0-alpha.16] — 2026-07-23

### Changed

- Suite-wide alpha.16 sync: aligned package metadata, current README/version banners, and conformance fixtures after alpha.15 was already published.

## [1.0.0-alpha.15] — 2026-06-28

### Changed

- Suite-wide alpha.15 sync: aligned package metadata, current README/version banners, distribution source trees, and release-prep notes with NPS-Dev.
- Carries the NCP Tier-3 BinaryVector, inbound NWP Bridge server hardening, NIP canonical trust/revoke, and NDP discovery canonical-form alignment delivered by the source-of-truth tree.

## [1.0.0-alpha.14] — 2026-06-26

### Added
- `nip.NipCaClient`: typed remote NIP CA client for discovery, CRL, agent/node registration, X.509 registration, renewal, revocation, and verification.
- `nwp.NwpNativeNodeServer`: native-mode NWP serving helper for dispatching QueryFrame/ActionFrame over an already established NCP stream.
- `conformance`: TC-N1/TC-N2 conformance catalog, manifest builder, and validator for CI/self-certification flows.

---

## [1.0.0-alpha.11] — 2026-05-28

### Added
- NOP saga compensation: DagNode.CompensateAction/CompensateParamsMapping, TaskFrame.CompensationPolicy, TaskStateCompensating/Compensated, CompensationPolicy constants (alpha.9 parity)
- NOP AggregateStrategyWeightedFirstK and MergeAll (alpha.11)
- NOP DelegateFrame.TargetClusterAnchor, AlignStreamFrame.AckSeq/NakSeq (alpha.11)
- NDP security profiles: constants + InMemoryRegistry.SecurityProfile enforcement (alpha.9 parity)
- NDP ephemeral TTL cap (60 s) in registry (alpha.9 parity)
- NDP AnnounceFrame alpha.9 fields: NodeRoles, ClusterAnchor, SpawnSpecRef, BridgeProtocols, ActivationMode, ActivationEndpoint
- NDP GraphFrame / GraphEdge redesigned to NPS-4 §5 topology snapshot format (alpha.11)
- NIP IdentReputationPolicyHint and IdentMetadata.ReputationPolicy (alpha.10 parity)
- NIP IdentFrame.OCSPStaple (alpha.11)
- NWP SubscribeFrame and NWM TrustAnchors field (alpha.11)

---

## [1.0.0-alpha.6] — 2026-05-12

### Changed

- Synchronized Go SDK source and package metadata with the suite-wide `1.0.0-alpha.6` release.
- Aligned NIP error/OID constants and removed the standalone NWP error-code surface that is no longer part of the active SDK API.

---

## [1.0.0-alpha.2] — 2026-04-19

### Changed

- Version bump to `1.0.0-alpha.2` for suite-wide synchronization. No functional changes beyond version alignment.
- 75 tests green.

### Covered modules

- core / ncp / nwp / nip / ndp / nop

---

## [1.0.0-alpha.1] — 2026-04-10

First public alpha as part of the NPS suite `v1.0.0-alpha.1` release.

[1.0.0-alpha.6]: https://github.com/LabAcacia/nps/releases/tag/v1.0.0-alpha.6
[1.0.0-alpha.2]: https://github.com/LabAcacia/nps/releases/tag/v1.0.0-alpha.2
[1.0.0-alpha.1]: https://github.com/LabAcacia/nps/releases/tag/v1.0.0-alpha.1
