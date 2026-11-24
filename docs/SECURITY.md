# Security Hardening Additions

This document tracks production hardening added to Trust Roundabout.

## Constant-time cryptography
* `const_time_eq` implemented for all secret comparisons to avoid timing side-channels.
* HMAC verification now uses constant-time compare for tag bytes.

## Secure key management
* Per-entity secret generated via `rand::rng().fill_bytes` – CSPRNG.
* Stub `HSMKeyProvider` interface defined for HSM-backed secret generation in production. Simulation uses in-memory secrets; production should route through PKCS#11/HSM.

## Signed attestations
* `Attestation` struct with HMAC-SHA256 signature over `entity_id || timestamp || claim`.
* Entities can present attestations for out-of-band verification.

## Immutable audit log
* `AuditLog` append-only with SHA-256 hash chain. Each entry links to previous hash for tamper evidence.
* All admin alerts, firewall drops, quarantine releases, and verification events are appended.
* `verify_chain()` stub for integrity verification. Production: store log in WORM storage / remote SIEM.

## SIEM / SOAR integration
* `SiemSink` trait with `emit(event_json)` implementation.
* Stub emitter prints JSON; production implementation ships to syslog, Kafka, Splunk, Sentinel, etc.
* Structured events include timestamp, entity_id, origin, ring, action, suspicion.

## eBPF / network tap integration
* `NetworkTap` trait defined for real packet/flow ingestion.
* Simulation uses synthetic spawner; production replaces `spawn_entity` with tap-derived events.

## Formal threat model
* See `whitepaper.md` §7 Threat Model and Mitigations.
* Additional controls: least privilege, separation of duties, rate limiting, origin correlation.

## Fuzzing & testing
* `cargo test` suite includes attack simulation tests.
* Recommended: add `cargo fuzz` targets for Door rotation, HMAC verification, metadata bounds.

## Red teaming
* Regular red team exercises should test:
  - False door probing at scale
  - Swarm attacks with VPN hops
  - Side-channel timing on HMAC
  - Firewall bypass via metadata spoofing

## Defense in depth
Perimeter firewall + Trust Roundabout behavioral layer + endpoint posture + Zero Trust identity + immutable audit log.

This is a simulation baseline. Production deployment requires hardening runtime, HSM, eBPF tap, signed attestations, and immutable SIEM storage.
