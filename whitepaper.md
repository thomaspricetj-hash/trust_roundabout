# Trust Roundabout – Zero Trust Multi-Lane Security Roundabout
## Whitepaper

**Version:** 0.1  
**Date:** 2026-11-23  
**Author:** Thomas

---

## 1. Overview

Trust Roundabout is a Zero Trust network-flow security model implemented as a circular, multi-lane verification system. Instead of a linear inspect → allow/deny firewall, entities orbit through concentric Trust Rings until sufficient evidence accumulates to grant deeper access.

The design is continuous, not binary. Trust is a score 0-100 with overlapping verification windows. Entities can move forward, stay circulating, drop back a ring, or be ejected to quarantine.

This mental model combines:
* Zero Trust
* Dynamic risk scoring
* Software-defined perimeters
* Behavioral analytics
* Adaptive access control
* Deceptive security with rotating false doors/keys and sandbox quarantine

## 2. Core Concept

### 2.1 Rings and Windows

| Ring | Focus | Window |
|------|-------|--------|
| Ring 1 | Protocol compliance | 0-25 |
| Ring 2 | Source reputation | 20-50 |
| Ring 3 | Behavioral analytics | 45-75 |
| Ring 4 | Identity & intent | 70-90 |
| Ring 5 | Resource authorization | 85-100 |

Windows overlap intentionally. Advancement requires trust score to reach the upper bound of the window minus tolerance. Adaptive lane sizing widens windows under load to avoid clogging.

### 2.2 Circular Feedback

Traditional: Inspect → Allow / Deny  
Roundabout: Inspect → Uncertain → Loop → Inspect Again → More Evidence

The circular path gives security tools time to develop confidence, ideal for slow-moving intrusions, credential abuse, bot behavior, lateral movement, and data exfiltration patterns.

## 3. Architecture

### 3.1 Entities
* `EntityType`: Packet, Flow, Session, Device
* `trust_score: f64` 0-100
* `ring: RingId`
* `resonance_signature`, `secondary_signature` – moving averages of trust with jitter
* `secret: [u8;32]` per-entity CSPRNG secret for HMAC challenge-response
* `suspicion_score`, `tagged`, `door_attempts`, `attempt_cooldown`, `last_attempt_tick`
* Bounded metadata with `MAX_ORIGIN_LEN`, `MAX_METADATA_ENTRIES`, `MAX_METADATA_VALUE_LEN`

### 3.2 TrustRing
* Window bounds, validator, adaptive sizing
* `doors: Vec<Door>` – 1 real + 2 false doors per ring
* `max_circulation_ticks` – ejection threshold
* `can_advance`, `should_drop_back`, `should_eject`

### 3.3 Door Model
* `is_real` flag
* Base frequency per ring, plus:
  * `rotation_offset` – random walk per tick
  * `slide_offset` + `slide_velocity` – sliding frequency axis with random reversal
  * Secondary key with independent rotation/slide
* Real doors drift slowly; false doors jump randomly
* Swarm mode tightens resonance tolerance and accelerates rotation

Dual-key resonance: primary and secondary signatures must both match door frequencies within tolerance.

### 3.4 HMAC Challenge-Response
Per-entity secret is used to compute HMAC-SHA256 over `entity.id || door.id || tick`. The first 4 bytes map to 0-100 and must be within `HMAC_TOLERANCE` of door frequency. Resonance alone is insufficient – secret-based verification prevents signature spoofing.

### 3.5 Validators
Pluggable trait `Validator`:
* ProtocolCompliance
* SourceReputation
* BehavioralAnalytics
* IdentityIntent
* ResourceAuthorization

Each evaluation nudges trust score stochastically.

## 4. Deception and Tracking

### 4.1 Rotating False Doors and False Keys
Doors rotate randomly with per-door offset that itself drifts randomly each tick. Doors also slide. Offsets are unpredictable, making pre-computation infeasible.

False door usage:
* Tags entity
* Increments suspicion
* Admin alert printed
* Entity moved to `Quarantine` sandbox
* Origin user recorded for correlation

### 4.2 Sandbox Quarantine
Quarantined entities remain active in a simulated environment:
* Fake progress messages mimicking real validation
* Signature continues to evolve
* Logging continues for origin tracking
* User is kept engaged while attribution is collected

### 4.3 Origin Correlation
* `origin_hits` map counts false door hits per origin user
* `origin_entity_count` enforces per-origin rate limit of 3 entities
* Auto-escalation at ≥3 false hits: all related entities quarantined, admin escalation logged
* Maps capped at `MAX_ORIGINS` with pruning

## 5. Swarm and Adaptive Defenses

* `false_hits_this_tick` counter
* Swarm threshold = 5 hits/tick → activates `swarm_mode`
* Swarm mode: tighter resonance tolerance, faster door rotation, longer cooldowns
* Cooldown 20 ticks, auto-deactivates
* Per-entity attempt rate limiting and exponential backoff
* Maximum circulation time and automatic ejection to quarantine

## 6. Hardening and Safety

* `#![forbid(unsafe_code)]`
* CSPRNG via `rand::rng()`, per-entity secret via `RngCore::fill_bytes`
* Global admission control `max_entities = 100`
* Checked/saturating arithmetic for all counters
* Safe ring indexing via `as_ring_index()` – no unsafe casts
* Bounded metadata length and entry count
* Explicit bounds checks before vector access
* Rust memory safety prevents buffer overflows; defense-in-depth with explicit limits

## 7. Threat Model and Mitigations

| Threat | Mitigation |
|--------|------------|
| Brute force door guessing | Rotating + sliding doors, random offsets, dual-key resonance, HMAC gate, per-entity attempt backoff |
| False door/key abuse | Tagging, admin alert, sandbox quarantine, origin correlation escalation |
| Swarm / DDoS | Swarm detection, tighter tolerance, faster rotation, admission control, origin rate limit |
| Slow-moving intrusion | Continuous trust scoring, overlapping windows, behavioral validator, circulation loop |
| Credential abuse | Identity & intent validator, secondary key, HMAC challenge |
| Metadata injection / DoS | Bounded metadata length/entries, origin map pruning |
| Buffer overflow | Rust safety, no unsafe code, explicit bounds |

### 7.1 VPN Resilience
Network fingerprint and network risk scoring are tracked per entity. High-risk network profiles are penalized in Ring 2 Source Reputation, raising suspicion. Simulated VPN hops randomly change `network_fingerprint` for high-risk entities, triggering `[VPN HOP DETECTED]` logs and suspicion escalation. This makes VPN use observable as behavioral change, not just IP change, and ties it to HMAC-bound identity.

### 7.2 Attacker Weak Points Addressed
* Ring index cast overflow → safe `Option<usize>` mapping
* Counter overflow → saturating arithmetic
* Unbounded maps → `MAX_ORIGINS` pruning
* Pure numeric resonance → HMAC secret binding
* Timing fingerprint → jittered sandbox logs
* Priority abuse → limited evaluations, backoff

### 7.3 Local Admin-Only Full Access
Only entities with origin `local_admin` – representing an on-site host terminal admin – bypass read-only enforcement. All remote entities are confined to read-only and cannot execute code. The simulation enforces `read_only` flag on quarantine, suspicion, and false-door tagging, with explicit exemption for `LOCAL_ADMIN_ORIGIN`. Admin access is logged and requires physical presence, preventing remote privilege escalation.

## 8. Attack Simulation Test Suite

`tests/attack_simulation.rs` validates design under adversarial load:
* Swarm attack triggers mitigation
* False door probing tags and sandboxes
* Brute-force door attempts hit backoff
* Origin correlation escalation works
* HMAC gate blocks fake resonance

All tests pass with `cargo test --test attack_simulation`.

## 9. Engineering Challenges

* Preventing roundabout clogging → adaptive window sizing, max circulation time, priority lanes
* Preventing attacker from intentionally clogging → max entities, per-origin rate limit, swarm mode
* Prediction resistance → rotating offsets + sliding velocity reversal + random drift
* Deception fidelity → sandbox simulates real system messages to retain attacker engagement

## 10. Future Enhancements

* Real network hooks and packet capture integration
* Persistent state with encrypted storage
* Metrics export Prometheus / Grafana
* Pluggable validators via WASM
* Signed origin claims and attestation
* Constant-time HMAC comparison
* Distributed roundabout with consensus

## 11. License

MIT License – see LICENSE.md

---

*Trust Roundabout is a conceptual model for implementing Zero Trust at the network-flow level. The Rust simulation demonstrates the mechanics of circular verification, deceptive doors, and adaptive trust scoring.*
