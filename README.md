# Trust Roundabout

A multi-lane Zero Trust security simulation implementing a circular trust model with sliding verification windows.

**Design Summary (≤350 chars):** Trust Roundabout is a Zero Trust multi-lane security simulation with five concentric rings, sliding verification windows, rotating/sliding doors with false doors/keys, dual-key resonance, HMAC challenge-response, sandbox quarantine deception, origin tracking, swarm mitigation, VPN-resilient fingerprinting, and local-admin-only full access.

## Concept

Instead of a linear inspect → allow/deny firewall, traffic orbits through concentric **Trust Rings** until enough evidence accumulates to grant deeper access.

- **Ring 1** – Protocol compliance  [0-25]
- **Ring 2** – Source reputation     [20-50]
- **Ring 3** – Behavioral analytics  [45-75]
- **Ring 4** – Identity & intent     [70-90]
- **Ring 5** – Resource authorization [85-100]

Windows overlap intentionally. Trust is continuous, not binary.

Entities can:
- Move forward
- Stay circulating
- Drop back a ring
- Be ejected to quarantine

## Features

- Sliding verification windows with overlap
- Continuous trust scoring 0-100
- Adaptive lane sizing under load
- Priority lanes for trusted entities
- Maximum circulation time & automatic ejection
- Circular feedback: Inspect → Uncertain → Loop
- Rotating doors with false doors and false keys
- Doors and keys rotate randomly with per-door offset; offset itself drifts randomly each tick
- Doors also slide: frequency slides with velocity that reverses randomly, making prediction even harder
- Dual-key resonance: primary and secondary keys must both match door frequencies; complex pattern prevents single-key bypass
- Resonance-based real key: entity signature must resonate with real door frequency
- False door usage tags entity, tracks origin user, admin alert, and sandbox quarantine
- Sandbox simulates real system with fake progress messages to keep entity engaged for longer tracking
- Decoy files in sandbox: quarantined entities are offered fake sensitive files; download attempts are logged with origin location ping
- Read-only enforcement: tagged/quarantined entities have code execution blocked and access restricted to read-only; advancement while tagged still enforces read-only
- Local admin-only full access: only entities with origin `local_admin` from on-site host terminal bypass read-only enforcement and can obtain full write/execute access; all remote entities remain read-only
- Origin correlation tracking with auto-escalation: repeated false door hits from same origin trigger admin escalation and mass quarantine
- Swarm mitigation: detects bursts of false door hits, activates swarm mode with tighter resonance tolerance and faster door rotation, and logs swarm alerts
- HMAC-SHA256 challenge-response per entity secret for real door verification
- VPN-resilient design: network fingerprint tracking, VPN hop detection, network risk scoring in source reputation validator, suspicion escalation on fingerprint change
- Defense-in-depth hardening: `#![forbid(unsafe_code)]`, CSPRNG, per-entity secret, global admission control, per-origin rate limiting, bounded metadata length and entry count, checked/saturating arithmetic, safe ring indexing
- Buffer-overflow protection via Rust safety guarantees plus explicit bounds checks
- Unit tests for door rotation invariants, metadata bounds, origin rate limiting, and HMAC determinism

## Getting Started

### Prerequisites

* Rust 1.70+ installed
* `cargo`

```bash
rustup update
cargo --version
```

### Run the simulation

```bash
cd D:/network/trust_roundabout
cargo run
```

The simulation seeds 38 entities and runs 100 ticks, printing advancements, drops, admin alerts, sandbox activity and periodic stats.

### Run tests

Unit tests:
```bash
cargo test
```

Attack simulation integration tests:
```bash
cargo test --test attack_simulation
```

The attack suite simulates swarm bursts, false-door probing, brute-force door attempts, origin correlation escalation and HMAC gate effectiveness.

## Production Deployment for Corporations

### As a standalone security appliance

Build a release binary for deployment on-prem or in a private cloud:

```bash
cargo build --release
```

Binary is at `target/release/trust_roundabout`. Run as a daemon with systemd or Docker.

### Docker

```dockerfile
FROM rust:1.80 AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/trust_roundabout /usr/local/bin/
ENTRYPOINT ["trust_roundabout"]
```

### Integration points

* **Network tap / eBPF**: Replace the synthetic entity spawner with a packet/flow collector. Map flows to `EntityType::Flow` / `Packet` and feed trust updates from IDS, SIEM, and identity providers.
* **SIEM / SOAR**: Admin alerts for false door usage and origin escalation can be emitted as JSON over syslog, Kafka, or webhook to Splunk, Sentinel, etc.
* **Policy engine**: Validators can be replaced with real checks: TLS validation, JA3 fingerprinting, device posture, user risk score from Okta/Azure AD.
* **Metrics**: Expose Prometheus metrics for ring counts, quarantine size, swarm mode, suspicion scores. Add a metrics endpoint in production.
* **Persistence**: Store entity state and origin correlation in Postgres/Redis with encryption at rest. Use `serde` for snapshots.
* **High availability**: Run multiple roundabout instances behind a load balancer with shared state via Redis. Doors can be synchronized via a shared RNG seed.
* **Compliance**: All logging is structured; no unsafe code; HMAC secrets are per-entity and never logged.

### Operational recommendations

* Start in monitoring mode: allow traffic but log decisions.
* Tune `MAX_ENTITIES`, `MAX_ORIGINS`, swarm thresholds per environment.
* Use priority lanes for known-good services.
* Review sandbox quarantine regularly; export tagged entities for forensic analysis.
* Rotate logs and admin alerts to your SOC.

## Architecture

`src/main.rs`

- `Entity` – packet/flow/session/device with trust_score, ring, priority, resonance_signature
- `TrustRing` – window bounds, validator, adaptive sizing, doors
- `Door` – real vs false, rotating frequency, resonance check
- Tagging & admin alerts for false door/key usage with sandbox quarantine
- `Validator` trait – protocol, reputation, behavioral, identity, authorization
- `Roundabout` – simulation tick loop with door rotation

The simulation seeds 38 entities and runs 100 ticks, printing advancements, drops, and stats.

## Extend

See `whitepaper.md` for full design. Typical extensions:
* Real network hooks and packet capture integration
* Persistent state with encrypted storage
* Metrics export Prometheus/Grafana
* Pluggable validators via WASM
* Distributed roundabout with consensus

## License

MIT License – see [LICENSE.md](LICENSE.md).
