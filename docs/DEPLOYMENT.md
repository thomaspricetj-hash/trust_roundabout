# Trust Roundabout – Production Deployment Guide

## Overview
Trust Roundabout is a Zero Trust multi-lane security simulation that can be wired into a real network as a behavioral trust layer behind a perimeter firewall.

## Architecture
```
[Perimeter Firewall] -> [Network Tap / eBPF] -> [Trust Roundabout Rust Engine] -> [SIEM/SOAR + Policy Enforcement]
                              |
                              v
                       [Audit Log / Immutable Store]
```

## Prerequisites
* Rust 1.70+
* Linux host for eBPF tap, or a packet mirror port
* Access to identity provider for attestation
* SIEM endpoint for logs

## Build
```bash
cd D:/network/trust_roundabout
cargo build --release
```

Binary: `target/release/trust_roundabout`

## Configuration
Create `config.toml`:
```toml
[firewall]
max_per_tick = 1000
allow_ports = [80,443,8080]
allow_protocols = ["tcp"]
block_geo = ["CN","RU"]

[roundabout]
max_entities = 10000
swarm_threshold = 5

[audit]
log_path = "/var/log/trust_roundabout/audit.log"
siem_webhook = "https://siem.example.com/ingest"
```

## Wiring up

### 1. Ingest real traffic
Replace synthetic spawner with a tap:
```rust
// src/network_tap.rs
pub trait NetworkTap {
    fn next_flow(&mut self) -> Option<Entity>;
}
```
Implement with eBPF/DPDK or use a mirrored port feeding a packet parser that creates `Entity` with metadata:
* `origin_user` – source identity
* `port`, `protocol`, `country` – for firewall checks
* `entity_type` – Packet/Flow/Session/Device

### 2. Firewall pre-filter
Use the built-in Firewall before roundabout:
```rust
let mut rb = Roundabout::new();
rb.firewall_allow_port(443);
rb.firewall_allow_protocol("tcp");
rb.firewall_block_geo("CN");
rb.firewall_block_origin("known_bad");
```

### 3. Trust evaluation loop
Run `rb.tick()` per interval e.g., 100ms. The engine updates trust scores, rotates/slides doors, checks dual-key resonance + HMAC, and emits events.

### 4. Policy enforcement
Map roundabout decisions to actions:
* `RingId::Core` – allow
* `RingId::Quarantine` – move to sandbox VLAN, enforce read-only
* `RingId::Ejected` – drop at firewall

Example:
```rust
if entity.ring == RingId::Quarantine {
    enforce_read_only(entity.id);
    siem.emit(event_json);
}
```

### 5. Audit log
`AuditLog` is append-only with hash chain. In production write to WORM storage:
```rust
audit.append(&format!("{} {}", timestamp, event));
```
Verify chain integrity on startup.

### 6. SIEM/SOAR integration
Implement `SiemSink`:
```rust
impl SiemSink for SplunkSink {
    fn emit(&self, json: &str) { /* POST to webhook */ }
}
```
All admin alerts, firewall drops, verification releases, and quarantine events are emitted.

### 7. Signed attestations
Use `Attestation` with HSM-backed HMAC:
```rust
let att = Attestation::sign(entity_id, claim, hsm_key);
```
Require attestations for high-value actions.

### 8. Local admin bypass
Only entities with `origin_user == "local_admin"` bypass read-only. Enforce via physical console + MFA, never over remote network.

### 9. Operations
* Start in monitoring mode: log decisions but don’t enforce.
* Tune `max_entities`, `swarm_threshold`, window sizes per environment.
* Review sandbox regularly for false positives; use verification recovery.
* Rotate logs, monitor audit chain integrity, run red team exercises.

## Example minimal integration
```rust
let mut rb = Roundabout::new();
rb.firewall_allow_port(443);
rb.firewall_allow_protocol("tcp");

// Ingest real flow
if let Some(entity) = tap.next_flow() {
    rb.spawn_entity(entity.entity_type, entity.initial_score, entity.priority);
}
rb.tick();
```

See `README.md` for run instructions and `whitepaper.md` for full design. Security hardening details in `docs/SECURITY.md`.
