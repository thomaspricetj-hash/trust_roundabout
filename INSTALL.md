# Trust Roundabout - Pre-Installation Checklist

This document lists everything that must be in place before you install Trust Roundabout in a corporate environment.

## System Requirements

### Operating System
* Linux: Ubuntu 22.04+, Debian 12+, RHEL 9+, or any systemd-based distro
* Windows: Windows 10/Server 2019+ PowerShell 5.1+
* Docker: Any OS with Docker Engine 24+

### Hardware
* Minimum: 2 CPU cores, 4 GB RAM, 10 GB disk
* Recommended: 4+ CPU cores, 8 GB RAM, SSD storage for logs
* Production: Dedicated host or container with isolated network tap

### Software Dependencies

#### Rust native install
* Rust 1.70+ `rustc --version`
* Cargo bundled with Rust
* `toml` crate dependencies – offline build requires Cargo.lock present

#### Docker install
* Docker Engine 24+ `docker --version`
* Docker Compose v2 `docker compose version`
* No Rust toolchain needed on host

#### Linux systemd install
* systemd enabled
* sudo privileges for service installation
* `useradd` and `systemctl` available

#### Windows install
* PowerShell 5.1+ run as Administrator
* Optional: NSSM for Windows Service alternative
* Internet access for rustup initial download

## Network Prerequisites

* Management network access for admin console
* Optional: Mirror/SPAN port or eBPF-capable kernel for real traffic ingestion
* SIEM webhook endpoint if you want alerts forwarded
* Outbound HTTPS 443 for Docker image pulls

## Security Prerequisites

* Dedicated service account `trustroundabout` with no login shell
* Log directory writable: `/var/log/trust_roundabout` on Linux, `C:\ProgramData\TrustRoundabout\logs` on Windows
* Config file permissions: readable by service user only, `chmod 600 config.toml`
* Firewall rules: Trust Roundabout runs beside existing firewall; do not block loopback
* For production hardening:
  * HSM or KMS for secret management
  * WORM storage for AuditLog
  * SIEM integration for immutable alerting

## Mandatory Configuration Before Install

Create `config.toml` from `config.toml.example` and set at minimum:

* `firewall.block_geo` – ISO country codes to block, e.g. `["CN","RU"]`
* `firewall.max_per_tick` – rate limit per origin, default 1000
* `firewall.allow_ports` – leave `[]` for permissive, or list allowed ports
* `firewall.allow_protocols` – leave `[]` for permissive, or list `tcp`/`udp`
* `audit.log_path` – writable log path for audit chain
* `audit.siem_webhook` – URL for SIEM alerts, or empty string to disable
* `simulation.ticks` – demo length, increase for longer runs
* `simulation.entities_*` – entity counts for demo mode

Permissions: `chmod 600 config.toml` and ensure service user can read it.

## Pre-Install Steps

1. Review `config.toml.example`
2. Decide deployment mode: Docker, systemd, or native binary
3. Prepare config:
   * Set `firewall.block_geo` for your threat model
   * Leave `allow_ports`/`allow_protocols` empty for permissive start, then tighten
   * Configure `audit.siem_webhook` if using SIEM
4. Create backup of existing firewall rules
5. Allocate disk for logs: simulation generates ~10 MB/hour at default tick rate
6. Ensure host time is NTP synchronized for audit log integrity
7. Review `docs/SECURITY.md` for hardening checklist

## Post-Install Verification

* `cargo test --offline` passes
* `docker compose up -d` shows healthy container
* `systemctl status trust-roundabout` active
* `cargo run` prints simulation stats without firewall drops
* Admin alerts appear in logs when false door test is performed

## Support

* See `README.md` for quick start
* See `docs/DEPLOYMENT.md` for production wiring
* See `whitepaper.md` for design rationale
