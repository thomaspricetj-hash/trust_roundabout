use trust_roundabout::{Roundabout, EntityType};
use rand::Rng;
use std::time::Duration;
use std::fs;

#[derive(serde::Deserialize)]
struct Config {
    firewall: FirewallConfig,
    simulation: SimulationConfig,
}

#[derive(serde::Deserialize)]
struct FirewallConfig {
    max_per_tick: usize,
    allow_ports: Vec<u16>,
    allow_protocols: Vec<String>,
    block_geo: Vec<String>,
}

#[derive(serde::Deserialize)]
struct SimulationConfig {
    ticks: u64,
    entities_packet: u32,
    entities_flow: u32,
    entities_session: u32,
    entities_device: u32,
}

fn main() {
    println!("Trust Roundabout - Zero Trust Multi-Lane Security Simulation");
    println!("==============================================================");
    
    let config_str = fs::read_to_string("config.toml").unwrap_or_default();
    let cfg: Config = toml::from_str(&config_str).unwrap_or_else(|_| {
        eprintln!("Failed to parse config.toml, using defaults");
        Config {
            firewall: FirewallConfig { max_per_tick: 1000, allow_ports: vec![], allow_protocols: vec![], block_geo: vec![] },
            simulation: SimulationConfig { ticks: 100, entities_packet: 20, entities_flow: 10, entities_session: 5, entities_device: 3 },
        }
    });

    let mut roundabout = Roundabout::new();

    // Apply firewall config
    for port in &cfg.firewall.allow_ports {
        roundabout.firewall_allow_port(*port);
    }
    for proto in &cfg.firewall.allow_protocols {
        roundabout.firewall_allow_protocol(proto);
    }
    for geo in &cfg.firewall.block_geo {
        roundabout.firewall_block_geo(geo);
    }

    let mut rng = rand::rng();
    for _ in 0..cfg.simulation.entities_packet {
        roundabout.spawn_entity(EntityType::Packet, rng.random_range(5.0..30.0), 0);
    }
    for _ in 0..cfg.simulation.entities_flow {
        roundabout.spawn_entity(EntityType::Flow, rng.random_range(15.0..45.0), 0);
    }
    for _ in 0..cfg.simulation.entities_session {
        roundabout.spawn_entity(EntityType::Session, rng.random_range(30.0..60.0), 1);
    }
    for _ in 0..cfg.simulation.entities_device {
        roundabout.spawn_entity(EntityType::Device, rng.random_range(50.0..80.0), 1);
    }
    // Demonstrate local admin-only full access
    roundabout.spawn_local_admin(EntityType::Session, 90.0, 1);

    for _ in 0..cfg.simulation.ticks {
        roundabout.tick();
        std::thread::sleep(Duration::from_millis(10));
    }

    println!("\nSimulation complete.");
    roundabout.print_stats();
}
