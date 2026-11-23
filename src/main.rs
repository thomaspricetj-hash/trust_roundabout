use trust_roundabout::{Roundabout, EntityType};
use rand::Rng;
use std::time::Duration;

fn main() {
    println!("Trust Roundabout - Zero Trust Multi-Lane Security Simulation");
    println!("==============================================================");
    
    let mut roundabout = Roundabout::new();

    let mut rng = rand::rng();
    for _ in 0..20 {
        roundabout.spawn_entity(EntityType::Packet, rng.random_range(5.0..30.0), 0);
    }
    for _ in 0..10 {
        roundabout.spawn_entity(EntityType::Flow, rng.random_range(15.0..45.0), 0);
    }
    for _ in 0..5 {
        roundabout.spawn_entity(EntityType::Session, rng.random_range(30.0..60.0), 1);
    }
    for _ in 0..3 {
        roundabout.spawn_entity(EntityType::Device, rng.random_range(50.0..80.0), 1);
    }

    for _ in 0..100 {
        roundabout.tick();
        std::thread::sleep(Duration::from_millis(10));
    }

    println!("\nSimulation complete.");
    roundabout.print_stats();
}
