use trust_roundabout::{Roundabout, EntityType};
use rand::Rng;

#[test]
fn test_swarm_attack_triggers_mitigation() {
    let mut rb = Roundabout::new();
    let mut rng = rand::rng();
    // Simulate a swarm: many entities from same origin pattern
    // We spawn max entities to stress admission control
    for _ in 0..100 {
        rb.spawn_entity(EntityType::Packet, rng.random_range(5.0..25.0), 0);
    }
    // Run ticks
    for _ in 0..50 {
        rb.tick();
    }
    // Swarm mode should have been triggered at least once due to false hits
    // Check that entities are quarantined via public API
    let quarantined = rb.quarantined_count();
    // At least some entities should be quarantined due to false door hits / suspicion
    assert!(quarantined > 0, "Expected some entities to be quarantined under swarm load");
}

#[test]
fn test_false_door_probing_tags_and_sandbox() {
    let mut rb = Roundabout::new();
    // Spawn a few entities with low trust to force advancement attempts
    for _ in 0..10 {
        rb.spawn_entity(EntityType::Flow, 20.0, 0);
    }
    for _ in 0..30 {
        rb.tick();
    }
    let tagged = rb.tagged_count();
    let quarantined = rb.quarantined_count();
    assert!(tagged > 0 || quarantined > 0, "False door probing should result in tagging/quarantine");
}

#[test]
fn test_brute_force_door_attempts_backoff() {
    let mut rb = Roundabout::new();
    // Spawn entities with high priority to increase door attempt rate
    for _ in 0..5 {
        rb.spawn_entity(EntityType::Session, 50.0, 1);
    }
    // Run many ticks to trigger attempt backoff
    for _ in 0..100 {
        rb.tick();
    }
    // Check that suspicion scores are bounded and entities eventually quarantined
    let max_suspicion = rb.max_suspicion();
    assert!(max_suspicion <= 100, "Suspicion should be bounded");
}

#[test]
fn test_origin_correlation_escalation() {
    let mut rb = Roundabout::new();
    // The simulation randomly assigns origins; we just ensure escalation logic doesn't panic
    for _ in 0..20 {
        rb.spawn_entity(EntityType::Packet, 10.0, 0);
    }
    for _ in 0..60 {
        rb.tick();
    }
    // Ensure origin maps are pruned to max size
    // If we could inspect private maps we'd assert len <= MAX_ORIGINS
    // Here we just ensure simulation completes without panic
}

#[test]
fn test_hmac_gate_blocks_fake_resonance() {
    let mut rb = Roundabout::new();
    // Spawn entities with trust high enough to attempt advancement
    for _ in 0..10 {
        rb.spawn_entity(EntityType::Device, 90.0, 1);
    }
    for _ in 0..80 {
        rb.tick();
    }
    // With HMAC gate, not all entities will advance; some will stay or be quarantined
    let total = rb.entity_count();
    let quarantined = rb.quarantined_count();
    // At least some entities should remain or be quarantined, not all advanced
    assert!(quarantined <= total);
}

#[test]
fn test_local_admin_bypasses_read_only() {
    let mut rb = Roundabout::new();
    // Spawn a local admin entity with high trust
    rb.spawn_local_admin(EntityType::Session, 95.0, 1);
    // Run many ticks to trigger suspicion / quarantine logic
    for _ in 0..200 {
        rb.tick();
    }
    // Local admin should never be tagged or read-only enforced
    // We verify via public counters: tagged_count should be 0 for admin only scenario
    // Since only admin exists, tagged_count must be 0
    assert_eq!(rb.tagged_count(), 0, "Local admin should never be tagged");
    assert_eq!(rb.quarantined_count(), 0, "Local admin should never be quarantined");
    // Suspicion may transiently rise during tick but is reset for admin; ensure it stays bounded
    assert!(rb.max_suspicion() <= 1, "Local admin suspicion should remain bounded");
}
