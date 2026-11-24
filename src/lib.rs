#![forbid(unsafe_code)]
use rand::Rng;
use rand::RngCore;
use std::collections::HashMap;
use std::time::Instant;
use uuid::Uuid;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Immutable append-only audit log with hash chain for tamper evidence
#[derive(Debug, Default)]
pub struct AuditLog {
    entries: Vec<String>,
    last_hash: Vec<u8>,
}
impl AuditLog {
    pub fn append(&mut self, event: &str) {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&self.last_hash);
        hasher.update(event.as_bytes());
        let hash = hasher.finalize().to_vec();
        self.last_hash = hash.clone();
        self.entries.push(event.to_string());
    }
    pub fn verify_chain(&self) -> bool {
        // Simple verification stub - in production verify each link
        true
    }
}

/// Constant-time equality to avoid timing side-channels
fn const_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntityType {
    Packet,
    Flow,
    Session,
    Device,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RingId {
    Ring1,
    Ring2,
    Ring3,
    Ring4,
    Ring5,
    Core,
    Quarantine,
    Ejected,
}

impl RingId {
    pub fn as_ring_index(&self) -> Option<usize> {
        match self {
            RingId::Ring1 => Some(0),
            RingId::Ring2 => Some(1),
            RingId::Ring3 => Some(2),
            RingId::Ring4 => Some(3),
            RingId::Ring5 => Some(4),
            _ => None,
        }
    }
    pub fn next(&self) -> RingId {
        match self {
            RingId::Ring1 => RingId::Ring2,
            RingId::Ring2 => RingId::Ring3,
            RingId::Ring3 => RingId::Ring4,
            RingId::Ring4 => RingId::Ring5,
            RingId::Ring5 => RingId::Core,
            RingId::Core => RingId::Core,
            _ => *self,
        }
    }
    pub fn prev(&self) -> RingId {
        match self {
            RingId::Ring2 => RingId::Ring1,
            RingId::Ring3 => RingId::Ring2,
            RingId::Ring4 => RingId::Ring3,
            RingId::Ring5 => RingId::Ring4,
            RingId::Ring1 => RingId::Quarantine,
            _ => *self,
        }
    }
}

#[derive(Debug)]
pub struct Entity {
    id: Uuid,
    entity_type: EntityType,
    trust_score: f64,
    ring: RingId,
    last_update: Instant,
    circulation_ticks: u32,
    priority: u8,
    metadata: HashMap<String, String>,
    resonance_signature: f64,
    secondary_signature: f64,
    suspicion_score: u32,
    tagged: bool,
    secret: [u8; 32],
    door_attempts: u32,
    last_attempt_tick: u64,
    attempt_cooldown: u64,
    network_fingerprint: String,
    network_risk: f64,
    last_network_fingerprint: String,
    read_only: bool,
} 

pub const MAX_ORIGIN_LEN: usize = 64;
pub const MAX_METADATA_ENTRIES: usize = 16;
pub const MAX_METADATA_VALUE_LEN: usize = 256;
pub const MAX_ORIGINS: usize = 2000;
pub const SUSPICION_EJECT_THRESHOLD: u32 = 15;
pub const MAX_DOOR_ATTEMPTS_PER_TICK: u32 = 3;
pub const HMAC_TOLERANCE: u32 = 12;
pub const LOCAL_ADMIN_ORIGIN: &str = "local_admin";

impl Entity {
    pub fn new(entity_type: EntityType, initial_score: f64, priority: u8) -> Self {
        let now = Instant::now();
        let mut rng = rand::rng();
        let signature = rng.random_range(0.0..100.0);
        let secondary_signature = rng.random_range(0.0..100.0);
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        let mut metadata = HashMap::new();
        let origin_raw = format!("user_{}", rng.random_range(1000..9999));
        let origin = if origin_raw.len() > MAX_ORIGIN_LEN {
            origin_raw[..MAX_ORIGIN_LEN].to_string()
        } else {
            origin_raw
        };
        Self::insert_metadata_bounded(&mut metadata, "origin_user".to_string(), origin);
        let network_fingerprint = format!("fp_{}", rng.random_range(100000..999999));
        let network_risk = rng.random_range(0.0..1.0);
        Self {
            id: Uuid::new_v4(),
            entity_type,
            trust_score: initial_score.clamp(0.0, 100.0),
            ring: RingId::Ring1,
            last_update: now,
            circulation_ticks: 0,
            priority,
            metadata,
            resonance_signature: signature,
            secondary_signature,
            suspicion_score: 0,
            tagged: false,
            secret,
            door_attempts: 0,
            last_attempt_tick: 0,
            attempt_cooldown: 0,
            network_fingerprint: network_fingerprint.clone(),
            network_risk,
            last_network_fingerprint: network_fingerprint,
            read_only: false,
        }
    }

    pub fn new_with_origin(entity_type: EntityType, initial_score: f64, priority: u8, origin: &str) -> Self {
        let now = Instant::now();
        let mut rng = rand::rng();
        let signature = rng.random_range(0.0..100.0);
        let secondary_signature = rng.random_range(0.0..100.0);
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        let mut metadata = HashMap::new();
        let origin_str = if origin.len() > MAX_ORIGIN_LEN {
            origin[..MAX_ORIGIN_LEN].to_string()
        } else {
            origin.to_string()
        };
        Self::insert_metadata_bounded(&mut metadata, "origin_user".to_string(), origin_str);
        let network_fingerprint = format!("fp_{}", rng.random_range(100000..999999));
        let network_risk = rng.random_range(0.0..1.0);
        Self {
            id: Uuid::new_v4(),
            entity_type,
            trust_score: initial_score.clamp(0.0, 100.0),
            ring: RingId::Ring1,
            last_update: now,
            circulation_ticks: 0,
            priority,
            metadata,
            resonance_signature: signature,
            secondary_signature,
            suspicion_score: 0,
            tagged: false,
            secret,
            door_attempts: 0,
            last_attempt_tick: 0,
            attempt_cooldown: 0,
            network_fingerprint: network_fingerprint.clone(),
            network_risk,
            last_network_fingerprint: network_fingerprint,
            read_only: false,
        }
    }

    pub fn insert_metadata_bounded(map: &mut HashMap<String, String>, key: String, value: String) {
        if map.len() >= MAX_METADATA_ENTRIES {
            return;
        }
        let key = key.chars().take(128).collect::<String>();
        let value = if value.len() > MAX_METADATA_VALUE_LEN {
            value[..MAX_METADATA_VALUE_LEN].to_string()
        } else {
            value
        };
        map.insert(key, value);
    }

    pub fn hmac_challenge(&self, door_id: usize, tick: u64) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("valid secret length");
        mac.update(self.id.as_bytes());
        mac.update(&door_id.to_be_bytes());
        mac.update(&tick.to_be_bytes());
        let result = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    pub fn is_local_admin(&self) -> bool {
        self.metadata.get("origin_user").map_or(false, |o| o == LOCAL_ADMIN_ORIGIN)
    }
}

pub trait Validator {
    fn evaluate(&self, entity: &mut Entity) -> f64;
}

pub struct ProtocolCompliance;
impl Validator for ProtocolCompliance {
    fn evaluate(&self, entity: &mut Entity) -> f64 {
        let mut rng = rand::rng();
        let delta = if rng.random_bool(0.85) { 2.0 } else { -5.0 };
        entity.trust_score = (entity.trust_score + delta).clamp(0.0, 100.0);
        delta
    }
}

pub struct SourceReputation;
impl Validator for SourceReputation {
    fn evaluate(&self, entity: &mut Entity) -> f64 {
        let mut rng = rand::rng();
        let base = match entity.entity_type {
            EntityType::Device => 1.5,
            EntityType::Session => 1.0,
            _ => 0.5,
        };
        // VPN / network risk penalty: high network_risk reduces trust and raises suspicion
        let vpn_penalty = if entity.network_risk > 0.7 { -base * 2.0 } else { 0.0 };
        let delta = if rng.random_bool(0.7) { base * 3.0 } else { -base * 2.0 } + vpn_penalty;
        entity.trust_score = (entity.trust_score + delta).clamp(0.0, 100.0);
        if entity.network_risk > 0.7 {
            entity.suspicion_score = entity.suspicion_score.saturating_add(1);
        }
        delta
    }
}

pub struct BehavioralAnalytics;
impl Validator for BehavioralAnalytics {
    fn evaluate(&self, entity: &mut Entity) -> f64 {
        let mut rng = rand::rng();
        let drift = rng.random_range(-1.5..0.8);
        entity.trust_score = (entity.trust_score + drift).clamp(0.0, 100.0);
        drift
    }
}

pub struct IdentityIntent;
impl Validator for IdentityIntent {
    fn evaluate(&self, entity: &mut Entity) -> f64 {
        let mut rng = rand::rng();
        let delta = if rng.random_bool(0.6) { 4.0 } else { -3.0 };
        entity.trust_score = (entity.trust_score + delta).clamp(0.0, 100.0);
        delta
    }
}

pub struct ResourceAuthorization;
impl Validator for ResourceAuthorization {
    fn evaluate(&self, entity: &mut Entity) -> f64 {
        let mut rng = rand::rng();
        let delta = if rng.random_bool(0.55) { 5.0 } else { -6.0 };
        entity.trust_score = (entity.trust_score + delta).clamp(0.0, 100.0);
        delta
    }
}

#[derive(Debug, Clone)]
pub struct Door {
    id: usize,
    is_real: bool,
    base_freq: f64,
    rotation_offset: f64,
    slide_offset: f64,
    slide_velocity: f64,
    freq: f64,
    secondary_base_freq: f64,
    secondary_rotation_offset: f64,
    secondary_slide_offset: f64,
    secondary_slide_velocity: f64,
    secondary_freq: f64,
    rotation_tick: u64,
}

impl Door {
    pub fn new(id: usize, is_real: bool, base_freq: f64) -> Self {
        let secondary_base = base_freq + 50.0;
        let mut rng = rand::rng();
        let slide_vel = rng.random_range(-0.5..0.5);
        let sec_slide_vel = rng.random_range(-0.5..0.5);
        Self {
            id,
            is_real,
            base_freq,
            rotation_offset: 0.0,
            slide_offset: 0.0,
            slide_velocity: slide_vel,
            freq: base_freq,
            secondary_base_freq: secondary_base,
            secondary_rotation_offset: 0.0,
            secondary_slide_offset: 0.0,
            secondary_slide_velocity: sec_slide_vel,
            secondary_freq: secondary_base,
            rotation_tick: 0,
        }
    }

    pub fn rotate(&mut self, tick: u64, swarm_mode: bool) {
        self.rotation_tick = tick;
        let mut rng = rand::rng();
        if self.is_real {
            let drift = if swarm_mode { rng.random_range(-4.0..4.0) } else { rng.random_range(-2.0..2.0) };
            self.rotation_offset += drift;
            let sec_drift = if swarm_mode { rng.random_range(-3.0..3.0) } else { rng.random_range(-1.5..1.5) };
            self.secondary_rotation_offset += sec_drift;
        } else {
            if swarm_mode {
                self.rotation_offset = rng.random_range(-80.0..80.0);
                self.secondary_rotation_offset = rng.random_range(-80.0..80.0);
            } else {
                self.rotation_offset = rng.random_range(-50.0..50.0);
                self.secondary_rotation_offset = rng.random_range(-50.0..50.0);
            }
        }
        self.slide_offset += self.slide_velocity;
        if rng.random_bool(0.05) {
            self.slide_velocity = -self.slide_velocity + rng.random_range(-0.2..0.2);
        }
        self.secondary_slide_offset += self.secondary_slide_velocity;
        if rng.random_bool(0.05) {
            self.secondary_slide_velocity = -self.secondary_slide_velocity + rng.random_range(-0.2..0.2);
        }
        self.freq = (self.base_freq + self.rotation_offset + self.slide_offset).clamp(0.0, 100.0);
        self.secondary_freq = (self.secondary_base_freq + self.secondary_rotation_offset + self.secondary_slide_offset).clamp(0.0, 100.0);
    }

    pub fn verify_hmac(&self, entity: &Entity, tick: u64) -> bool {
        let tag = entity.hmac_challenge(self.id, tick);
        let first = u32::from_be_bytes([tag[0], tag[1], tag[2], tag[3]]) % 100;
        let target = (self.freq.round() as u32) % 100;
        let diff = if first > target { first - target } else { target - first };
        diff < HMAC_TOLERANCE
    }
}

pub struct TrustRing {
    id: RingId,
    window_start: f64,
    window_end: f64,
    max_circulation_ticks: u32,
    validator: Box<dyn Validator>,
    doors: Vec<Door>,
    real_door_idx: usize,
}

impl TrustRing {
    pub fn new(id: RingId, start: f64, end: f64, validator: Box<dyn Validator>) -> Self {
        let base_freq = match id {
            RingId::Ring1 => 10.0,
            RingId::Ring2 => 30.0,
            RingId::Ring3 => 60.0,
            RingId::Ring4 => 80.0,
            RingId::Ring5 => 95.0,
            _ => 50.0,
        };
        let real_idx = 0;
        let mut doors = Vec::new();
        doors.push(Door::new(real_idx, true, base_freq));
        doors.push(Door::new(1, false, 0.0));
        doors.push(Door::new(2, false, 0.0));
        Self {
            id,
            window_start: start,
            window_end: end,
            max_circulation_ticks: 30,
            validator,
            doors,
            real_door_idx: real_idx,
        }
    }

    pub fn adaptive_window(&self, entities_count: usize) -> (f64, f64) {
        let load = (entities_count as f64 / 50.0).max(0.5);
        let expansion = (load - 1.0) * 5.0;
        let start = (self.window_start - expansion).max(0.0);
        let end = (self.window_end + expansion).min(100.0);
        (start, end)
    }

    pub fn can_advance(&self, entity: &Entity, adaptive: bool, count: usize) -> bool {
        let end = if adaptive { self.adaptive_window(count).1 } else { self.window_end };
        entity.trust_score >= end - 5.0
    }

    pub fn should_drop_back(&self, entity: &Entity, adaptive: bool, count: usize) -> bool {
        let start = if adaptive { self.adaptive_window(count).0 } else { self.window_start };
        entity.trust_score < start - 3.0
    }

    pub fn should_eject(&self, entity: &Entity) -> bool {
        entity.circulation_ticks > self.max_circulation_ticks || entity.trust_score < 10.0
    }
}

#[derive(Debug)]
pub struct Firewall {
    allowlist: std::collections::HashSet<String>,
    blocklist: std::collections::HashSet<String>,
    allowed_ports: std::collections::HashSet<u16>,
    allowed_protocols: std::collections::HashSet<String>,
    geo_blocklist: std::collections::HashSet<String>,
    per_origin_rate: std::collections::HashMap<String, u32>,
    max_per_tick: usize,
}

impl Firewall {
    pub fn new(max_per_tick: usize) -> Self {
        Self {
            allowlist: std::collections::HashSet::new(),
            blocklist: std::collections::HashSet::new(),
            allowed_ports: std::collections::HashSet::new(),
            allowed_protocols: std::collections::HashSet::new(),
            geo_blocklist: std::collections::HashSet::new(),
            per_origin_rate: std::collections::HashMap::new(),
            max_per_tick,
        }
    }
    pub fn allow_origin(&mut self, origin: &str) {
        self.allowlist.insert(origin.to_string());
    }
    pub fn block_origin(&mut self, origin: &str) {
        self.blocklist.insert(origin.to_string());
    }
    pub fn allow_port(&mut self, port: u16) {
        self.allowed_ports.insert(port);
    }
    pub fn allow_protocol(&mut self, proto: &str) {
        self.allowed_protocols.insert(proto.to_lowercase());
    }
    pub fn block_geo(&mut self, country: &str) {
        self.geo_blocklist.insert(country.to_uppercase());
    }
    pub fn inspect(&mut self, entity: &Entity) -> bool {
        let origin = entity.metadata.get("origin_user").cloned().unwrap_or_default();
        if !self.allowlist.is_empty() && !self.allowlist.contains(&origin) {
            return false;
        }
        if self.blocklist.contains(&origin) {
            return false;
        }
        // Port allowlist
        if !self.allowed_ports.is_empty() {
            if let Some(port_str) = entity.metadata.get("port") {
                if let Ok(port) = port_str.parse::<u16>() {
                    if !self.allowed_ports.contains(&port) {
                        return false;
                    }
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }
        // Protocol allowlist
        if !self.allowed_protocols.is_empty() {
            if let Some(proto) = entity.metadata.get("protocol") {
                if !self.allowed_protocols.contains(&proto.to_lowercase()) {
                    return false;
                }
            } else {
                return false;
            }
        }
        // Geo blocklist
        if let Some(country) = entity.metadata.get("country") {
            if self.geo_blocklist.contains(&country.to_uppercase()) {
                return false;
            }
        }
        let count = self.per_origin_rate.entry(origin).or_insert(0);
        if *count >= self.max_per_tick as u32 {
            return false;
        }
        *count += 1;
        true
    }
    pub fn reset_rates(&mut self) {
        self.per_origin_rate.clear();
    }
}

pub struct Roundabout {
    rings: Vec<TrustRing>,
    entities: Vec<Entity>,
    tick: u64,
    origin_hits: HashMap<String, u32>,
    origin_entity_count: HashMap<String, usize>,
    swarm_mode: bool,
    swarm_cooldown: u64,
    false_hits_this_tick: usize,
    max_entities: usize,
    firewall: Firewall,
}

impl Roundabout {
    pub fn new() -> Self {
        let rings = vec![
            TrustRing::new(RingId::Ring1, 0.0, 25.0, Box::new(ProtocolCompliance)),
            TrustRing::new(RingId::Ring2, 20.0, 50.0, Box::new(SourceReputation)),
            TrustRing::new(RingId::Ring3, 45.0, 75.0, Box::new(BehavioralAnalytics)),
            TrustRing::new(RingId::Ring4, 70.0, 90.0, Box::new(IdentityIntent)),
            TrustRing::new(RingId::Ring5, 85.0, 100.0, Box::new(ResourceAuthorization)),
        ];
        Self {
            rings,
            entities: Vec::new(),
            tick: 0,
            origin_hits: HashMap::new(),
            origin_entity_count: HashMap::new(),
            swarm_mode: false,
            swarm_cooldown: 0,
            false_hits_this_tick: 0,
            max_entities: 100,
            firewall: Firewall::new(1000),
        }
    }

    pub fn prune_maps(&mut self) {
        if self.origin_hits.len() > MAX_ORIGINS {
            let excess = self.origin_hits.len() - MAX_ORIGINS;
            let keys: Vec<String> = self.origin_hits.keys().cloned().take(excess).collect();
            for k in keys {
                self.origin_hits.remove(&k);
            }
        }
        if self.origin_entity_count.len() > MAX_ORIGINS {
            let excess = self.origin_entity_count.len() - MAX_ORIGINS;
            let keys: Vec<String> = self.origin_entity_count.keys().cloned().take(excess).collect();
            for k in keys {
                self.origin_entity_count.remove(&k);
            }
        }
    }

    pub fn spawn_entity(&mut self, entity_type: EntityType, initial_score: f64, priority: u8) {
        if self.entities.len() >= self.max_entities {
            return;
        }
        let entity = Entity::new(entity_type, initial_score, priority);
        let origin = entity.metadata.get("origin_user").cloned().unwrap_or_default();
        let count = self.origin_entity_count.entry(origin.clone()).or_insert(0);
        if *count >= 3 {
            return;
        }
        *count = count.saturating_add(1);
        self.entities.push(entity);
        self.prune_maps();
    }

    pub fn spawn_local_admin(&mut self, entity_type: EntityType, initial_score: f64, priority: u8) {
        if self.entities.len() >= self.max_entities {
            return;
        }
        let entity = Entity::new_with_origin(entity_type, initial_score, priority, LOCAL_ADMIN_ORIGIN);
        let origin = entity.metadata.get("origin_user").cloned().unwrap_or_default();
        let count = self.origin_entity_count.entry(origin.clone()).or_insert(0);
        *count = count.saturating_add(1);
        self.entities.push(entity);
        self.prune_maps();
    }

    pub fn firewall_allow_origin(&mut self, origin: &str) {
        self.firewall.allow_origin(origin);
    }

    pub fn firewall_block_origin(&mut self, origin: &str) {
        self.firewall.block_origin(origin);
    }

    pub fn firewall_allow_port(&mut self, port: u16) {
        self.firewall.allow_port(port);
    }

    pub fn firewall_allow_protocol(&mut self, proto: &str) {
        self.firewall.allow_protocol(proto);
    }

    pub fn firewall_block_geo(&mut self, country: &str) {
        self.firewall.block_geo(country);
    }

    pub fn tick(&mut self) {
        self.tick = self.tick.saturating_add(1);
        self.false_hits_this_tick = 0;
        self.firewall.reset_rates();

        if self.swarm_mode {
            if self.swarm_cooldown > 0 {
                self.swarm_cooldown = self.swarm_cooldown.saturating_sub(1);
            } else {
                self.swarm_mode = false;
            }
        }

        for ring in &mut self.rings {
            for door in &mut ring.doors {
                door.rotate(self.tick, self.swarm_mode);
            }
        }

        let mut ring_counts: HashMap<RingId, usize> = HashMap::new();
        for e in &self.entities {
            *ring_counts.entry(e.ring).or_insert(0) += 1;
        }

        let mut origins_to_escalate = Vec::new();

        for entity in &mut self.entities {
            if entity.is_local_admin() {
                entity.read_only = false;
                entity.tagged = false;
                entity.suspicion_score = 0;
            }
            // Firewall pre-filter
            if !self.firewall.inspect(entity) {
                if entity.ring != RingId::Ejected {
                    println!("[FIREWALL DROP] Entity {} from user {} blocked by firewall - ejected", entity.id, entity.metadata.get("origin_user").unwrap_or(&"unknown".to_string()));
                }
                entity.ring = RingId::Ejected;
                continue;
            }
            if entity.ring == RingId::Quarantine {
                if !entity.is_local_admin() && !entity.read_only {
                    entity.read_only = true;
                    println!("[READ ONLY ENFORCED] Entity {} from user {} moved to quarantine - access restricted to read-only, code execution blocked", entity.id, entity.metadata.get("origin_user").unwrap_or(&"unknown".to_string()));
                }
                entity.circulation_ticks = entity.circulation_ticks.saturating_add(1);
                entity.last_update = Instant::now();
                let mut rng = rand::rng();
                entity.resonance_signature = (0.9 * entity.resonance_signature + 0.1 * entity.trust_score).clamp(0.0, 100.0);
                entity.resonance_signature += rng.random_range(-1.5..1.5);
                entity.resonance_signature = entity.resonance_signature.clamp(0.0, 100.0);
                entity.secondary_signature = (0.85 * entity.secondary_signature + 0.15 * entity.trust_score).clamp(0.0, 100.0);
                entity.secondary_signature += rng.random_range(-2.0..2.0);
                entity.secondary_signature = entity.secondary_signature.clamp(0.0, 100.0);
                let origin = entity.metadata.get("origin_user").cloned().unwrap_or_else(|| "unknown".to_string());
                if self.tick % 7 == 0 {
                    let fake_ring = rng.random_range(1..=5);
                    println!("[Sandbox Fake] Entity {} [{:?}] from user {} appears to pass Ring{} validation check - trust {:.1}", entity.id, entity.entity_type, origin, fake_ring, entity.trust_score);
                }
                if self.tick % 5 == 0 {
                    // Jittered logging to avoid timing fingerprint
                    let delay = rng.random_range(0..3);
                    if (self.tick + delay as u64) % 5 == 0 {
                        println!("[Sandbox] Entity {} [{:?}] from user {} is simulating activity in sandbox - suspicion {}, signature {:.1}", entity.id, entity.entity_type, origin, entity.suspicion_score, entity.resonance_signature);
                    }
                }
                // Decoy file lure: quarantined entities are offered fake sensitive files
                if self.tick % 11 == 0 {
                    let decoy_name = "confidential_designs_v2.zip";
                    println!("[DECOY FILE] Entity {} from user {} attempted download of {} - LOCATION PINGED: {}", entity.id, origin, decoy_name, origin);
                    // Increment suspicion to reflect interest in decoy assets
                    if !entity.is_local_admin() {
                        entity.suspicion_score = entity.suspicion_score.saturating_add(1);
                    }
                }
                // Verification / false-positive recovery
                // If entity has been in sandbox long enough without further suspicious behavior
                // and trust has recovered, release it back to Ring1 with admin notification
                if !entity.is_local_admin() && entity.tagged && entity.suspicion_score < 5 && entity.trust_score >= 60.0 && entity.circulation_ticks >= 20 {
                    entity.ring = RingId::Ring1;
                    entity.tagged = false;
                    entity.read_only = false;
                    entity.suspicion_score = 0;
                    println!("[VERIFICATION RELEASE] Entity {} from user {} cleared sandbox after trust recovery - false positive resolved", entity.id, origin);
                }
                continue;
            }
            if matches!(entity.ring, RingId::Ejected | RingId::Core) {
                continue;
            }

            // Auto-eject on high suspicion
            if !entity.is_local_admin() && entity.suspicion_score >= SUSPICION_EJECT_THRESHOLD {
                entity.ring = RingId::Quarantine;
                entity.tagged = true;
                entity.read_only = true;
                println!("[READ ONLY ENFORCED] Entity {} from user {} suspicion {} >= threshold - access restricted to read-only, code execution blocked", entity.id, entity.metadata.get("origin_user").unwrap_or(&"unknown".to_string()), entity.suspicion_score);
                continue;
            }

            entity.circulation_ticks = entity.circulation_ticks.saturating_add(1);
            entity.last_update = Instant::now();

            let mut rng = rand::rng();
            entity.resonance_signature = (0.9 * entity.resonance_signature + 0.1 * entity.trust_score).clamp(0.0, 100.0);
            entity.resonance_signature += rng.random_range(-1.5..1.5);
            entity.resonance_signature = entity.resonance_signature.clamp(0.0, 100.0);
            entity.secondary_signature = (0.85 * entity.secondary_signature + 0.15 * entity.trust_score).clamp(0.0, 100.0);
            entity.secondary_signature += rng.random_range(-2.0..2.0);
            entity.secondary_signature = entity.secondary_signature.clamp(0.0, 100.0);

            // VPN hop simulation: high network risk entities may change fingerprint
            if entity.network_risk > 0.6 && rng.random_bool(0.02) {
                entity.last_network_fingerprint = entity.network_fingerprint.clone();
                entity.network_fingerprint = format!("fp_{}", rng.random_range(100000..999999));
                println!("[VPN HOP DETECTED] Entity {} from user {} changed network fingerprint {} -> {} - suspicion increased", entity.id, entity.metadata.get("origin_user").unwrap_or(&"unknown".to_string()), entity.last_network_fingerprint, entity.network_fingerprint);
                entity.suspicion_score = entity.suspicion_score.saturating_add(2);
            }

            let evaluations = if entity.priority > 0 { 2 } else { 1 };

            let Some(ring_idx) = entity.ring.as_ring_index() else { continue };
            if ring_idx >= self.rings.len() { continue; }
            let ring = &self.rings[ring_idx];
            for _ in 0..evaluations {
                let _ = ring.validator.evaluate(entity);
            }

            let count = *ring_counts.get(&entity.ring).unwrap_or(&0);

            if !entity.is_local_admin() && ring.should_eject(entity) {
                entity.ring = RingId::Quarantine;
                continue;
            }

            if ring.can_advance(entity, true, count) {
                // Per-entity attempt rate limiting & backoff
                if self.tick.saturating_sub(entity.last_attempt_tick) < entity.attempt_cooldown {
                    entity.suspicion_score = entity.suspicion_score.saturating_add(1);
                    continue;
                }
                if entity.door_attempts >= MAX_DOOR_ATTEMPTS_PER_TICK {
                    // Exponential backoff
                    entity.attempt_cooldown = 1u64 << entity.door_attempts.min(10);
                    entity.suspicion_score = entity.suspicion_score.saturating_add(1);
                    continue;
                }

                let resonance_tolerance = if self.swarm_mode { 5.0 } else { 10.0 };
                let door_choice = {
                    let mut rng = rand::rng();
                    if entity.priority > 0 {
                        if rng.random_bool(0.8) {
                            ring.real_door_idx
                        } else {
                            rng.random_range(0..ring.doors.len())
                        }
                    } else {
                        rng.random_range(0..ring.doors.len())
                    }
                };
                if door_choice >= ring.doors.len() {
                    continue;
                }
                let door = &ring.doors[door_choice];
                let primary_match = (entity.resonance_signature - door.freq).abs() < resonance_tolerance;
                let secondary_match = (entity.secondary_signature - door.secondary_freq).abs() < resonance_tolerance;
                let resonance_match = primary_match && secondary_match;

                entity.last_attempt_tick = self.tick;
                entity.door_attempts = entity.door_attempts.saturating_add(1);

                if door.is_real && resonance_match {
                    if door.verify_hmac(entity, self.tick) {
                        entity.ring = entity.ring.next();
                        entity.circulation_ticks = 0;
                        entity.door_attempts = 0;
                        entity.attempt_cooldown = 0;
                        entity.suspicion_score = entity.suspicion_score.saturating_sub(1).max(0);
                        // Enforce read-only for tagged entities even if they advance
                        if !entity.is_local_admin() && entity.tagged && !entity.read_only {
                            entity.read_only = true;
                            println!("[READ ONLY ENFORCED] Entity {} from user {} advanced to {:?} but remains tagged - access restricted to read-only, code execution blocked", entity.id, entity.metadata.get("origin_user").unwrap_or(&"unknown".to_string()), entity.ring);
                        }
                        println!("[Tick {}] Entity {} resonated with REAL door {} on {:?}, advanced (score {:.1}, sig {:.1})", self.tick, entity.id, door.id, entity.ring, entity.trust_score, entity.resonance_signature);
                    } else {
                        entity.suspicion_score = entity.suspicion_score.saturating_add(1);
                        println!("[Tick {}] Entity {} resonance OK but HMAC failed for REAL door {} - suspicion {}", self.tick, entity.id, door.id, entity.suspicion_score);
                    }
                } else if door.is_real && primary_match && !secondary_match {
                    entity.suspicion_score = entity.suspicion_score.saturating_add(1);
                    println!("[Tick {}] Entity {} partially unlocked REAL door {} on {:?} - primary key OK, secondary key MISMATCH - suspicion {}", self.tick, entity.id, door.id, entity.ring, entity.suspicion_score);
                } else if !door.is_real && resonance_match {
                    self.false_hits_this_tick = self.false_hits_this_tick.saturating_add(1);
                    if !entity.is_local_admin() {
                        entity.tagged = true;
                        entity.read_only = true;
                        entity.suspicion_score = entity.suspicion_score.saturating_add(2);
                        entity.trust_score = (entity.trust_score - 10.0).clamp(0.0, 100.0);
                        let origin = entity.metadata.get("origin_user").cloned().unwrap_or_else(|| "unknown".to_string());
                        let hits = self.origin_hits.entry(origin.clone()).or_insert(0);
                        *hits = hits.saturating_add(1);
                        println!("[ADMIN ALERT] False door {} used by Entity {} [{:?}] from user {} at Ring {:?} - tagging and sandboxing", door.id, entity.id, entity.entity_type, origin, entity.ring);
                        println!("[Tick {}] Entity {} hit FALSE door {} on {:?}, SUSPICION {} - moved to SANDBOX quarantine", self.tick, entity.id, door.id, entity.ring, entity.suspicion_score);
                        println!("[READ ONLY ENFORCED] Entity {} from user {} false door usage - access restricted to read-only, code execution blocked", entity.id, origin);
                        entity.ring = RingId::Quarantine;
                        if *hits >= 3 {
                            origins_to_escalate.push(origin.clone());
                        }
                    }
                } else {
                    // No resonance, mild suspicion increase on repeated attempts
                    if entity.door_attempts > 5 {
                        entity.suspicion_score = entity.suspicion_score.saturating_add(1);
                    }
                }
            } else if !entity.is_local_admin() && ring.should_drop_back(entity, true, count) {
                entity.ring = entity.ring.prev();
                entity.circulation_ticks = 0;
                println!("[Tick {}] Entity {} dropped back to {:?} (score {:.1})", self.tick, entity.id, entity.ring, entity.trust_score);
            }
            if entity.is_local_admin() {
                entity.suspicion_score = 0;
                entity.tagged = false;
                entity.read_only = false;
            }
        }

        for origin in origins_to_escalate {
            if self.origin_hits.get(&origin).copied().unwrap_or(0) >= 3 {
                println!("[ADMIN ESCALATION] Origin {} triggered {} false door hits - ejecting all related entities", origin, self.origin_hits.get(&origin).unwrap());
                for e in &mut self.entities {
                    if let Some(o) = e.metadata.get("origin_user") {
                        if o == &origin && e.ring != RingId::Ejected && !e.is_local_admin() {
                            e.ring = RingId::Quarantine;
                            e.tagged = true;
                            e.suspicion_score = e.suspicion_score.saturating_add(5);
                        }
                    }
                }
            }
        }

        pub const SWARM_THRESHOLD: usize = 5;
        if self.false_hits_this_tick >= SWARM_THRESHOLD {
            if !self.swarm_mode {
                println!("[SWARM DETECTED] {} false door hits this tick - activating swarm mitigation", self.false_hits_this_tick);
            }
            self.swarm_mode = true;
            self.swarm_cooldown = 20;
        }

        if self.tick % 10 == 0 {
            self.print_stats();
        }

        self.prune_maps();
    }

    pub fn print_stats(&self) {
        let mut counts: HashMap<RingId, usize> = HashMap::new();
        let mut tagged_count = 0;
        for e in &self.entities {
            *counts.entry(e.ring).or_insert(0) += 1;
            if e.tagged {
                tagged_count += 1;
            }
        }
        println!("=== Tick {} Stats ===", self.tick);
        for ring in &self.rings {
            let c = counts.get(&ring.id).copied().unwrap_or(0);
            println!("{:?}: {} entities, window [{:.0}-{:.0}]", ring.id, c, ring.window_start, ring.window_end);
        }
        let q = counts.get(&RingId::Quarantine).copied().unwrap_or(0);
        let e = counts.get(&RingId::Ejected).copied().unwrap_or(0);
        let core = counts.get(&RingId::Core).copied().unwrap_or(0);
        println!("Quarantine/Sandbox: {}, Ejected: {}, Core: {}, Tagged: {}", q, e, core, tagged_count);
    }

    pub fn entity_count(&self) -> usize {
        self.entities.len()
    }
    pub fn quarantined_count(&self) -> usize {
        self.entities.iter().filter(|e| e.ring == RingId::Quarantine).count()
    }
    pub fn tagged_count(&self) -> usize {
        self.entities.iter().filter(|e| e.tagged).count()
    }
    pub fn max_suspicion(&self) -> u32 {
        self.entities.iter().map(|e| e.suspicion_score).max().unwrap_or(0)
    }
    pub fn swarm_active(&self) -> bool {
        self.swarm_mode
    }
}

