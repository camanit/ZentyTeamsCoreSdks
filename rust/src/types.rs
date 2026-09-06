use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

// ─────────────────────────────────────────────
//  AGENT ROLE
// ─────────────────────────────────────────────

/// Peran agent yang menggunakan SDK ini.
/// Purple selalu aktif — tidak bisa dinonaktifkan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AgentRole {
    /// Penyerang — melakukan real attack, fuzzing, dan exploit
    RedTeam,
    /// Pembela — deteksi anomali, mitigasi, dan auto-patch
    BlueTeam,
    /// Pencatat & analis — selalu aktif di semua phase
    PurpleTeam,
    /// Intelijen ancaman — OSINT, dark web, credential leak
    DarkIntel,
}

impl std::fmt::Display for AgentRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentRole::RedTeam   => write!(f, "RED_TEAM"),
            AgentRole::BlueTeam  => write!(f, "BLUE_TEAM"),
            AgentRole::PurpleTeam => write!(f, "PURPLE_TEAM"),
            AgentRole::DarkIntel => write!(f, "DARK_INTEL"),
        }
    }
}

// ─────────────────────────────────────────────
//  SEVERITY & RESULTS
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Info,
    Low,
    #[default]
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttackResult {
    /// Berhasil menembus — sistem rentan
    Breached,
    /// Diblokir oleh Blue Team
    Blocked,
    /// Berhasil sebagian
    Partial,
    /// Serangan gagal — sistem aman
    #[default]
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DefenseResult {
    /// Serangan berhasil diblokir total
    #[default]
    Blocked,
    /// Patch berhasil diterapkan
    Patched,
    /// Ancaman diisolasi
    Quarantined,
    /// Gagal menahan serangan
    Failed,
    /// Dalam proses investigasi
    Investigating,
}

// ─────────────────────────────────────────────
//  BATTLE PHASE
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BattlePhase {
    /// Phase 1: Red menyerang, tanpa Blue (cari kelemahan murni)
    UndefendedAttack,
    /// Phase 2: Red vs Blue (uji pertahanan)
    RedVsBlue,
    /// Phase 3: Semua sistem aktif (operasi penuh 24/7)
    FullEcosystem,
}

impl std::fmt::Display for BattlePhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BattlePhase::UndefendedAttack => write!(f, "UNDEFENDED_ATTACK"),
            BattlePhase::RedVsBlue        => write!(f, "RED_VS_BLUE"),
            BattlePhase::FullEcosystem    => write!(f, "FULL_ECOSYSTEM"),
        }
    }
}

// ─────────────────────────────────────────────
//  ATTACK EVENT (Red Team)
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AttackEvent {
    /// ID unik event (auto-generated jika kosong)
    pub event_id: Option<String>,
    /// Target sistem yang diserang (domain / IP)
    pub target: String,
    /// Vektor serangan: SQLi, XSS, RCE, BruteForce, QRIS-Manipulation, dll
    pub vector: String,
    /// Payload yang digunakan
    pub payload: String,
    /// Endpoint atau path yang diserang
    pub endpoint: Option<String>,
    /// Hasil serangan
    pub result: AttackResult,
    /// Tingkat keparahan
    pub severity: Severity,
    /// CVE terkait (jika ada)
    pub cve_id: Option<String>,
    /// Catatan tambahan
    pub notes: Option<String>,
    /// Phase battle saat ini
    pub battle_phase: Option<BattlePhase>,
    /// Timestamp (auto-filled oleh SDK)
    pub timestamp: Option<DateTime<Utc>>,
}

impl AttackEvent {
    pub fn finalize(mut self) -> Self {
        if self.event_id.is_none() {
            self.event_id = Some(Uuid::new_v4().to_string());
        }
        if self.timestamp.is_none() {
            self.timestamp = Some(Utc::now());
        }
        self
    }
}

// ─────────────────────────────────────────────
//  DEFENSE EVENT (Blue Team)
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DefenseEvent {
    pub event_id: Option<String>,
    /// ID attack event yang ditangani (korelasi ke Red Team)
    pub attack_event_id: Option<String>,
    /// Aksi mitigasi yang dilakukan
    pub action: String,
    /// Hasil pertahanan
    pub result: DefenseResult,
    /// Patch atau rule yang diterapkan
    pub patch_applied: Option<String>,
    /// Waktu respons sejak serangan terdeteksi (dalam milidetik)
    pub response_time_ms: Option<u64>,
    /// Catatan tambahan dari Blue Team AI
    pub notes: Option<String>,
    pub timestamp: Option<DateTime<Utc>>,
}

impl DefenseEvent {
    pub fn finalize(mut self) -> Self {
        if self.event_id.is_none() {
            self.event_id = Some(Uuid::new_v4().to_string());
        }
        if self.timestamp.is_none() {
            self.timestamp = Some(Utc::now());
        }
        self
    }
}

// ─────────────────────────────────────────────
//  TELEMETRY EVENT (Purple Team — always on)
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub event_id: String,
    /// Sumber event: RED_TEAM / BLUE_TEAM / DARK_INTEL / ANTIVIRUS / SDK
    pub source: AgentRole,
    /// Kategori event: ATTACK / DEFENSE / DETECTION / MITIGATION / IOC / dll
    pub category: String,
    /// Data event (serialized JSON bebas)
    pub payload: serde_json::Value,
    /// Hash SHA-256 dari payload (untuk Merkle Chain)
    pub payload_hash: String,
    /// Hash event sebelumnya (untuk chain integrity)
    pub previous_hash: Option<String>,
    pub timestamp: DateTime<Utc>,
}

// ─────────────────────────────────────────────
//  VULNERABILITY REPORT
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityReport {
    pub vuln_id: String,
    pub target: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    /// Skor CVSS 0.0 - 10.0
    pub cvss_score: f32,
    pub cve_id: Option<String>,
    pub affected_endpoint: Option<String>,
    pub proof_of_concept: Option<String>,
    pub remediation: Option<String>,
    pub discovered_by: AgentRole,
    pub timestamp: DateTime<Utc>,
}

// ─────────────────────────────────────────────
//  THREAT IOC (Dark Intelligence)
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIoc {
    pub ioc_id: String,
    /// Tipe: IP / DOMAIN / HASH / EMAIL / URL / API_KEY_LEAKED
    pub ioc_type: String,
    pub value: String,
    pub source: String,
    pub confidence_score: u8, // 0-100
    pub severity: Severity,
    pub description: Option<String>,
    pub timestamp: DateTime<Utc>,
}

// ─────────────────────────────────────────────
//  ARTIFACT SCAN RESULT (Integrity Scanner)
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtefactScanResult {
    pub scan_id: String,
    pub file_name: String,
    pub file_hash_sha256: String,
    pub is_clean: bool,
    pub threats_found: Vec<String>,
    pub scan_engine_version: String,
    pub timestamp: DateTime<Utc>,
}

// ─────────────────────────────────────────────
//  API RESPONSE
// ─────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ApiResponse {
    pub success: bool,
    pub id: Option<String>,
    pub message: Option<String>,
}
