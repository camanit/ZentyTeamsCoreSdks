use crate::client::ZentyTeamsClient;
use crate::types::*;
use crate::error::ZentyError;
use serde_json::json;

/// Ekstensi Red Team untuk ZentyTeamsClient.
/// Hanya bisa digunakan oleh agent dengan role RedTeam.
///
/// Phase 1: Red menyerang TANPA pertahanan Blue (cari kelemahan murni)
/// Phase 2: Red menyerang DENGAN Blue aktif (uji pertahanan)
/// Phase 3: Red terus probing sebagai bagian ekosistem penuh
impl ZentyTeamsClient {

    // ─────────────────────────────────────────────────────
    //  CORE: LAPORKAN EVENT SERANGAN
    // ─────────────────────────────────────────────────────

    /// Laporkan satu event serangan ke Purple Team & gplay.ctar.tech.
    /// Purple Team otomatis menerima semua event ini.
    pub async fn report_attack(&self, event: AttackEvent) -> Result<ApiResponse, ZentyError> {
        let event = event.finalize();
        self.post("/api/v1/red/attack", &event).await
    }

    /// Laporkan vulnerability yang ditemukan (masuk ke Risk Matrix)
    pub async fn report_vulnerability(&self, report: VulnerabilityReport) -> Result<ApiResponse, ZentyError> {
        self.post("/api/v1/red/vulnerability", &report).await
    }

    // ─────────────────────────────────────────────────────
    //  WEB ATTACK VECTORS
    // ─────────────────────────────────────────────────────

    /// Laporkan keberhasilan SQL Injection
    pub async fn report_sqli(
        &self, target: &str, endpoint: &str,
        payload: &str, result: AttackResult, phase: BattlePhase,
    ) -> Result<ApiResponse, ZentyError> {
        self.report_attack(AttackEvent {
            target: target.to_string(),
            vector: "SQL_INJECTION".to_string(),
            payload: payload.to_string(),
            endpoint: Some(endpoint.to_string()),
            result,
            severity: Severity::Critical,
            battle_phase: Some(phase),
            ..Default::default()
        }).await
    }

    /// Laporkan XSS (Reflected / Stored / DOM)
    pub async fn report_xss(
        &self, target: &str, xss_type: &str,
        payload: &str, result: AttackResult, phase: BattlePhase,
    ) -> Result<ApiResponse, ZentyError> {
        self.report_attack(AttackEvent {
            target: target.to_string(),
            vector: format!("XSS_{}", xss_type.to_uppercase()),
            payload: payload.to_string(),
            result,
            severity: Severity::High,
            battle_phase: Some(phase),
            notes: Some(format!("XSS type: {}", xss_type)),
            ..Default::default()
        }).await
    }

    /// Laporkan Remote Code Execution (RCE)
    pub async fn report_rce(
        &self, target: &str, endpoint: &str,
        payload: &str, result: AttackResult, phase: BattlePhase,
    ) -> Result<ApiResponse, ZentyError> {
        self.report_attack(AttackEvent {
            target: target.to_string(),
            vector: "RCE".to_string(),
            payload: payload.to_string(),
            endpoint: Some(endpoint.to_string()),
            result,
            severity: Severity::Critical,
            battle_phase: Some(phase),
            ..Default::default()
        }).await
    }

    /// Laporkan SSRF (Server-Side Request Forgery)
    pub async fn report_ssrf(
        &self, target: &str, forged_url: &str,
        result: AttackResult, phase: BattlePhase,
    ) -> Result<ApiResponse, ZentyError> {
        self.report_attack(AttackEvent {
            target: target.to_string(),
            vector: "SSRF".to_string(),
            payload: forged_url.to_string(),
            result,
            severity: Severity::High,
            battle_phase: Some(phase),
            ..Default::default()
        }).await
    }

    /// Laporkan Path Traversal / Directory Traversal
    pub async fn report_path_traversal(
        &self, target: &str, path: &str,
        result: AttackResult, phase: BattlePhase,
    ) -> Result<ApiResponse, ZentyError> {
        self.report_attack(AttackEvent {
            target: target.to_string(),
            vector: "PATH_TRAVERSAL".to_string(),
            payload: path.to_string(),
            result,
            severity: Severity::High,
            battle_phase: Some(phase),
            ..Default::default()
        }).await
    }

    // ─────────────────────────────────────────────────────
    //  AUTH ATTACK VECTORS
    // ─────────────────────────────────────────────────────

    /// Laporkan percobaan brute force / credential stuffing
    pub async fn report_brute_force(
        &self, target: &str, attempts: u32,
        result: AttackResult, phase: BattlePhase,
    ) -> Result<ApiResponse, ZentyError> {
        self.report_attack(AttackEvent {
            target: target.to_string(),
            vector: "BRUTE_FORCE".to_string(),
            payload: format!("{} attempts", attempts),
            result,
            severity: Severity::High,
            battle_phase: Some(phase),
            notes: Some(format!("Total attempts: {}", attempts)),
            ..Default::default()
        }).await
    }

    /// Laporkan JWT manipulation / algorithm confusion
    pub async fn report_jwt_attack(
        &self, target: &str, technique: &str,
        result: AttackResult, phase: BattlePhase,
    ) -> Result<ApiResponse, ZentyError> {
        self.report_attack(AttackEvent {
            target: target.to_string(),
            vector: "JWT_MANIPULATION".to_string(),
            payload: technique.to_string(),
            result,
            severity: Severity::Critical,
            battle_phase: Some(phase),
            ..Default::default()
        }).await
    }

    // ─────────────────────────────────────────────────────
    //  API & PAYMENT ATTACK VECTORS
    // ─────────────────────────────────────────────────────

    /// Laporkan API fuzzing & parameter manipulation
    pub async fn report_api_fuzz(
        &self, target: &str, endpoint: &str,
        fuzz_count: u32, vulnerabilities_found: u32,
        phase: BattlePhase,
    ) -> Result<ApiResponse, ZentyError> {
        let body = json!({
            "target": target,
            "endpoint": endpoint,
            "vector": "API_FUZZING",
            "fuzz_count": fuzz_count,
            "vulnerabilities_found": vulnerabilities_found,
            "battle_phase": phase,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        self.post("/api/v1/red/api-fuzz", &body).await
    }

    /// Laporkan manipulasi logika pembayaran (QRIS, token replay, race condition)
    pub async fn report_payment_attack(
        &self, target: &str, payment_system: &str,
        technique: &str, result: AttackResult, phase: BattlePhase,
    ) -> Result<ApiResponse, ZentyError> {
        self.report_attack(AttackEvent {
            target: target.to_string(),
            vector: format!("PAYMENT_LOGIC_{}", payment_system.to_uppercase()),
            payload: technique.to_string(),
            result,
            severity: Severity::Critical,
            battle_phase: Some(phase),
            notes: Some(format!("Payment system: {}", payment_system)),
            ..Default::default()
        }).await
    }

    /// Laporkan rate-limit bypass attempt
    pub async fn report_rate_limit_bypass(
        &self, target: &str, endpoint: &str,
        technique: &str, result: AttackResult, phase: BattlePhase,
    ) -> Result<ApiResponse, ZentyError> {
        self.report_attack(AttackEvent {
            target: target.to_string(),
            vector: "RATE_LIMIT_BYPASS".to_string(),
            payload: technique.to_string(),
            endpoint: Some(endpoint.to_string()),
            result,
            severity: Severity::Medium,
            battle_phase: Some(phase),
            ..Default::default()
        }).await
    }

    // ─────────────────────────────────────────────────────
    //  NETWORK ATTACK VECTORS
    // ─────────────────────────────────────────────────────

    /// Laporkan hasil port scanning & service fingerprinting
    pub async fn report_recon(
        &self, target: &str, open_ports: &[u16],
        services: &[&str], phase: BattlePhase,
    ) -> Result<ApiResponse, ZentyError> {
        let body = json!({
            "target": target,
            "vector": "RECONNAISSANCE",
            "open_ports": open_ports,
            "services_detected": services,
            "battle_phase": phase,
            "severity": "INFO",
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        self.post("/api/v1/red/recon", &body).await
    }

    /// Laporkan Man-in-the-Middle (MITM) attack
    pub async fn report_mitm(
        &self, target: &str, intercept_point: &str,
        data_captured: bool, phase: BattlePhase,
    ) -> Result<ApiResponse, ZentyError> {
        self.report_attack(AttackEvent {
            target: target.to_string(),
            vector: "MITM".to_string(),
            payload: intercept_point.to_string(),
            result: if data_captured { AttackResult::Breached } else { AttackResult::Failed },
            severity: Severity::Critical,
            battle_phase: Some(phase),
            notes: Some(format!("Data captured: {}", data_captured)),
            ..Default::default()
        }).await
    }

    // ─────────────────────────────────────────────────────
    //  ADVANCED VECTORS (AI-powered)
    // ─────────────────────────────────────────────────────

    /// Laporkan supply chain attack attempt (plugin / dependency)
    pub async fn report_supply_chain_attack(
        &self, target: &str, package_name: &str,
        technique: &str, result: AttackResult, phase: BattlePhase,
    ) -> Result<ApiResponse, ZentyError> {
        self.report_attack(AttackEvent {
            target: target.to_string(),
            vector: "SUPPLY_CHAIN".to_string(),
            payload: format!("{}:{}", package_name, technique),
            result,
            severity: Severity::Critical,
            battle_phase: Some(phase),
            notes: Some(format!("Package: {}", package_name)),
            ..Default::default()
        }).await
    }

    /// Laporkan ransomware behavior simulation
    pub async fn report_ransomware_sim(
        &self, target: &str, files_encrypted: u32,
        backup_bypassed: bool, phase: BattlePhase,
    ) -> Result<ApiResponse, ZentyError> {
        let body = json!({
            "target": target,
            "vector": "RANSOMWARE_SIMULATION",
            "files_encrypted": files_encrypted,
            "backup_bypassed": backup_bypassed,
            "result": if backup_bypassed { "BREACHED" } else { "PARTIAL" },
            "severity": "CRITICAL",
            "battle_phase": phase,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        self.post("/api/v1/red/ransomware-sim", &body).await
    }

    /// Laporkan social engineering simulation (phishing, pretexting)
    pub async fn report_social_engineering(
        &self, target_org: &str, technique: &str,
        success_rate: f32, phase: BattlePhase,
    ) -> Result<ApiResponse, ZentyError> {
        let body = json!({
            "target": target_org,
            "vector": "SOCIAL_ENGINEERING",
            "technique": technique,
            "success_rate_percent": success_rate,
            "battle_phase": phase,
            "severity": "HIGH",
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        self.post("/api/v1/red/social-eng", &body).await
    }
}
