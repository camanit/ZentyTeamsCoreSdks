use crate::client::ZentyTeamsClient;
use crate::types::*;
use crate::error::ZentyError;
use serde_json::json;

/// Ekstensi Blue Team untuk ZentyTeamsClient.
/// Blue Team aktif di Phase 2 & 3.
/// Purple Team otomatis menerima semua event Blue Team.
impl ZentyTeamsClient {

    // ─────────────────────────────────────────────────────
    //  CORE: LAPORKAN AKSI PERTAHANAN
    // ─────────────────────────────────────────────────────

    /// Laporkan satu aksi pertahanan/mitigasi
    pub async fn report_defense(&self, event: DefenseEvent) -> Result<ApiResponse, ZentyError> {
        let event = event.finalize();
        self.post("/api/v1/blue/defense", &event).await
    }

    // ─────────────────────────────────────────────────────
    //  ANOMALY DETECTION
    // ─────────────────────────────────────────────────────

    /// Laporkan anomali trafik yang terdeteksi
    pub async fn report_anomaly(
        &self, source_ip: &str, anomaly_type: &str,
        severity: Severity, details: &str,
    ) -> Result<ApiResponse, ZentyError> {
        let body = json!({
            "source_ip": source_ip,
            "anomaly_type": anomaly_type,
            "severity": severity,
            "details": details,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        self.post("/api/v1/blue/anomaly", &body).await
    }

    /// Laporkan deteksi rate-limit abuse
    pub async fn report_rate_limit_trigger(
        &self, source_ip: &str, endpoint: &str,
        requests_per_min: u32,
    ) -> Result<ApiResponse, ZentyError> {
        let body = json!({
            "source_ip": source_ip,
            "endpoint": endpoint,
            "requests_per_minute": requests_per_min,
            "action": "RATE_LIMITED",
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        self.post("/api/v1/blue/rate-limit", &body).await
    }

    // ─────────────────────────────────────────────────────
    //  MITIGATION ACTIONS
    // ─────────────────────────────────────────────────────

    /// Laporkan IP yang di-block
    pub async fn report_ip_blocked(
        &self, ip: &str, reason: &str,
        attack_event_id: Option<String>,
    ) -> Result<ApiResponse, ZentyError> {
        self.report_defense(DefenseEvent {
            attack_event_id,
            action: format!("IP_BLOCKED:{}", ip),
            result: DefenseResult::Blocked,
            notes: Some(reason.to_string()),
            ..Default::default()
        }).await
    }

    /// Laporkan session yang di-kill paksa
    pub async fn report_session_killed(
        &self, session_id: &str, user_id: &str,
        reason: &str, attack_event_id: Option<String>,
    ) -> Result<ApiResponse, ZentyError> {
        self.report_defense(DefenseEvent {
            attack_event_id,
            action: format!("SESSION_KILLED:{}:{}", session_id, user_id),
            result: DefenseResult::Blocked,
            notes: Some(reason.to_string()),
            ..Default::default()
        }).await
    }

    /// Laporkan patch kode yang diterapkan
    pub async fn report_patch_applied(
        &self, target: &str, patch_description: &str,
        response_time_ms: u64, attack_event_id: Option<String>,
    ) -> Result<ApiResponse, ZentyError> {
        self.report_defense(DefenseEvent {
            attack_event_id,
            action: format!("PATCH_APPLIED:{}", target),
            result: DefenseResult::Patched,
            patch_applied: Some(patch_description.to_string()),
            response_time_ms: Some(response_time_ms),
            ..Default::default()
        }).await
    }

    /// Laporkan firewall rule baru yang diaktifkan
    pub async fn report_firewall_rule(
        &self, rule_description: &str,
        attack_event_id: Option<String>,
    ) -> Result<ApiResponse, ZentyError> {
        self.report_defense(DefenseEvent {
            attack_event_id,
            action: format!("FIREWALL_RULE_ADDED:{}", rule_description),
            result: DefenseResult::Blocked,
            ..Default::default()
        }).await
    }

    // ─────────────────────────────────────────────────────
    //  ANTIVIRUS ENGINE REPORTS
    // ─────────────────────────────────────────────────────

    /// Laporkan hasil scan antivirus
    pub async fn report_av_scan(
        &self, result: ArtefactScanResult,
    ) -> Result<ApiResponse, ZentyError> {
        self.post("/api/v1/blue/av-scan", &result).await
    }

    /// Laporkan file yang dikarantina (malware/ransomware/spyware)
    pub async fn report_quarantine(
        &self, file_path: &str, file_hash: &str,
        threat_name: &str, threat_type: &str,
    ) -> Result<ApiResponse, ZentyError> {
        let body = json!({
            "file_path": file_path,
            "file_hash_sha256": file_hash,
            "threat_name": threat_name,
            "threat_type": threat_type,   // MALWARE / RANSOMWARE / SPYWARE / ROOTKIT / BACKDOOR
            "action": "QUARANTINED",
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        self.post("/api/v1/blue/quarantine", &body).await
    }

    /// Laporkan deteksi ransomware behavior (mass file encryption)
    pub async fn report_ransomware_detected(
        &self, process_name: &str, files_affected: u32,
        action_taken: &str,
    ) -> Result<ApiResponse, ZentyError> {
        let body = json!({
            "process_name": process_name,
            "files_affected": files_affected,
            "action_taken": action_taken,
            "threat_type": "RANSOMWARE",
            "severity": "CRITICAL",
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        self.post("/api/v1/blue/ransomware-alert", &body).await
    }

    /// Laporkan deteksi spyware / keylogger
    pub async fn report_spyware_detected(
        &self, process_name: &str, spyware_type: &str,
        action_taken: &str,
    ) -> Result<ApiResponse, ZentyError> {
        let body = json!({
            "process_name": process_name,
            "spyware_type": spyware_type,  // KEYLOGGER / SCREEN_CAPTURE / DATA_EXFIL
            "action_taken": action_taken,
            "threat_type": "SPYWARE",
            "severity": "CRITICAL",
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        self.post("/api/v1/blue/spyware-alert", &body).await
    }

    /// Laporkan deteksi rootkit
    pub async fn report_rootkit_detected(
        &self, detection_method: &str, kernel_level: bool,
        action_taken: &str,
    ) -> Result<ApiResponse, ZentyError> {
        let body = json!({
            "detection_method": detection_method,
            "kernel_level": kernel_level,
            "action_taken": action_taken,
            "threat_type": "ROOTKIT",
            "severity": "CRITICAL",
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        self.post("/api/v1/blue/rootkit-alert", &body).await
    }

    // ─────────────────────────────────────────────────────
    //  AUTO-REMEDIATION
    // ─────────────────────────────────────────────────────

    /// Minta Blue Team AI untuk generate patch suggestion
    pub async fn request_auto_remediation(
        &self, vulnerability_id: &str, context: &str,
    ) -> Result<String, ZentyError> {
        let body = json!({
            "vulnerability_id": vulnerability_id,
            "context": context,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        #[derive(serde::Deserialize)]
        struct RemediationResponse { suggestion: String }
        let url = format!("{}/api/v1/blue/auto-remediate", self.base_url);
        let [auth, tenant, role] = self.auth_headers();
        let res = self.http.post(&url)
            .header("Authorization", auth.1)
            .header("X-Zenty-Tenant", tenant.1)
            .header("X-Zenty-Agent-Role", role.1)
            .json(&body)
            .send().await?;
        let r: RemediationResponse = res.json().await?;
        Ok(r.suggestion)
    }

    // ─────────────────────────────────────────────────────
    //  INTEGRITY SCANNER
    // ─────────────────────────────────────────────────────

    /// Kirim artifact ke gplay.ctar.tech untuk dipindai sebelum deploy
    pub async fn scan_artifact(
        &self, file_name: &str, file_bytes: &[u8],
    ) -> Result<ArtefactScanResult, ZentyError> {
        use sha2::{Sha256, Digest};
        let hash = hex::encode(Sha256::digest(file_bytes));
        let body = json!({
            "file_name": file_name,
            "file_hash_sha256": hash,
            "file_size_bytes": file_bytes.len(),
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        let url = format!("{}/api/v1/blue/scan-artifact", self.base_url);
        let [auth, tenant, role] = self.auth_headers();
        let res = self.http.post(&url)
            .header("Authorization", auth.1)
            .header("X-Zenty-Tenant", tenant.1)
            .header("X-Zenty-Agent-Role", role.1)
            .json(&body)
            .send().await?;
        Ok(res.json::<ArtefactScanResult>().await?)
    }

    // ─────────────────────────────────────────────────────
    //  LOW-LEVEL DEFENSE & ACTIVE DECEPTION EXTENSIONS
    // ─────────────────────────────────────────────────────

    /// Laporkan deteksi Memory Injection (Process Hollowing / Reflective DLL / AMSI bypass)
    pub async fn report_memory_injection_alert(
        &self,
        pid: u32,
        process_name: &str,
        technique: &str,
        unbacked_address: &str,
    ) -> Result<ApiResponse, ZentyError> {
        let body = json!({
            "event_type": "MEMORY_INJECTION_ALERT",
            "pid": pid,
            "process_name": process_name,
            "technique": technique,
            "mitre_id": "T1055",
            "unbacked_memory_address": unbacked_address,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        self.post("/api/v1/blue/rootkit-alert", &body).await
    }

    /// Laporkan anomali Parent-Child / Living-off-the-Land (LotL)
    pub async fn report_lotl_anomaly(
        &self,
        parent_process: &str,
        child_process: &str,
        command_line: &str,
        severity: Severity,
    ) -> Result<ApiResponse, ZentyError> {
        let body = json!({
            "event_type": "LOTL_PARENT_CHILD_ANOMALY",
            "parent_process": parent_process,
            "child_process": child_process,
            "command_line": command_line,
            "mitre_id": "T1059",
            "severity": severity,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        self.post("/api/v1/blue/anomaly", &body).await
    }

    /// Laporkan interaksi penyerang dengan Honey-Token (Active Deception)
    pub async fn report_honey_token_triggered(
        &self,
        token_type: &str,
        token_id: &str,
        source_ip: &str,
        details: &str,
    ) -> Result<ApiResponse, ZentyError> {
        let body = json!({
            "event_type": "HONEY_TOKEN_TRIGGERED",
            "token_type": token_type,
            "token_id": token_id,
            "source_ip": source_ip,
            "mitre_id": "T1078",
            "details": details,
            "action": "TRAP_ENGAGED",
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        self.post("/api/v1/blue/anomaly", &body).await
    }
}

