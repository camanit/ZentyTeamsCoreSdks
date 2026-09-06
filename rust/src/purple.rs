use crate::client::ZentyTeamsClient;
use crate::types::*;
use crate::error::ZentyError;
use serde_json::json;
use sha2::{Sha256, Digest};

/// Purple Team — SELALU AKTIF di semua phase.
/// Merekam, menghubungkan, dan menganalisa semua event dari Red, Blue, Dark Intel.
impl ZentyTeamsClient {

    // ─────────────────────────────────────────────────────
    //  MERKLE CHAIN TELEMETRY
    // ─────────────────────────────────────────────────────

    /// Kirim telemetry event ke Merkle Chain Audit Ledger.
    /// Setiap event di-hash dan di-chain — anti-tamper, tidak bisa dimanipulasi.
    pub async fn send_telemetry(
        &self,
        category: &str,
        payload: serde_json::Value,
        previous_hash: Option<String>,
    ) -> Result<TelemetryEvent, ZentyError> {
        // Hitung SHA-256 dari payload untuk chain integrity
        let payload_str = payload.to_string();
        let hash = hex::encode(Sha256::digest(payload_str.as_bytes()));

        let event = TelemetryEvent {
            event_id:      uuid::Uuid::new_v4().to_string(),
            source:        self.role.clone(),
            category:      category.to_string(),
            payload:       payload.clone(),
            payload_hash:  hash,
            previous_hash,
            timestamp:     chrono::Utc::now(),
        };

        self.post("/api/v1/purple/telemetry", &event).await?;
        Ok(event)
    }

    // ─────────────────────────────────────────────────────
    //  BATTLE SESSION MANAGEMENT
    // ─────────────────────────────────────────────────────

    /// Mulai sesi battle baru — Purple mulai merekam
    pub async fn start_battle_session(
        &self, target: &str, phase: BattlePhase,
        operator: &str, scope_notes: &str,
    ) -> Result<String, ZentyError> {
        let body = json!({
            "target": target,
            "phase": phase,
            "operator": operator,
            "scope_notes": scope_notes,
            "started_at": chrono::Utc::now().to_rfc3339(),
        });
        #[derive(serde::Deserialize)]
        struct SessionResp { session_id: String }
        let url = format!("{}/api/v1/purple/session/start", self.base_url);
        let [auth, tenant, role] = self.auth_headers();
        let res = self.http.post(&url)
            .header("Authorization", auth.1)
            .header("X-Zenty-Tenant", tenant.1)
            .header("X-Zenty-Agent-Role", role.1)
            .json(&body).send().await?;
        let r: SessionResp = res.json().await?;
        Ok(r.session_id)
    }

    /// Akhiri sesi battle — Purple generate laporan otomatis
    pub async fn end_battle_session(
        &self, session_id: &str,
    ) -> Result<ApiResponse, ZentyError> {
        let body = json!({
            "session_id": session_id,
            "ended_at": chrono::Utc::now().to_rfc3339(),
        });
        self.post("/api/v1/purple/session/end", &body).await
    }

    // ─────────────────────────────────────────────────────
    //  RISK MATRIX & SCORING
    // ─────────────────────────────────────────────────────

    /// Minta Purple Team AI kalkulasi Risk Matrix dari session
    pub async fn get_risk_matrix(
        &self, session_id: &str,
    ) -> Result<serde_json::Value, ZentyError> {
        self.get(&format!("/api/v1/purple/risk-matrix/{}", session_id)).await
    }

    /// Korelasikan attack event dengan defense event
    pub async fn correlate_events(
        &self, attack_event_id: &str, defense_event_id: &str,
        outcome: &str,
    ) -> Result<ApiResponse, ZentyError> {
        let body = json!({
            "attack_event_id": attack_event_id,
            "defense_event_id": defense_event_id,
            "outcome": outcome,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        self.post("/api/v1/purple/correlate", &body).await
    }

    // ─────────────────────────────────────────────────────
    //  REPORT GENERATION
    // ─────────────────────────────────────────────────────

    /// Minta Purple generate laporan komprehensif dari session
    pub async fn generate_report(
        &self, session_id: &str, report_type: &str,
    ) -> Result<serde_json::Value, ZentyError> {
        // report_type: "EXECUTIVE" | "TECHNICAL" | "COMPLIANCE" | "FULL"
        self.get(&format!(
            "/api/v1/purple/report/{}/{}",
            session_id, report_type
        )).await
    }

    /// Ambil seluruh audit trail dari session (Merkle chain log)
    pub async fn get_audit_trail(
        &self, session_id: &str,
    ) -> Result<Vec<TelemetryEvent>, ZentyError> {
        self.get(&format!("/api/v1/purple/audit-trail/{}", session_id)).await
    }
}
