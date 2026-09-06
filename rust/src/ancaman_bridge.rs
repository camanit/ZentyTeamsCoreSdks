use crate::client::ZentyTeamsClient;
use crate::error::ZentyError;
use crate::types::{ApiResponse, ArtefactScanResult};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Representasi ancaman hasil deteksi Antivirus ANCAMAN AV (Ring-0 / Ring-3)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AncamanThreatReport {
    pub threat_id: String,
    pub file_path: String,
    pub file_hash_sha256: String,
    pub threat_name: String,
    pub threat_family: String, // e.g. "RANSOMWARE", "SPYWARE", "ROOTKIT", "TROJAN", "INJECTOR"
    pub ring_level: u8,        // 0 = Kernel WDK / eBPF, 3 = User Mode RASP / Scanner
    pub detection_engine: String,
    pub action_taken: String,  // "QUARANTINED", "PROCESS_KILLED", "MEMORY_UNHOOKED", "BLOCKED"
    pub timestamp: String,
}

impl Default for AncamanThreatReport {
    fn default() -> Self {
        Self {
            threat_id: format!("ANC-{}", Uuid::new_v4().to_string()[0..8].to_uppercase()),
            file_path: String::new(),
            file_hash_sha256: String::new(),
            threat_name: "Generic.Suspicious".to_string(),
            threat_family: "MALWARE".to_string(),
            ring_level: 3,
            detection_engine: "ANCAMAN_ENGINE_CORE_V1".to_string(),
            action_taken: "QUARANTINED".to_string(),
            timestamp: Utc::now().to_rfc3339(),
        }
    }
}

/// Bridge untuk mengintegrasikan engine ANCAMAN AV (Milestone 3B)
/// Mendukung koneksi online HTTP ke Axum Server maupun Offline Air-Gapped file sync (ThinkPad T410)
pub struct AncamanBridge {
    client: ZentyTeamsClient,
}

impl AncamanBridge {
    pub fn new(client: ZentyTeamsClient) -> Self {
        Self { client }
    }

    /// Kirimkan laporan deteksi ANCAMAN AV ke Central Server Gateway
    pub async fn submit_threat(&self, report: &AncamanThreatReport) -> Result<ApiResponse, ZentyError> {
        let scan_result = ArtefactScanResult {
            scan_id: report.threat_id.clone(),
            file_name: report.file_path.clone(),
            file_hash_sha256: report.file_hash_sha256.clone(),
            is_clean: false,
            threats_found: vec![format!("{}:{}", report.threat_family, report.threat_name)],
            scan_engine_version: format!("{} (Ring-{})", report.detection_engine, report.ring_level),
            timestamp: Utc::now(),
        };

        // Kirim hasil scan
        let res = self.client.report_av_scan(scan_result).await?;

        // Jika ada aksi karantina, sinkronkan ke endpoint quarantine
        let _ = self.client.report_quarantine(
            &report.file_path,
            &report.file_hash_sha256,
            &report.threat_name,
            &report.threat_family,
        ).await;

        Ok(res)
    }

    /// Membaca file telemetry/ancaman drop JSON dari ThinkPad T410 (Offline Air-Gapped Mode)
    pub async fn ingest_airgap_drop_file(&self, file_path: &Path) -> Result<usize, ZentyError> {
        if !file_path.exists() {
            return Err(ZentyError::AirgapError("File drop telemetri tidak ditemukan".to_string()));
        }

        let raw_content = fs::read_to_string(file_path)?;

        let reports: Vec<AncamanThreatReport> = serde_json::from_str(&raw_content)?;

        let mut ingested_count = 0;
        for r in &reports {
            if self.submit_threat(r).await.is_ok() {
                ingested_count += 1;
            }
        }

        Ok(ingested_count)
    }

    /// Menyimpan laporan deteksi lokal ke folder sinkronisasi air-gapped (misal USB drive / transfer antar laptop)
    pub fn export_airgap_drop_file(
        reports: &[AncamanThreatReport],
        dest_dir: &Path,
    ) -> Result<PathBuf, ZentyError> {
        if !dest_dir.exists() {
            let _ = fs::create_dir_all(dest_dir);
        }

        let file_name = format!("ancaman_sync_{}.json", Utc::now().format("%Y%m%d_%H%M%S"));
        let target_path = dest_dir.join(file_name);

        let json_str = serde_json::to_string_pretty(reports)?;

        fs::write(&target_path, json_str)?;

        Ok(target_path)
    }
}
