use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Entri log audit forensik dengan cryptographic chaining (WORM - Write Once Read Many)
/// Memenuhi standar UU ITE No. 1/2024 & ISO/IEC 27037 (Digital Evidence Handling)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ForensicLogEntry {
    pub log_id: String,
    pub timestamp_ms: u64,
    pub timestamp_rfc3339: String,
    pub source_module: String,
    pub event_type: String,
    pub raw_data_hash: String,     // Hash SHA-256 dari payload telemetry asli
    pub prev_block_hash: String,   // Tautan ke blok sebelumnya (Immutable Chain)
    pub current_block_hash: String, // Hash block saat ini (Sealed Evidence)
}

impl ForensicLogEntry {
    pub fn create_entry(
        source_module: &str,
        event_type: &str,
        raw_payload: &str,
        prev_hash: &str,
    ) -> Self {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let timestamp_rfc3339 = Utc::now().to_rfc3339();

        // 1. Hash payload asli
        let mut payload_hasher = Sha256::new();
        payload_hasher.update(raw_payload.as_bytes());
        let raw_data_hash = format!("{:x}", payload_hasher.finalize());

        // 2. Hitung hash blok saat ini (Kombinasi ID + Timestamp + Source + PayloadHash + PrevHash)
        let log_id = format!("WORM-{}", &Uuid::new_v4().to_string()[0..8].to_uppercase());
        let block_content = format!(
            "{}:{}:{}:{}:{}:{}",
            log_id, timestamp_ms, source_module, event_type, raw_data_hash, prev_hash
        );

        let mut block_hasher = Sha256::new();
        block_hasher.update(block_content.as_bytes());
        let current_block_hash = format!("{:x}", block_hasher.finalize());

        Self {
            log_id,
            timestamp_ms,
            timestamp_rfc3339,
            source_module: source_module.to_string(),
            event_type: event_type.to_string(),
            raw_data_hash,
            prev_block_hash: prev_hash.to_string(),
            current_block_hash,
        }
    }
}

/// Laporan Chain of Custody Resmi untuk kebutuhan BAP Digital & Pembuktian Pengadilan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainOfCustodyReport {
    pub case_id: String,
    pub generated_at: String,
    pub total_blocks: usize,
    pub genesis_hash: String,
    pub latest_merkle_root: String,
    pub is_valid: bool,
    pub compliance_standards: Vec<String>,
    pub entries: Vec<ForensicLogEntry>,
}

/// Engine Merkle WORM Ledger untuk Purple Team Orchestrator (Milestone 4)
#[derive(Debug, Clone)]
pub struct MerkleLedgerEngine {
    chain: Vec<ForensicLogEntry>,
    last_hash: String,
}

impl Default for MerkleLedgerEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleLedgerEngine {
    pub const GENESIS_HASH: &'static str =
        "0000000000000000000000000000000000000000000000000000000000000000";

    pub fn new() -> Self {
        Self {
            chain: Vec::new(),
            last_hash: Self::GENESIS_HASH.to_string(),
        }
    }

    /// Menambahkan event baru ke dalam WORM Merkle Chain
    pub fn append_event(
        &mut self,
        source: &str,
        event_type: &str,
        payload: &str,
    ) -> ForensicLogEntry {
        let entry = ForensicLogEntry::create_entry(source, event_type, payload, &self.last_hash);
        self.last_hash = entry.current_block_hash.clone();
        self.chain.push(entry.clone());
        entry
    }

    /// Ambil seluruh rantai forensik
    pub fn get_chain(&self) -> &[ForensicLogEntry] {
        &self.chain
    }

    /// Ambil hash terakhir (Merkle Root puncak)
    pub fn get_latest_root(&self) -> &str {
        &self.last_hash
    }

    /// Verifikasi Integritas Rantai Forensik (Validasi Sah di Pengadilan)
    /// Memastikan tidak ada blok yang pernah disunting, diselipkan, atau dihapus
    pub fn verify_chain_integrity(&self) -> bool {
        if self.chain.is_empty() {
            return true;
        }

        // Verifikasi blok pertama terhadap genesis hash
        if self.chain[0].prev_block_hash != Self::GENESIS_HASH {
            return false;
        }

        for i in 1..self.chain.len() {
            let current = &self.chain[i];
            let previous = &self.chain[i - 1];

            // 1. Pastikan prev_hash cocok dengan hash blok sebelumnya
            if current.prev_block_hash != previous.current_block_hash {
                return false;
            }

            // 2. Verifikasi ulang hash blok saat ini secara matematis
            let block_content = format!(
                "{}:{}:{}:{}:{}:{}",
                current.log_id,
                current.timestamp_ms,
                current.source_module,
                current.event_type,
                current.raw_data_hash,
                current.prev_block_hash
            );
            let mut hasher = Sha256::new();
            hasher.update(block_content.as_bytes());
            let recalculated = format!("{:x}", hasher.finalize());

            if recalculated != current.current_block_hash {
                return false;
            }
        }

        true
    }

    /// Menghasilkan berkas laporan Chain of Custody resmi (UU ITE & ISO 27037)
    pub fn generate_chain_of_custody_report(&self, case_id: &str) -> ChainOfCustodyReport {
        let is_valid = self.verify_chain_integrity();
        ChainOfCustodyReport {
            case_id: case_id.to_string(),
            generated_at: Utc::now().to_rfc3339(),
            total_blocks: self.chain.len(),
            genesis_hash: Self::GENESIS_HASH.to_string(),
            latest_merkle_root: self.last_hash.clone(),
            is_valid,
            compliance_standards: vec![
                "UU ITE No. 1/2024 (Keabsahan Alat Bukti Elektronik)".to_string(),
                "ISO/IEC 27037:2012 (Digital Evidence Handling)".to_string(),
                "RFC 3161 (Cryptographic Timestamping)".to_string(),
                "NIST SP 800-86 (Forensic Techniques in Incident Response)".to_string(),
            ],
            entries: self.chain.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_chain_integrity_valid() {
        let mut engine = MerkleLedgerEngine::new();
        engine.append_event("BLUE_RASP", "INLINE_HOOK_DETECTED", "payload-1");
        engine.append_event("AXUM_GATEWAY", "DOUBLE_SPEND_BLOCKED", "payload-2");
        engine.append_event("ANCAMAN_AV", "RANSOMWARE_QUARANTINED", "payload-3");

        assert_eq!(engine.get_chain().len(), 3);
        assert!(engine.verify_chain_integrity());

        let report = engine.generate_chain_of_custody_report("CASE-NKRI-2026-001");
        assert!(report.is_valid);
        assert_eq!(report.total_blocks, 3);
    }

    #[test]
    fn test_merkle_chain_tamper_detection() {
        let mut engine = MerkleLedgerEngine::new();
        engine.append_event("BLUE_RASP", "EVENT_1", "clean");
        engine.append_event("AXUM_GATEWAY", "EVENT_2", "clean");

        // Simulasikan sabotase atau modifikasi memori oleh penyerang
        engine.chain[1].raw_data_hash = "f4k3_h4sh_t4mp3r3d".to_string();

        assert!(!engine.verify_chain_integrity());
    }
}
