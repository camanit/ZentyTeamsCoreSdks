use crate::client::ZentyTeamsClient;
use crate::error::ZentyError;
use crate::types::ApiResponse;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// ═══════════════════════════════════════════════════════════════════════════
/// AUTONOMOUS DEFENSE AI SENTINEL (BLUE SHIELD & DISTRESS BEACON)
///
/// Modul kecerdasan otonom sisi client:
/// 1. Memeriksa setiap payload & transaksi secara otonom (sub-1ms RASP).
/// 2. Menghitung skor anomali & entropi payload (anti-obfuscated attack).
/// 3. Memblokir serangan secara lokal (Auto-Containment) sebelum menyentuh DB.
/// 4. Memancarkan "Sovereign Distress Signal" ke Command Center jika sistem
///    klien diserang masif atau terindikasi lockout/ransomware.
/// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SentinelVerdict {
    /// Trafik normal & aman
    Allow {
        anomaly_score: f64,
    },
    /// Anomali sedang — dicatat ke audit ledger
    Watch {
        anomaly_score: f64,
        indicator: String,
    },
    /// Serangan terdeteksi — diblokir instan di tingkat memori (RASP)
    BlockAndContain {
        threat_score: f64,
        attack_type: String,
        reason: String,
    },
    /// Situasi darurat — serangan berskala sindikat / ancaman lockout
    EmergencyLockdown {
        threat_score: f64,
        distress_signal_id: String,
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SovereignDistressSignal {
    pub signal_id: String,
    pub tenant_id: String,
    pub node_target: String,
    pub threat_level: String,
    pub attack_footprint_hash: String,
    pub recommended_action: String,
    pub timestamp: String,
    pub details: HashMap<String, String>,
}

#[derive(Clone)]
pub struct AutonomousSentinel {
    client: ZentyTeamsClient,
    consecutive_threats: std::sync::Arc<std::sync::atomic::AtomicU32>,
    classifier: crate::ai_fingerprint::AiBehavioralClassifier,
}

impl AutonomousSentinel {
    pub fn new(client: ZentyTeamsClient) -> Self {
        Self {
            client,
            consecutive_threats: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
            classifier: crate::ai_fingerprint::AiBehavioralClassifier::new(),
        }
    }

    /// Akses classifier perilaku AI internal
    pub fn classifier(&self) -> &crate::ai_fingerprint::AiBehavioralClassifier {
        &self.classifier
    }

    /// Evaluasi muatan request secara otonom (RASP Micro-Engine 7 Dimensi)
    pub fn inspect_payload(&self, source_ip: &str, endpoint: &str, payload: &str) -> SentinelVerdict {
        let entropy = calculate_shannon_entropy(payload);
        let mut score: f64 = 0.0;
        let mut attack_type = "UNKNOWN".to_string();
        let mut reason = "Normal behavioral baseline".to_string();

        let lower = payload.to_lowercase();

        // 1. FinSec & QRIS Negative Balance Manipulation Check
        if lower.contains("amount") || lower.contains("nominal") || lower.contains("saldo") {
            if lower.contains("-") || lower.contains("0x") || lower.contains("nan") || lower.contains("infinity") {
                score += 0.85;
                attack_type = "FINSEC_NEGATIVE_BALANCE_TAMPER".to_string();
                reason = "Upaya manipulasi nilai transaksi / race condition saldo".to_string();
            }
        }

        // 2. High-Entropy Obfuscation (Shellcode / Hex Encoded Exploit)
        if entropy > 4.8 && payload.len() > 32 {
            score += 0.65;
            attack_type = "OBFUSCATED_PAYLOAD_DETECTED".to_string();
            reason = format!("Entropi data mencurigakan ({:.2}) terindikasi payload terselubung", entropy);
        }

        // 3. SQL Injection & Bypass Pattern
        if lower.contains("union select") || lower.contains("' or '1'='1") || lower.contains("--") || lower.contains("xp_cmdshell") {
            score += 0.80;
            attack_type = "SQL_INJECTION_AUTOBREACH".to_string();
            reason = "Vektor injeksi database terdeteksi pada muatan request".to_string();
        }

        // 4. Path Traversal & Hostage File Probing
        if payload.contains("../") || payload.contains("..\\") || lower.contains("/etc/shadow") || lower.contains("c:\\windows\\system32") {
            score += 0.88;
            attack_type = "PATH_TRAVERSAL_RANSOM_PROBE".to_string();
            reason = "Penyusupan direktori sistem terdeteksi".to_string();
        }

        // 5. XSS & Script Injection
        let xss_patterns = ["<script", "javascript:", "onerror=", "onload=", "eval(", "document.cookie"];
        for p in &xss_patterns {
            if lower.contains(p) {
                score += 0.70;
                attack_type = "XSS_SCRIPT_INJECTION".to_string();
                reason = "Injeksi skrip berbahaya terdeteksi".to_string();
                break;
            }
        }

        // 6. Command Injection
        let cmd_patterns = ["; ls", "| cat", "&& rm", "$(", "`id`", "wget http", "curl http"];
        for p in &cmd_patterns {
            if lower.contains(p) {
                score += 0.90;
                attack_type = "COMMAND_INJECTION_HOSTAGE".to_string();
                reason = "Percobaan eksekusi perintah sistem (command injection)".to_string();
                break;
            }
        }

        // 7. PILLAR I: Behavioral AI Fingerprinting Dimension
        let ai_score = self.classifier.record_and_classify(source_ip, endpoint, payload, None);
        if ai_score.ai_confidence_score >= 0.40 {
            score = (score + (ai_score.ai_confidence_score * 0.40)) * ai_score.threat_multiplier;
            if attack_type == "UNKNOWN" {
                attack_type = format!("AI_AGENT_DETECTED_{:?}", ai_score.archetype);
                reason = format!(
                    "Perilaku bot/AI otonom terdeteksi (Keyakinan: {:.0}%, Jitter: {:.1}ms)",
                    ai_score.ai_confidence_score * 100.0,
                    ai_score.mean_jitter_ms
                );
            } else {
                reason = format!("{} [AI-Accelerated: {:?}]", reason, ai_score.archetype);
            }
        }

        // Keputusan Otonom
        if score >= 0.80 {
            let count = self.consecutive_threats.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            if count >= 3 {
                // Ancaman berturut-turut — sistem dicurigai sedang diserang sindikat terorganisir
                let signal_id = format!("SIG-DISTRESS-{}", uuid::Uuid::new_v4());
                return SentinelVerdict::EmergencyLockdown {
                    threat_score: score,
                    distress_signal_id: signal_id,
                    reason: format!("Serangan masif berulang ({} ancaman). Sinyal darurat kedaulatan dipancarkan!", count),
                };
            }
            SentinelVerdict::BlockAndContain {
                threat_score: score,
                attack_type,
                reason,
            }
        } else if score >= 0.40 {
            SentinelVerdict::Watch {
                anomaly_score: score,
                indicator: attack_type,
            }
        } else {
            // Reset counter ancaman berulang jika trafik kembali normal
            self.consecutive_threats.store(0, std::sync::atomic::Ordering::SeqCst);
            SentinelVerdict::Allow {
                anomaly_score: score,
            }
        }
    }

    /// Pancarkan Sinyal Darurat Kedaulatan ke Markas Komando (AIControlPlane)
    pub async fn emit_distress_beacon(
        &self,
        node_target: &str,
        incident_summary: &str,
        raw_evidence: &str,
    ) -> Result<ApiResponse, ZentyError> {
        let mut hasher = Sha256::new();
        hasher.update(raw_evidence.as_bytes());
        let footprint_hash = hex::encode(hasher.finalize());

        let signal_id = format!("SIG-DISTRESS-{}", uuid::Uuid::new_v4());
        let mut details = HashMap::new();
        details.insert("incident_summary".to_string(), incident_summary.to_string());
        details.insert("client_timestamp".to_string(), chrono::Utc::now().to_rfc3339());
        details.insert("doctrine_trigger".to_string(), "DEFENSE_BREACH_RECLAIM_SIGNAL".to_string());

        let signal = SovereignDistressSignal {
            signal_id,
            tenant_id: self.client.tenant_id().to_string(),
            node_target: node_target.to_string(),
            threat_level: "CRITICAL_HOSTAGE_RISK".to_string(),
            attack_footprint_hash: footprint_hash,
            recommended_action: "MOBILIZE_SOVEREIGN_RED_RESCUE_PATHFINDER".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            details,
        };

        // Kirim sinyal bahaya ke Markas Komando
        self.client.post("/api/v1/sentinel/distress", &signal).await
    }
}

/// Hitung Shannon Entropy dari sebuah teks payload
fn calculate_shannon_entropy(data: &str) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    for b in data.bytes() {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}
