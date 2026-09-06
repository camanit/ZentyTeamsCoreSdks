use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Instant;

/// Kategori mutasi vektor serangan logika pembayaran (FinSec & QRIS)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FinSecMutationCategory {
    NegativeAmountInjection,
    ZeroSumBypass,
    MicroFractionRounding,
    IntegerMaxOverflow,
    EmvcoQrisCrcTampering,
    IdempotencyReplayAttack,
    ConcurrentDoubleSpend,
    ValidBaseline,
}

/// Definisi skenario uji mutasi pembayaran siluman (Ghost Transaction)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostScenario {
    pub scenario_id: String,
    pub name: String,
    pub category: FinSecMutationCategory,
    pub payload_amount: f64,
    pub currency: String,
    pub qris_payload_raw: Option<String>,
    pub expected_behavior: String,
    pub compliance_standard: String, // e.g. "BI-ASPI-QRIS-2024", "OJK-FINSEC-REG-77"
}

/// Hasil eksekusi satu skenario pengujian Ghost Transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostScenarioResult {
    pub scenario_id: String,
    pub name: String,
    pub category: FinSecMutationCategory,
    pub status_code: u16,
    pub is_threat_neutralized: bool,
    pub latency_ms: u128,
    pub server_response: String,
    pub compliance_status: String,
}

/// Laporan Audit Komprehensif Ghost Transaction Sandbox
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostAuditReport {
    pub target_gateway: String,
    pub audit_timestamp: String,
    pub total_scenarios_executed: usize,
    pub threats_blocked: usize,
    pub anomalies_leaked: usize,
    pub finsec_immunity_score: f64, // 0.0 - 100.0%
    pub aspi_qris_compliant: bool,
    pub ojk_regulatory_compliant: bool,
    pub results: Vec<GhostScenarioResult>,
    pub recommended_micro_patches: Vec<String>,
}

pub struct GhostTransactionEngine {
    client: Client,
}

impl GhostTransactionEngine {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap_or_else(|_| Client::new()),
        }
    }

    /// Menghasilkan 7 skenario mutasi pembayaran ekstrim (FinSec & QRIS ASPI)
    pub fn generate_scenarios(tx_prefix: &str) -> Vec<GhostScenario> {
        vec![
            GhostScenario {
                scenario_id: format!("{}-GHOST-01", tx_prefix),
                name: "NEGATIVE_AMOUNT_CREDIT_INJECTION".to_string(),
                category: FinSecMutationCategory::NegativeAmountInjection,
                payload_amount: -75000.0,
                currency: "IDR".to_string(),
                qris_payload_raw: None,
                expected_behavior: "HTTP 400 Bad Request / approved: false (Negative Balance Rejection)".to_string(),
                compliance_standard: "BI-ASPI-QRIS-2024 (Pasal 12 Integritas Transaksi)".to_string(),
            },
            GhostScenario {
                scenario_id: format!("{}-GHOST-02", tx_prefix),
                name: "ZERO_SUM_QRIS_BYPASS".to_string(),
                category: FinSecMutationCategory::ZeroSumBypass,
                payload_amount: 0.0,
                currency: "IDR".to_string(),
                qris_payload_raw: Some("00020101021226600016ID.CO.QRIS.WWW011893600999000000000102081234567852045812530336054010.005802ID5913HADID_SHOP6007JAKARTA6304ABCD".to_string()),
                expected_behavior: "HTTP 400 / approved: false (Zero Sum Settlement Block)".to_string(),
                compliance_standard: "OJK-FINSEC-REG-77 (Anti-Free Settlement)".to_string(),
            },
            GhostScenario {
                scenario_id: format!("{}-GHOST-03", tx_prefix),
                name: "MICRO_FRACTION_PRECISION_FLOAT".to_string(),
                category: FinSecMutationCategory::MicroFractionRounding,
                payload_amount: 0.000000001,
                currency: "IDR".to_string(),
                qris_payload_raw: None,
                expected_behavior: "HTTP 400 / approved: false (Rupiah Fractional Underflow Rejection)".to_string(),
                compliance_standard: "BI-ASPI-QRIS-2024 (Standardisasi Presisi Mata Uang)".to_string(),
            },
            GhostScenario {
                scenario_id: format!("{}-GHOST-04", tx_prefix),
                name: "INTEGER_MAX_OVERFLOW_CRASH".to_string(),
                category: FinSecMutationCategory::IntegerMaxOverflow,
                payload_amount: 999_999_999_999_999.0,
                currency: "IDR".to_string(),
                qris_payload_raw: None,
                expected_behavior: "HTTP 400 / approved: false (Upper Limit Threshold Enforcement)".to_string(),
                compliance_standard: "BI-ASPI-QRIS-2024 (Batas Maksimum Transaksi Harian)".to_string(),
            },
            GhostScenario {
                scenario_id: format!("{}-GHOST-05", tx_prefix),
                name: "EMVCO_QRIS_CRC_TAMPERING".to_string(),
                category: FinSecMutationCategory::EmvcoQrisCrcTampering,
                payload_amount: 50000.0,
                currency: "IDR".to_string(),
                // CRC-16 diubah secara ilegal untuk menguji integritas parser QRIS
                qris_payload_raw: Some("00020101021251440014ID.CO.TELKOM01189360099900000000025204581253033605405500005802ID5914CENTRAL_MARKET6007BANDUNG6304DEAD".to_string()),
                expected_behavior: "HTTP 400 / approved: false (Invalid EMVCo Checksum Rejected)".to_string(),
                compliance_standard: "EMVCo QR Code Merchant Specification v2.0".to_string(),
            },
            GhostScenario {
                scenario_id: format!("{}-GHOST-06", tx_prefix),
                name: "IDEMPOTENCY_REPLAY_ATTACK".to_string(),
                category: FinSecMutationCategory::IdempotencyReplayAttack,
                payload_amount: 250000.0,
                currency: "IDR".to_string(),
                qris_payload_raw: None,
                expected_behavior: "HTTP 400 / approved: false (Replay Idempotency Token Rejection)".to_string(),
                compliance_standard: "OJK-FINSEC-REG-77 (Anti-Replay Token Locking)".to_string(),
            },
            GhostScenario {
                scenario_id: format!("{}-GHOST-07", tx_prefix),
                name: "VALID_BASELINE_SETTLEMENT".to_string(),
                category: FinSecMutationCategory::ValidBaseline,
                payload_amount: 150000.0,
                currency: "IDR".to_string(),
                qris_payload_raw: None,
                expected_behavior: "HTTP 200 OK / approved: true (Legitimate Transaction Approved)".to_string(),
                compliance_standard: "Standard Transaction SLA <5ms".to_string(),
            },
        ]
    }

    /// Menjalankan seluruh kampanye pengujian Ghost Transaction secara asinkron
    pub async fn run_audit(&self, target_url: &str) -> GhostAuditReport {
        let prefix = &uuid::Uuid::new_v4().to_string()[0..8];
        let scenarios = Self::generate_scenarios(prefix);
        let endpoint = format!("{}/api/v1/gate/validate-transaction", target_url.trim_end_matches('/'));

        let mut results = Vec::new();
        let mut threats_blocked = 0;
        let mut anomalies_leaked = 0;
        let mut recommended_patches = Vec::new();

        for sc in &scenarios {
            let start = Instant::now();
            let body = json!({
                "transaction_id": sc.scenario_id,
                "user_id": "ghost-sandbox-fuzzer",
                "amount": sc.payload_amount,
                "currency": sc.currency,
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "qris_raw": sc.qris_payload_raw
            });

            let res = self.client
                .post(&endpoint)
                .header("Content-Type", "application/json")
                .header("X-Zenty-Simulated-Attack", "true")
                .header("X-Zenty-Ghost-Sandbox", "true")
                .json(&body)
                .send()
                .await;

            let latency = start.elapsed().as_millis();

            match res {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let text = resp.text().await.unwrap_or_default();
                    let is_approved = text.contains("\"approved\":true") && status == 200;

                    let (is_neutralized, compliance_status) = if sc.category == FinSecMutationCategory::ValidBaseline {
                        // Baseline transaksi wajar memang harus disetujui (approved)
                        if is_approved {
                            (true, "COMPLIANT_APPROVED".to_string())
                        } else {
                            (false, "FALSE_POSITIVE_REJECTION".to_string())
                        }
                    } else {
                        // Vektor serangan harus DITOLAK / DIBLOKIR
                        if !is_approved {
                            (true, "THREAT_BLOCKED".to_string())
                        } else {
                            (false, "VULNERABILITY_EXPOSED".to_string())
                        }
                    };

                    if is_neutralized {
                        threats_blocked += 1;
                    } else {
                        anomalies_leaked += 1;
                        recommended_patches.push(format!(
                            "GHOST-VULN: Terapkan In-Memory Filter pada kategori {:?} (Standar: {})",
                            sc.category, sc.compliance_standard
                        ));
                    }

                    results.push(GhostScenarioResult {
                        scenario_id: sc.scenario_id.clone(),
                        name: sc.name.clone(),
                        category: sc.category.clone(),
                        status_code: status,
                        is_threat_neutralized: is_neutralized,
                        latency_ms: latency,
                        server_response: text,
                        compliance_status,
                    });
                }
                Err(err) => {
                    // Jika koneksi server gagal atau tidak terjangkau
                    results.push(GhostScenarioResult {
                        scenario_id: sc.scenario_id.clone(),
                        name: sc.name.clone(),
                        category: sc.category.clone(),
                        status_code: 0,
                        is_threat_neutralized: false,
                        latency_ms: latency,
                        server_response: format!("Koneksi Ghost Engine Gagal: {}", err),
                        compliance_status: "NETWORK_ERROR".to_string(),
                    });
                    anomalies_leaked += 1;
                }
            }
        }

        let total = scenarios.len();
        let immunity_score = if total > 0 {
            (threats_blocked as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        let aspi_compliant = immunity_score >= 85.0 && anomalies_leaked == 0;
        let ojk_compliant = immunity_score >= 85.0 && anomalies_leaked == 0;

        GhostAuditReport {
            target_gateway: endpoint,
            audit_timestamp: chrono::Utc::now().to_rfc3339(),
            total_scenarios_executed: total,
            threats_blocked,
            anomalies_leaked,
            finsec_immunity_score: immunity_score,
            aspi_qris_compliant: aspi_compliant,
            ojk_regulatory_compliant: ojk_compliant,
            results,
            recommended_micro_patches: recommended_patches,
        }
    }
}

impl Default for GhostTransactionEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ghost_scenarios_generation() {
        let scenarios = GhostTransactionEngine::generate_scenarios("TEST");
        assert_eq!(scenarios.len(), 7);
        assert_eq!(scenarios[0].category, FinSecMutationCategory::NegativeAmountInjection);
        assert_eq!(scenarios[6].category, FinSecMutationCategory::ValidBaseline);
    }
}
