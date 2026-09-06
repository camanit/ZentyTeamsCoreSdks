use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Instant;
use tokio::task::JoinSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzTestCase {
    pub name: String,
    pub transaction_id: String,
    pub amount: f64,
    pub currency: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzResult {
    pub test_name: String,
    pub payload_amount: f64,
    pub status_code: u16,
    pub was_blocked: bool,
    pub latency_ms: u128,
    pub server_response: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConcurrencyBurstReport {
    pub target_url: String,
    pub total_requests: usize,
    pub successful_approvals: usize,
    pub blocked_double_spends: usize,
    pub average_latency_ms: f64,
    pub is_atomic_lock_effective: bool,
    pub details: Vec<FuzzResult>,
}

pub struct LogicFuzzer {
    client: Client,
}

impl LogicFuzzer {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap_or_else(|_| Client::new()),
        }
    }

    /// Menghasilkan test cases mutasi batas nominal QRIS / WebPay
    pub fn generate_payment_mutations(tx_prefix: &str) -> Vec<FuzzTestCase> {
        vec![
            FuzzTestCase {
                name: "NEGATIVE_BALANCE_INJECTION".to_string(),
                transaction_id: format!("{}-NEG-1", tx_prefix),
                amount: -50000.0,
                currency: "IDR".to_string(),
                description: "Uji nilai negatif untuk mencoba manipulasi saldo kredit".to_string(),
            },
            FuzzTestCase {
                name: "ZERO_SUM_QRIS_BYPASS".to_string(),
                transaction_id: format!("{}-ZERO-2", tx_prefix),
                amount: 0.0,
                currency: "IDR".to_string(),
                description: "Uji nominal 0.0 rupiah apakah dianggap lunas".to_string(),
            },
            FuzzTestCase {
                name: "MICRO_FRACTION_FLOAT".to_string(),
                transaction_id: format!("{}-FRAC-3", tx_prefix),
                amount: 0.00000001,
                currency: "IDR".to_string(),
                description: "Uji pecahan desimal mikro di bawah satuan mata uang terkecil".to_string(),
            },
            FuzzTestCase {
                name: "INTEGER_MAX_OVERFLOW".to_string(),
                transaction_id: format!("{}-MAX-4", tx_prefix),
                amount: 999_999_999_999.0,
                currency: "IDR".to_string(),
                description: "Uji angka mendekati integer limit untuk trigger crash".to_string(),
            },
            FuzzTestCase {
                name: "NORMAL_STANDARD_PAYMENT".to_string(),
                transaction_id: format!("{}-NORM-5", tx_prefix),
                amount: 150000.0,
                currency: "IDR".to_string(),
                description: "Baseline transaksi wajar yang harus disetujui".to_string(),
            },
        ]
    }

    /// Menjalankan kampanye fuzzing logika pembayaran ke endpoint target
    pub async fn run_payment_fuzz_campaign(
        &self,
        gateway_url: &str,
    ) -> Vec<FuzzResult> {
        let cases = Self::generate_payment_mutations(&uuid::Uuid::new_v4().to_string()[0..8]);
        let mut results = Vec::new();
        let endpoint = format!("{}/api/v1/gate/validate-transaction", gateway_url.trim_end_matches('/'));

        for case in cases {
            let start = Instant::now();
            let body = json!({
                "transaction_id": case.transaction_id,
                "user_id": "fuzzer-agent-red",
                "amount": case.amount,
                "currency": case.currency,
                "timestamp": chrono::Utc::now().to_rfc3339()
            });

            match self.client
                .post(&endpoint)
                .header("Content-Type", "application/json")
                .header("X-Zenty-Simulated-Attack", "true")
                .json(&body)
                .send()
                .await
            {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let text = resp.text().await.unwrap_or_default();
                    let was_blocked = text.contains("\"approved\":false") || status >= 400;
                    results.push(FuzzResult {
                        test_name: case.name,
                        payload_amount: case.amount,
                        status_code: status,
                        was_blocked,
                        latency_ms: start.elapsed().as_millis(),
                        server_response: text,
                    });
                }
                Err(err) => {
                    results.push(FuzzResult {
                        test_name: case.name,
                        payload_amount: case.amount,
                        status_code: 0,
                        was_blocked: true,
                        latency_ms: start.elapsed().as_millis(),
                        server_response: format!("Koneksi gagal / error: {}", err),
                    });
                }
            }
        }

        results
    }

    /// Menjalankan pengujian Concurrency & Race Condition Burst (Simultaneous Tokio Burst)
    pub async fn run_concurrency_burst(
        &self,
        gateway_url: &str,
        burst_size: usize,
    ) -> ConcurrencyBurstReport {
        let endpoint = format!("{}/api/v1/gate/validate-transaction", gateway_url.trim_end_matches('/'));
        // Menggunakan SATU ID Transaksi yang sama persis untuk menguji ketahanan Double-Spending
        let target_tx_id = format!("RACE-BURST-{}", &uuid::Uuid::new_v4().to_string()[0..8]);

        let mut tasks = JoinSet::new();
        let client = self.client.clone();

        for i in 0..burst_size {
            let ep = endpoint.clone();
            let tx_id = target_tx_id.clone();
            let c = client.clone();

            tasks.spawn(async move {
                let start = Instant::now();
                let body = json!({
                    "transaction_id": tx_id,
                    "user_id": format!("user-burst-{}", i),
                    "amount": 250000.0,
                    "currency": "IDR",
                    "timestamp": chrono::Utc::now().to_rfc3339()
                });

                let res = c.post(&ep)
                    .header("Content-Type", "application/json")
                    .header("X-Zenty-Simulated-Attack", "true")
                    .json(&body)
                    .send()
                    .await;

                let latency = start.elapsed().as_millis();
                match res {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let text = resp.text().await.unwrap_or_default();
                        let was_blocked = text.contains("\"approved\":false");
                        (status, was_blocked, latency, text)
                    }
                    Err(e) => (0, true, latency, e.to_string()),
                }
            });
        }

        let mut approvals = 0;
        let mut blocks = 0;
        let mut total_latency = 0;
        let mut details = Vec::new();

        let mut idx = 0;
        while let Some(res) = tasks.join_next().await {
            if let Ok((status, was_blocked, latency, text)) = res {
                total_latency += latency;
                if was_blocked {
                    blocks += 1;
                } else {
                    approvals += 1;
                }

                if details.len() < 10 {
                    details.push(FuzzResult {
                        test_name: format!("BURST_REQ_{}", idx),
                        payload_amount: 250000.0,
                        status_code: status,
                        was_blocked,
                        latency_ms: latency,
                        server_response: text,
                    });
                }
                idx += 1;
            }
        }

        let avg_latency = if burst_size > 0 {
            total_latency as f64 / burst_size as f64
        } else {
            0.0
        };

        // Kunci atomik berhasil jika HANYA 1 yang lolos (approval == 1) dan sisanya (burst_size - 1) diblokir!
        let is_atomic_lock_effective = approvals <= 1 && blocks >= (burst_size - 1);

        ConcurrencyBurstReport {
            target_url: endpoint,
            total_requests: burst_size,
            successful_approvals: approvals,
            blocked_double_spends: blocks,
            average_latency_ms: avg_latency,
            is_atomic_lock_effective,
            details,
        }
    }
}

impl Default for LogicFuzzer {
    fn default() -> Self {
        Self::new()
    }
}
