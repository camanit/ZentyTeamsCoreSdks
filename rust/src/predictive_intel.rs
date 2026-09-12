use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// ═══════════════════════════════════════════════════════════════════════════
/// PILLAR VIII: PREDICTIVE THREAT INTELLIGENCE & ATTACK CAMPAIGN FORECASTING
///
/// Mesin intelijen ancaman prediktif otonom:
/// 1. Threat Campaign Forecasting: Menganalisis recon mikro, memprediksi target
///    berikutnya 15-60 menit sebelum serangan skala penuh.
/// 2. Preemptive Decoy Deployment: Otomatis memasang honeypot & canary di jalur
///    yang diperkirakan akan dilalui penyerang.
/// 3. Behavioral Baseline Drift Detector: Membedakan fluktuasi bisnis wajar
///    vs "slow-and-low" AI reconnaissance tersembunyi.
/// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicroReconObservation {
    pub ip: String,
    pub endpoint: String,
    pub payload_signature: String,
    pub entropy: f64,
    pub cadence_ms: u64,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CampaignPrediction {
    pub campaign_id: String,
    pub suspected_actor_archetype: String,
    pub predicted_target: String,
    pub confidence_score: f64,
    pub estimated_window_minutes: u32,
    pub recommended_countermeasures: Vec<String>,
    pub generated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PreemptiveDecoy {
    pub decoy_id: String,
    pub campaign_id: String,
    pub target_route: String,
    pub decoy_type: String,
    pub deployed_at: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BaselineDriftMetric {
    pub endpoint: String,
    pub baseline_frequency: f64,
    pub current_frequency: f64,
    pub entropy_shift: f64,
    pub drift_detected: bool,
    pub drift_severity: String,
    pub reason: String,
}

#[derive(Clone, Debug, Default)]
pub struct PredictiveIntelEngine {
    observations: Arc<RwLock<Vec<MicroReconObservation>>>,
    campaigns: Arc<RwLock<HashMap<String, CampaignPrediction>>>,
    preemptive_decoys: Arc<RwLock<Vec<PreemptiveDecoy>>>,
    baselines: Arc<RwLock<HashMap<String, f64>>>,
}

impl PredictiveIntelEngine {
    pub fn new() -> Self {
        let mut default_baselines = HashMap::new();
        default_baselines.insert("/api/v1/auth/login".to_string(), 12.0);
        default_baselines.insert("/api/v1/payments/execute".to_string(), 5.0);
        default_baselines.insert("/api/v1/users/profile".to_string(), 25.0);

        Self {
            observations: Arc::new(RwLock::new(Vec::new())),
            campaigns: Arc::new(RwLock::new(HashMap::new())),
            preemptive_decoys: Arc::new(RwLock::new(Vec::new())),
            baselines: Arc::new(RwLock::new(default_baselines)),
        }
    }

    /// 1. Catat observasi micro-recon dan evaluasi kemungkinan kampanye serangan
    pub fn record_observation(&self, obs: MicroReconObservation) -> Option<CampaignPrediction> {
        let mut history = self.observations.write().unwrap();
        history.push(obs.clone());

        // Korelasikan recon dalam 50 observasi terakhir
        let recent: Vec<_> = history.iter().rev().take(30).collect();

        // Deteksi micro-burst cadence: interval teratur antar request (~50ms-200ms)
        let mut cadences = Vec::new();
        let mut endpoints = HashMap::new();

        for item in &recent {
            cadences.push(item.cadence_ms);
            *endpoints.entry(item.endpoint.clone()).or_insert(0usize) += 1;
        }

        let is_cadence_robotic = if cadences.len() >= 3 {
            let avg: f64 = cadences.iter().map(|&x| x as f64).sum::<f64>() / cadences.len() as f64;
            let variance: f64 = cadences.iter().map(|&x| (x as f64 - avg).powi(2)).sum::<f64>() / cadences.len() as f64;
            variance.sqrt() < 25.0 // Sangat presisi (AI robotic timing)
        } else {
            false
        };

        // Identifikasi pola target probing (misal probe auth lalu langsung menuju database/admin)
        let probed_critical_targets = endpoints.keys().any(|ep| {
            ep.contains("login") || ep.contains("admin") || ep.contains("config") || ep.contains("env")
        });

        if is_cadence_robotic || (probed_critical_targets && recent.len() >= 5) {
            let predicted_target = if endpoints.keys().any(|ep| ep.contains("login")) {
                "/api/v1/auth/internal-sso-bypass".to_string()
            } else if endpoints.keys().any(|ep| ep.contains("admin")) {
                "/api/v1/system/database-dump".to_string()
            } else {
                "/api/v1/cloud/metadata-sts".to_string()
            };

            let confidence = if is_cadence_robotic && probed_critical_targets {
                0.94
            } else if is_cadence_robotic {
                0.86
            } else {
                0.75
            };

            let archetype = if obs.entropy > 4.2 {
                "AUTONOMOUS_POLYMORPHIC_AI_CLUSTER"
            } else {
                "SLOW_LOW_AI_RECON_AGENT"
            };

            let mut hasher = Sha256::new();
            hasher.update(format!("{}:{}:{}", obs.ip, predicted_target, chrono::Utc::now().timestamp()).as_bytes());
            let hash_str = hex::encode(hasher.finalize());
            let campaign_id = format!("CMP-PREDICT-{}", &hash_str[..8]);

            let prediction = CampaignPrediction {
                campaign_id: campaign_id.clone(),
                suspected_actor_archetype: archetype.to_string(),
                predicted_target: predicted_target.clone(),
                confidence_score: confidence,
                estimated_window_minutes: 30,
                recommended_countermeasures: vec![
                    format!("DEPLOY_PREEMPTIVE_CANARY on {}", predicted_target),
                    "ACTIVATE_DYNAMIC_MTD_TOKEN_ROTATION".to_string(),
                    "ROUTER_ENFORCE_CAPTCHA_TAR_PIT".to_string(),
                ],
                generated_at: chrono::Utc::now().to_rfc3339(),
            };

            let mut camps = self.campaigns.write().unwrap();
            camps.insert(campaign_id, prediction.clone());
            Some(prediction)
        } else {
            None
        }
    }

    /// 2. Pasang Preemptive Decoy di Jalur yang Diprediksi
    pub fn deploy_preemptive_decoy(&self, campaign: &CampaignPrediction) -> PreemptiveDecoy {
        let decoy = PreemptiveDecoy {
            decoy_id: format!("DCY-PREEMPT-{}", &uuid::Uuid::new_v4().to_string()[..8]),
            campaign_id: campaign.campaign_id.clone(),
            target_route: campaign.predicted_target.clone(),
            decoy_type: "HONEY_CANARY_TRIPWIRE_BEACON".to_string(),
            deployed_at: chrono::Utc::now().to_rfc3339(),
            status: "ARMED_AND_SURVEILLING".to_string(),
        };

        let mut decoys = self.preemptive_decoys.write().unwrap();
        decoys.push(decoy.clone());
        decoy
    }

    /// 3. Deteksi Deviasi Baseline Traffic (Slow-and-Low vs Business Burst)
    pub fn analyze_baseline_drift(
        &self,
        endpoint: &str,
        current_frequency: f64,
        current_entropy: f64,
    ) -> BaselineDriftMetric {
        let baselines = self.baselines.read().unwrap();
        let baseline = baselines.get(endpoint).copied().unwrap_or(10.0);

        let freq_ratio = current_frequency / baseline;
        let entropy_shift = (current_entropy - 3.2).abs();

        let (drift_detected, severity, reason) = if freq_ratio > 3.0 && entropy_shift > 1.0 {
            (
                true,
                "CRITICAL".to_string(),
                "Volumetric anomaly combined with high entropy payload: Suspected automated AI fuzzing attack"
                    .to_string(),
            )
        } else if freq_ratio < 0.2 && entropy_shift > 1.2 {
            (
                true,
                "ELEVATED".to_string(),
                "Slow-and-low reconnaissance detected: Ultra low request frequency with highly anomalous polymorphic entropy"
                    .to_string(),
            )
        } else if freq_ratio > 2.0 {
            (
                false,
                "LOW".to_string(),
                "Business peak traffic: Normal entropy distribution despite frequency rise".to_string(),
            )
        } else {
            (
                false,
                "NORMAL".to_string(),
                "Operating within established statistical baseline".to_string(),
            )
        };

        BaselineDriftMetric {
            endpoint: endpoint.to_string(),
            baseline_frequency: baseline,
            current_frequency,
            entropy_shift,
            drift_detected,
            drift_severity: severity,
            reason,
        }
    }

    /// Ambil seluruh prediksi serangan aktif
    pub fn get_active_predictions(&self) -> Vec<CampaignPrediction> {
        let camps = self.campaigns.read().unwrap();
        camps.values().cloned().collect()
    }

    /// Ambil seluruh decoy preemptive yang terpasang
    pub fn get_active_decoys(&self) -> Vec<PreemptiveDecoy> {
        let decoys = self.preemptive_decoys.read().unwrap();
        decoys.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_predictive_campaign_forecasting() {
        let engine = PredictiveIntelEngine::new();

        // Simulasikan micro-recon robotic cadence (inter-arrival time ~100ms)
        let mut last_prediction = None;
        for i in 0..5 {
            let obs = MicroReconObservation {
                ip: "198.51.100.44".to_string(),
                endpoint: "/api/v1/auth/login".to_string(),
                payload_signature: format!("scan_probe_step_{}", i),
                entropy: 4.6,
                cadence_ms: 100, // konsisten
                timestamp: chrono::Utc::now().timestamp(),
            };
            if let Some(pred) = engine.record_observation(obs) {
                last_prediction = Some(pred);
            }
        }

        assert!(last_prediction.is_some());
        let pred = last_prediction.unwrap();
        assert!(pred.campaign_id.starts_with("CMP-PREDICT-"));
        assert_eq!(pred.suspected_actor_archetype, "AUTONOMOUS_POLYMORPHIC_AI_CLUSTER");
        assert!(pred.confidence_score >= 0.85);
        assert_eq!(pred.predicted_target, "/api/v1/auth/internal-sso-bypass");

        // Uji penyebaran decoy preemptive otomatis
        let decoy = engine.deploy_preemptive_decoy(&pred);
        assert!(decoy.decoy_id.starts_with("DCY-PREEMPT-"));
        assert_eq!(decoy.status, "ARMED_AND_SURVEILLING");
        assert_eq!(decoy.target_route, "/api/v1/auth/internal-sso-bypass");
    }

    #[test]
    fn test_baseline_drift_detection() {
        let engine = PredictiveIntelEngine::new();

        // 1. Slow-and-low reconnaissance: frekuensi sangat rendah (0.1 req/s vs baseline 12.0) tapi entropi sangat tinggi
        let slow_recon = engine.analyze_baseline_drift("/api/v1/auth/login", 0.5, 4.8);
        assert!(slow_recon.drift_detected);
        assert_eq!(slow_recon.drift_severity, "ELEVATED");
        assert!(slow_recon.reason.contains("Slow-and-low"));

        // 2. Normal traffic: frekuensi normal, entropi normal
        let normal_traffic = engine.analyze_baseline_drift("/api/v1/auth/login", 12.5, 3.2);
        assert!(!normal_traffic.drift_detected);
        assert_eq!(normal_traffic.drift_severity, "NORMAL");

        // 3. Volumetric AI attack: frekuensi lonjak drastis + entropi tinggi
        let volumetric_attack = engine.analyze_baseline_drift("/api/v1/auth/login", 80.0, 4.5);
        assert!(volumetric_attack.drift_detected);
        assert_eq!(volumetric_attack.drift_severity, "CRITICAL");
    }
}
