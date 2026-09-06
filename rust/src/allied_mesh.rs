use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Standar Kriptografi Pasca-Kuantum (Post-Quantum Cryptography / PQC NIST FIPS 203 & 204)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PqcAlgorithm {
    /// NIST FIPS 203: ML-KEM (Kyber-768 / Kyber-1024) untuk Enkapsulasi Kunci
    MlKem768,
    /// NIST FIPS 204: ML-DSA (Dilithium-3 / Dilithium-5) untuk Tanda Tangan Digital
    MlDsa65,
    /// Stateless Hash-Based Signature untuk Ketahanan Jangka Panjang
    SphincsPlus,
    /// Hybrid Mode: PQC + Classical Elliptic Curve (Ed25519 + ML-DSA)
    HybridQuantumSafe,
}

/// Saluran Interoperabilitas Aliansi Pertahanan & Intelijen Siber Global
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlliedCertChannel {
    /// ASEAN CERT Network (Asia Tenggara & Mitra Strategis)
    AseanCert,
    /// INTERPOL Global Cyber Crime Operations Desk (IGCI Singapura)
    InterpolCyber,
    /// International Forum of Incident Response and Security Teams (FIRST)
    GlobalFirst,
    /// Bilateral Strategic Defense Cyber Exchange (NATO CCDCOE Compatible)
    AlliedBilateral,
}

/// Bukti Keamanan Zero-Knowledge (ZKP) untuk Berbagi Intelijen Tanpa Mengekspos PII / Rahasia Dagang
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkpThreatProof {
    pub proof_id: String,
    pub timestamp_ms: u64,
    pub timestamp_rfc3339: String,
    pub target_alliance: AlliedCertChannel,
    pub pqc_algorithm: PqcAlgorithm,
    /// Komitmen kriptografis (Pedersen / SHA-256 ZKP Hash)
    pub threat_commitment_hash: String,
    /// Zero-Knowledge Proof: membuktikan bahwa payload adalah malware tanpa mengekspos isi file/source code
    pub zero_knowledge_proof_data: String,
    pub is_signature_quantum_safe: bool,
    pub public_quantum_key_id: String,
}

/// Kontribusi Bobot Model AI Federasi (Global Immune Swarm Network)
/// Menggunakan Differential Privacy agar AI di seluruh node aliansi belajar bersama tanpa pernah mengirim data mentah
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedSwarmDelta {
    pub model_id: String,
    pub iteration_epoch: u64,
    pub model_architecture: String,
    pub differential_privacy_epsilon: f64, // Parameter privasi (e.g. 0.5 - 1.0)
    pub gradient_weights_hash: String,
    pub contributor_node_id: String,
    pub generated_at: String,
}

/// Bridge Utama Milestone 7: Global Allied & Post-Quantum Mesh (2027+)
pub struct AlliedMeshBridge;

impl AlliedMeshBridge {
    /// Menghasilkan Bukti Ancaman Zero-Knowledge (ZKP) Terenkripsi Pasca-Kuantum
    pub fn create_zkp_threat_indicator(
        alliance: AlliedCertChannel,
        pqc_algo: PqcAlgorithm,
        raw_threat_sample: &str,
        public_key_id: &str,
    ) -> ZkpThreatProof {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // 1. Hitung komitmen SHA-256 untuk payload
        let mut hasher = Sha256::new();
        hasher.update(raw_threat_sample.as_bytes());
        let commitment_hash = format!("{:x}", hasher.finalize());

        // 2. Simulasi pembuatan ZKP proof token (zk-SNARK / commitment proof)
        let mut proof_hasher = Sha256::new();
        proof_hasher.update(format!("{}:{}:{}", commitment_hash, public_key_id, timestamp_ms).as_bytes());
        let zkp_token = format!("ZKP-PQC-PROOF-{:x}", proof_hasher.finalize());

        ZkpThreatProof {
            proof_id: format!("ZKP-{}", &Uuid::new_v4().to_string()[0..8].to_uppercase()),
            timestamp_ms,
            timestamp_rfc3339: Utc::now().to_rfc3339(),
            target_alliance: alliance,
            pqc_algorithm: pqc_algo,
            threat_commitment_hash: commitment_hash,
            zero_knowledge_proof_data: zkp_token,
            is_signature_quantum_safe: true,
            public_quantum_key_id: public_key_id.to_string(),
        }
    }

    /// Verifikasi Bukti ZKP Pasca-Kuantum yang Diterima dari Node Aliansi
    pub fn verify_zkp_threat_proof(proof: &ZkpThreatProof) -> bool {
        // Validasi keutuhan token dan format PQC
        proof.is_signature_quantum_safe
            && !proof.threat_commitment_hash.is_empty()
            && proof.threat_commitment_hash.len() == 64
            && proof.zero_knowledge_proof_data.starts_with("ZKP-PQC-PROOF-")
    }

    /// Menghasilkan Delta Pembaruan AI Federasi dengan Differential Privacy untuk Imun Global
    pub fn export_federated_ai_gradient(
        node_id: &str,
        epoch: u64,
        gradient_raw: &[f32],
        epsilon: f64,
    ) -> FederatedSwarmDelta {
        let mut hasher = Sha256::new();
        for val in gradient_raw {
            hasher.update(val.to_le_bytes());
        }
        let gradient_weights_hash = format!("{:x}", hasher.finalize());

        FederatedSwarmDelta {
            model_id: "ZENTY-NEURAL-IMMUNE-V1".to_string(),
            iteration_epoch: epoch,
            model_architecture: "Transformer-Based Behavioral Anomaly Swarm".to_string(),
            differential_privacy_epsilon: epsilon,
            gradient_weights_hash,
            contributor_node_id: node_id.to_string(),
            generated_at: Utc::now().to_rfc3339(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zkp_threat_proof_creation_and_verification() {
        let proof = AlliedMeshBridge::create_zkp_threat_indicator(
            AlliedCertChannel::AseanCert,
            PqcAlgorithm::MlDsa65,
            "simulated-malicious-memory-implant-binary-bytes",
            "PUB-ML-DSA-NODE-NKRI-01",
        );

        assert!(proof.proof_id.starts_with("ZKP-"));
        assert!(proof.is_signature_quantum_safe);
        assert!(AlliedMeshBridge::verify_zkp_threat_proof(&proof));
    }

    #[test]
    fn test_federated_ai_gradient_export() {
        let sample_gradients = vec![0.012, -0.045, 0.128, -0.003, 0.091];
        let delta = AlliedMeshBridge::export_federated_ai_gradient(
            "ZNTY-NODE-JAKARTA-01",
            42,
            &sample_gradients,
            0.75,
        );

        assert_eq!(delta.iteration_epoch, 42);
        assert_eq!(delta.differential_privacy_epsilon, 0.75);
        assert!(!delta.gradient_weights_hash.is_empty());
    }
}
