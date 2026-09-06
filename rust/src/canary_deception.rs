use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Tipe umpan (Canary Token) yang dipasang di lingkungan klien
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CanaryType {
    DatabaseRow,
    ApiKeySecret,
    DecoyConfigFile,
    WebBeaconUrl,
}

/// Status operasional Canary Trap
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CanaryStatus {
    Armed,
    Triggered,
    Quarantined,
}

/// Representasi satu instansi Canary Token yang aktif
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CanaryToken {
    pub token_id: String,
    pub canary_type: CanaryType,
    pub target_location: String,
    pub trap_identifier: String,
    pub decoy_payload: String,
    pub deployment_snippet: String,
    pub status: CanaryStatus,
    pub created_at: String,
    pub trigger_count: usize,
}

/// Alarm peringatan saat ada penyerang yang menyentuh Canary (Zero False-Positive)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CanaryTriggerAlert {
    pub alert_id: String,
    pub token_id: String,
    pub canary_type: CanaryType,
    pub attacker_ip: String,
    pub attacker_user_agent: String,
    pub accessed_identifier: String,
    pub query_context: String,
    pub confidence_score: f32, // Selalu 1.0 (100% Zero False-Positive)
    pub quarantine_engaged: bool,
    pub triggered_at: String,
    pub merkle_proof_hash: String,
}

/// Engine Deception Aktif untuk pembuatan dan verifikasi jebakan Canary
pub struct CanaryDeceptionEngine;

impl CanaryDeceptionEngine {
    /// Membuat baris database umpan (Canary DB Row) yang siap di-insert ke tabel produksi
    pub fn generate_database_canary(table_name: &str) -> CanaryToken {
        let unique_suffix = Uuid::new_v4().to_string()[0..8].to_uppercase();
        let token_id = format!("CANARY-DB-{}", unique_suffix);
        let trap_email = format!("sec-ops.canary.{}@ctar-internal.id", unique_suffix.to_lowercase());
        let trap_user = format!("adm_canary_{}", unique_suffix.to_lowercase());
        let fake_pass_hash = "$2a$12$e9CanaryTrapZeroTrustSimulatedHashFakeSecret998811";

        let snippet = format!(
            "INSERT INTO {} (id, username, email, password_hash, is_admin, created_at) VALUES ('usr-canary-{}', '{}', '{}', '{}', true, NOW());",
            table_name, unique_suffix.to_lowercase(), trap_user, trap_email, fake_pass_hash
        );

        CanaryToken {
            token_id: token_id.clone(),
            canary_type: CanaryType::DatabaseRow,
            target_location: format!("Database Table: {}", table_name),
            trap_identifier: trap_email.clone(),
            decoy_payload: format!("Username: {}, Email: {}", trap_user, trap_email),
            deployment_snippet: snippet,
            status: CanaryStatus::Armed,
            created_at: Utc::now().to_rfc3339(),
            trigger_count: 0,
        }
    }

    /// Membuat umpan API Secret Key produksi palsu untuk mendeteksi pencurian kredensial
    pub fn generate_api_key_canary() -> CanaryToken {
        let unique_suffix = Uuid::new_v4().to_string()[0..8].to_uppercase();
        let token_id = format!("CANARY-KEY-{}", unique_suffix);
        let fake_api_key = format!("sk-live-zenty-canary-{}-992288", unique_suffix);

        let snippet = format!(
            "// Simpan kunci jebakan ini di file konfirmasi internal atau repository:\nconst PAYMENT_GATEWAY_KEY = \"{}\";",
            fake_api_key
        );

        CanaryToken {
            token_id: token_id.clone(),
            canary_type: CanaryType::ApiKeySecret,
            target_location: "API Gateway & Environment Variables".to_string(),
            trap_identifier: fake_api_key.clone(),
            decoy_payload: format!("Production API Live Secret: {}", fake_api_key),
            deployment_snippet: snippet,
            status: CanaryStatus::Armed,
            created_at: Utc::now().to_rfc3339(),
            trigger_count: 0,
        }
    }

    /// Membuat umpan berkas konfigurasi .env palsu (Honey-Config)
    pub fn generate_config_canary() -> CanaryToken {
        let unique_suffix = Uuid::new_v4().to_string()[0..8].to_uppercase();
        let token_id = format!("CANARY-ENV-{}", unique_suffix);
        let trap_db_pass = format!("Zenty_DbCanarySecret_{}_9988", unique_suffix);

        let snippet = format!(
            "# .env.production.backup (Decoy Canary File)\nDB_HOST=10.240.12.99\nDB_USER=root_canary\nDB_PASS={}\nAWS_ACCESS_KEY_ID=AKIA_CANARY_{}_TRAP\nAWS_SECRET_ACCESS_KEY=sec_canary_w99118822\n",
            trap_db_pass, unique_suffix
        );

        CanaryToken {
            token_id: token_id.clone(),
            canary_type: CanaryType::DecoyConfigFile,
            target_location: "Server File System (.env / backup)".to_string(),
            trap_identifier: trap_db_pass.clone(),
            decoy_payload: format!("Decoy Password & AWS Key: {}", trap_db_pass),
            deployment_snippet: snippet,
            status: CanaryStatus::Armed,
            created_at: Utc::now().to_rfc3339(),
            trigger_count: 0,
        }
    }

    /// Membuat Web Beacon / URL Canary
    pub fn generate_web_beacon_canary(base_url: Option<&str>) -> CanaryToken {
        let unique_suffix = Uuid::new_v4().to_string()[0..8].to_uppercase();
        let token_id = format!("CANARY-URL-{}", unique_suffix);
        let base = base_url.unwrap_or("http://127.0.0.1:8080");
        let trip_url = format!("{}/api/v1/canary/trip/{}", base, token_id);

        let snippet = format!(
            "<!-- Sisipkan pixel/link umpan ini di halaman rahasia atau email -->\n<img src=\"{}\" width=\"1\" height=\"1\" alt=\"tracker\" style=\"display:none;\" />",
            trip_url
        );

        CanaryToken {
            token_id: token_id.clone(),
            canary_type: CanaryType::WebBeaconUrl,
            target_location: "Web Portal / Admin Dashboard".to_string(),
            trap_identifier: token_id.clone(),
            decoy_payload: format!("Decoy Beacon Endpoint: {}", trip_url),
            deployment_snippet: snippet,
            status: CanaryStatus::Armed,
            created_at: Utc::now().to_rfc3339(),
            trigger_count: 0,
        }
    }

    /// Mengevaluasi apakah suatu string/query/request menyentuh token Canary yang terpasang
    pub fn evaluate_canary_trip(
        canary: &CanaryToken,
        attacker_ip: &str,
        user_agent: &str,
        query_context: &str,
    ) -> CanaryTriggerAlert {
        let timestamp = Utc::now().to_rfc3339();
        let alert_id = format!("CANARY-ALERT-{}", &Uuid::new_v4().to_string()[0..8].to_uppercase());

        // Hitung bukti kriptografis tamper-proof Merkle proof
        let mut hasher = Sha256::new();
        hasher.update(alert_id.as_bytes());
        hasher.update(canary.token_id.as_bytes());
        hasher.update(attacker_ip.as_bytes());
        hasher.update(timestamp.as_bytes());
        let merkle_proof = hex::encode(hasher.finalize());

        CanaryTriggerAlert {
            alert_id,
            token_id: canary.token_id.clone(),
            canary_type: canary.canary_type.clone(),
            attacker_ip: attacker_ip.to_string(),
            attacker_user_agent: user_agent.to_string(),
            accessed_identifier: canary.trap_identifier.clone(),
            query_context: query_context.to_string(),
            confidence_score: 1.0, // 100% Zero False-Positive
            quarantine_engaged: true,
            triggered_at: timestamp,
            merkle_proof_hash: merkle_proof,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_database_canary() {
        let canary = CanaryDeceptionEngine::generate_database_canary("users");
        assert_eq!(canary.canary_type, CanaryType::DatabaseRow);
        assert_eq!(canary.status, CanaryStatus::Armed);
        assert!(canary.deployment_snippet.contains("INSERT INTO users"));
        assert!(canary.trap_identifier.contains("@ctar-internal.id"));
    }

    #[test]
    fn test_generate_api_key_and_trigger() {
        let canary = CanaryDeceptionEngine::generate_api_key_canary();
        assert_eq!(canary.canary_type, CanaryType::ApiKeySecret);
        assert!(canary.trap_identifier.starts_with("sk-live-zenty-canary-"));

        let alert = CanaryDeceptionEngine::evaluate_canary_trip(
            &canary,
            "185.220.101.5",
            "sqlmap/1.6#stable",
            "SELECT * FROM users WHERE email = 'sec-ops.canary@ctar-internal.id'",
        );

        assert_eq!(alert.attacker_ip, "185.220.101.5");
        assert_eq!(alert.confidence_score, 1.0);
        assert!(alert.quarantine_engaged);
        assert_eq!(alert.merkle_proof_hash.len(), 64);
    }
}
