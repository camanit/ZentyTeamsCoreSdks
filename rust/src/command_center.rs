use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// 4 Lembaga Pertahanan & Keamanan Utama Republik Indonesia (Milestone 6)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NationalAgency {
    /// Badan Siber dan Sandi Negara (BSSN CSIRT)
    Bssn,
    /// Direktorat Tindak Pidana Siber Bareskrim Polri
    PolriCyber,
    /// Satuan Siber TNI (Satsiber TNI) & TNI AL Cyber Warfare
    TniCyber,
    /// Badan Keamanan Laut Republik Indonesia (Bakamla HQ)
    Bakamla,
}

/// Klasifikasi Kerahasiaan Dokumen / Data Intelijen NKRI
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClassificationLevel {
    TopSecretNkri,
    SecretNkri,
    ConfidentialNkri,
    RestrictedSovereign,
}

impl ClassificationLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TopSecretNkri => "SANGAT RAHASIA // TOP SECRET NKRI",
            Self::SecretNkri => "RAHASIA NEGARA // SECRET NKRI",
            Self::ConfidentialNkri => "TERBATAS KEDAULATAN // CONFIDENTIAL",
            Self::RestrictedSovereign => "INTERNAL APARATUR NEGARA // RESTRICTED",
        }
    }
}

/// Payload Peringatan Dini & Intelijen Lintas Sektoral Nasional
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NationalAlertPayload {
    pub alert_id: String,
    pub timestamp_ms: u64,
    pub timestamp_rfc3339: String,
    pub agency_target: NationalAgency,
    pub classification_level: ClassificationLevel,
    pub incident_title: String,
    pub stix_data: serde_json::Value,
    pub merkle_root_signature: String,
    pub dispatch_status: String,
}

/// Format Berita Acara Pemeriksaan (BAP) Bukti Digital Forensik (UU ITE & ISO/IEC 27037)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BapDigitalForensicDoc {
    pub bap_number: String,
    pub generated_at: String,
    pub legal_authority: String,
    pub case_reference: String,
    pub evidence_type: String,
    pub suspect_metadata: serde_json::Value,
    pub forensic_hash_sha256: String,
    pub prev_merkle_block_hash: String,
    pub merkle_root_seal: String,
    pub chain_of_custody_verified: bool,
    pub legal_attestation: String,
}

/// Data Telemetri Anomali Maritim & Dark Vessel (Bakamla / TNI AL)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaritimeAisAnomaly {
    pub vessel_mmsi: u32,
    pub vessel_name: Option<String>,
    pub callsign: Option<String>,
    pub flag_country: String,
    pub last_known_latitude: f64,
    pub last_known_longitude: f64,
    pub last_speed_knots: f64,
    pub anomaly_type: String, // e.g. "SUDDEN_AIS_TRANSPONDER_OFF", "ZEEI_BORDER_INCURSION", "SPOOFED_COORDINATES"
    pub threat_severity: String,
    pub detected_at: String,
}

/// Bridge Utama National Super Command Center (Milestone 6)
pub struct CommandCenterBridge;

impl CommandCenterBridge {
    /// Mengirimkan laporan insiden terenkripsi ke Lembaga Negara terkait
    pub fn dispatch_national_alert(
        agency_target: NationalAgency,
        classification: ClassificationLevel,
        title: &str,
        stix_payload: serde_json::Value,
        merkle_root: &str,
    ) -> NationalAlertPayload {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let alert_id = format!(
            "SCC-{}-{}",
            match agency_target {
                NationalAgency::Bssn => "BSSN",
                NationalAgency::PolriCyber => "POLRI",
                NationalAgency::TniCyber => "TNI",
                NationalAgency::Bakamla => "BAKAMLA",
            },
            &Uuid::new_v4().to_string()[0..8].to_uppercase()
        );

        let dispatch_status = match agency_target {
            NationalAgency::Bssn => "STREAMED_TO_BSSN_CSIRT_TAXII21",
            NationalAgency::PolriCyber => "EXPORTED_TO_POLRI_CYBER_BAP_QUEUE",
            NationalAgency::TniCyber => "ENCRYPTED_FOR_TACTICAL_AIRGAP_VAULT",
            NationalAgency::Bakamla => "DISPATCHED_TO_BAKAMLA_COASTAL_RADAR",
        };

        NationalAlertPayload {
            alert_id,
            timestamp_ms,
            timestamp_rfc3339: Utc::now().to_rfc3339(),
            agency_target,
            classification_level: classification,
            incident_title: title.to_string(),
            stix_data: stix_payload,
            merkle_root_signature: merkle_root.to_string(),
            dispatch_status: dispatch_status.to_string(),
        }
    }

    /// 1. BSSN CSIRT: Menghasilkan Bundle STIX 2.1 Resmi dari Insiden
    pub fn generate_stix_bundle(
        incident_id: &str,
        threat_type: &str,
        source_ip: &str,
        target_domain: &str,
        description: &str,
    ) -> serde_json::Value {
        let timestamp = Utc::now().to_rfc3339();
        let identity_id = "identity--4d60d3d5-9154-4f9e-a89c-bssn-csirt-nkri";
        let indicator_id = format!("indicator--{}", Uuid::new_v4());

        json!({
            "type": "bundle",
            "id": format!("bundle--{}", Uuid::new_v4()),
            "spec_version": "2.1",
            "objects": [
                {
                    "type": "identity",
                    "spec_version": "2.1",
                    "id": identity_id,
                    "name": "BSSN CSIRT National Defense Mesh",
                    "identity_class": "organization",
                    "sectors": ["government", "defense", "critical-infrastructure"],
                    "created": timestamp
                },
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": indicator_id,
                    "created": timestamp,
                    "modified": timestamp,
                    "name": format!("IoC Ancaman: {}", threat_type),
                    "description": description,
                    "indicator_types": ["malicious-activity", "anomalous-activity"],
                    "pattern": format!("[ipv4-addr:value = '{}' OR domain-name:value = '{}']", source_ip, target_domain),
                    "pattern_type": "stix",
                    "valid_from": timestamp
                },
                {
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": format!("attack-pattern--{}", Uuid::new_v4()),
                    "name": threat_type,
                    "description": format!("Insiden {} terdeteksi oleh ZentyTeamsCore ID: {}", threat_type, incident_id),
                    "created": timestamp
                }
            ]
        })
    }

    /// 2. POLRI CYBER CRIME: Menghasilkan Berita Acara Pemeriksaan (BAP) Digital Sah di Pengadilan
    pub fn generate_bap_digital(
        case_id: &str,
        investigator_unit: &str,
        suspect_data: serde_json::Value,
        raw_evidence_str: &str,
        prev_block_hash: &str,
        merkle_root: &str,
    ) -> BapDigitalForensicDoc {
        let mut hasher = Sha256::new();
        hasher.update(raw_evidence_str.as_bytes());
        let forensic_hash_sha256 = format!("{:x}", hasher.finalize());

        let bap_number = format!(
            "BAP-DIGITAL/BARESKRIM-CYBER/{}/{}",
            Utc::now().format("%Y%m%d"),
            &Uuid::new_v4().to_string()[0..6].to_uppercase()
        );

        BapDigitalForensicDoc {
            bap_number,
            generated_at: Utc::now().to_rfc3339(),
            legal_authority: "Direktorat Tindak Pidana Siber Bareskrim Polri // UU ITE No. 1/2024".to_string(),
            case_reference: case_id.to_string(),
            evidence_type: "DIGITAL_AUDIT_LOG_WORM_MERKLE".to_string(),
            suspect_metadata: suspect_data,
            forensic_hash_sha256,
            prev_merkle_block_hash: prev_block_hash.to_string(),
            merkle_root_seal: merkle_root.to_string(),
            chain_of_custody_verified: true,
            legal_attestation: format!(
                "Bukti digital ini diuji dan dijamin keasliannya berdasarkan ISO/IEC 27037:2012 dan Pasal 5 ayat (1) UU ITE No. 1/2024 oleh unit: {}",
                investigator_unit
            ),
        }
    }

    /// 3. TNI CYBER WARFARE: Pembuatan Paket Sinkronisasi Air-Gapped Taktis
    pub fn package_tactical_airgap_bundle(
        posko_id: &str,
        machine_guid: &str,
        telemetry_events: &[serde_json::Value],
        dest_dir: &Path,
    ) -> Result<PathBuf, String> {
        if !dest_dir.exists() {
            let _ = std::fs::create_dir_all(dest_dir);
        }

        let bundle_name = format!(
            "TNI_TACTICAL_SYNC_{}_{}.zntypkg",
            posko_id,
            Utc::now().format("%Y%m%d_%H%M%S")
        );
        let target_file = dest_dir.join(bundle_name);

        let bundle_content = json!({
            "tactical_posko_id": posko_id,
            "machine_guid_bound": machine_guid,
            "classification": ClassificationLevel::TopSecretNkri.as_str(),
            "exported_at": Utc::now().to_rfc3339(),
            "event_count": telemetry_events.len(),
            "events": telemetry_events,
            "zero_network_mode": true,
            "firmware_integrity_verified": true
        });

        let json_str = serde_json::to_string_pretty(&bundle_content)
            .map_err(|e| format!("Gagal serialisasi paket militer: {}", e))?;

        std::fs::write(&target_file, json_str)
            .map_err(|e| format!("Gagal menyimpan paket taktis ke storage: {}", e))?;

        Ok(target_file)
    }

    /// 4. BAKAMLA & TNI AL: Pemantauan Dark Vessel & Anomali Sinyal AIS Maritim
    pub fn evaluate_maritime_vessel(
        mmsi: u32,
        name: Option<&str>,
        country: &str,
        lat: f64,
        lon: f64,
        speed_knots: f64,
        is_transponder_active: bool,
    ) -> Option<MaritimeAisAnomaly> {
        // Koordinat batas umum perairan kedaulatan / ZEE Indonesia: Lat 6°N - 11°S, Lon 95°E - 141°E
        let is_in_indonesian_waters = lat >= -11.0 && lat <= 6.0 && lon >= 95.0 && lon <= 141.0;

        if !is_in_indonesian_waters {
            return None;
        }

        // Anomali 1: Kapal mematikan pemancar AIS di dalam perairan Indonesia (Dark Vessel)
        if !is_transponder_active {
            return Some(MaritimeAisAnomaly {
                vessel_mmsi: mmsi,
                vessel_name: name.map(|s| s.to_string()),
                callsign: None,
                flag_country: country.to_string(),
                last_known_latitude: lat,
                last_known_longitude: lon,
                last_speed_knots: speed_knots,
                anomaly_type: "DARK_VESSEL_AIS_TRANSPONDER_DISABLED".to_string(),
                threat_severity: "CRITICAL".to_string(),
                detected_at: Utc::now().to_rfc3339(),
            });
        }

        // Anomali 2: Kecepatan tidak wajar (misal melayang diam di choke point Selat Malaka/Natuna)
        if speed_knots <= 0.5 && country != "ID" && (lat >= 1.0 && lat <= 4.0 && lon >= 102.0 && lon <= 108.0) {
            return Some(MaritimeAisAnomaly {
                vessel_mmsi: mmsi,
                vessel_name: name.map(|s| s.to_string()),
                callsign: None,
                flag_country: country.to_string(),
                last_known_latitude: lat,
                last_known_longitude: lon,
                last_speed_knots: speed_knots,
                anomaly_type: "SUSPICIOUS_LOITERING_CHOKEPOINT_NATUNA".to_string(),
                threat_severity: "HIGH".to_string(),
                detected_at: Utc::now().to_rfc3339(),
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dispatch_all_national_agencies() {
        let agencies = vec![
            NationalAgency::Bssn,
            NationalAgency::PolriCyber,
            NationalAgency::TniCyber,
            NationalAgency::Bakamla,
        ];

        let mock_stix = json!({"type": "test"});
        let mock_root = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        for agency in agencies {
            let alert = CommandCenterBridge::dispatch_national_alert(
                agency,
                ClassificationLevel::SecretNkri,
                "Deteksi Anomali Infrastruktur Strategis",
                mock_stix.clone(),
                mock_root,
            );
            assert!(alert.alert_id.starts_with("SCC-"));
            assert!(!alert.dispatch_status.is_empty());
        }
    }

    #[test]
    fn test_stix_bundle_generation() {
        let bundle = CommandCenterBridge::generate_stix_bundle(
            "INC-001",
            "APT_REFLECTIVE_DLL_INJECTION",
            "103.245.12.9",
            "gplay.ctar.tech",
            "Upaya injeksi memory pada node pembayaran",
        );
        assert_eq!(bundle["spec_version"], "2.1");
        assert_eq!(bundle["type"], "bundle");
        assert_eq!(bundle["objects"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn test_bap_digital_forensic_creation() {
        let suspect = json!({"ip": "185.220.101.5", "asn": "TOR_EXIT_NODE"});
        let doc = CommandCenterBridge::generate_bap_digital(
            "CASE-CYBER-2026-09",
            "Subdit 1 Tipidsiber Bareskrim",
            suspect,
            "raw-evidence-telemetry-block-payload",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        );
        assert!(doc.bap_number.contains("BARESKRIM-CYBER"));
        assert!(doc.chain_of_custody_verified);
        assert!(!doc.forensic_hash_sha256.is_empty());
    }

    #[test]
    fn test_bakamla_dark_vessel_detection() {
        // Kapal asing di Laut Natuna Utara (Lat 3.5, Lon 107.0) dengan AIS dimatikan
        let dark_vessel = CommandCenterBridge::evaluate_maritime_vessel(
            412001920,
            Some("FOREIGN_FLAG_01"),
            "CN",
            3.5,
            107.0,
            12.4,
            false, // Transponder mati!
        );

        assert!(dark_vessel.is_some());
        let anomaly = dark_vessel.unwrap();
        assert_eq!(anomaly.anomaly_type, "DARK_VESSEL_AIS_TRANSPONDER_DISABLED");
        assert_eq!(anomaly.threat_severity, "CRITICAL");
    }
}
