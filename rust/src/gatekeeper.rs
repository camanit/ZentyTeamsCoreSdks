use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Kategori pelanggaran keamanan kode dalam pipeline CI/CD
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GateViolationCategory {
    HardcodedSecret,
    SqlInjectionRisk,
    DangerousExecution,
    PaymentBypassLogic,
    BackdoorTrojanPattern,
    EnvFileLeakage,
}

/// Tingkat keparahan pelanggaran kode
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GateSeverity {
    Info,
    Warning,
    High,
    Critical,
}

/// Detail satu pelanggaran yang ditemukan oleh Gatekeeper AI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateViolation {
    pub file_path: String,
    pub line_number: usize,
    pub category: GateViolationCategory,
    pub severity: GateSeverity,
    pub matched_pattern: String,
    pub description: String,
    pub ai_fix_recommendation: String,
}

/// Status keputusan akhir Release Gate
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GateVerdict {
    ReleaseApproved,
    ReleaseBlocked,
}

/// Laporan evaluasi rilis komprehensif
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateEvaluationReport {
    pub repository: String,
    pub commit_ref: String,
    pub scan_timestamp: String,
    pub total_files_scanned: usize,
    pub total_violations_found: usize,
    pub critical_violations: usize,
    pub high_violations: usize,
    pub verdict: GateVerdict,
    pub violations: Vec<GateViolation>,
    pub merkle_seal_hash: String,
}

/// Engine utama CI/CD & Pre-Commit AI Sentinel
pub struct ReleaseGateEngine;

impl ReleaseGateEngine {
    /// Memindai konten berkas kode terhadap pola-pola kerentanan berbahaya
    pub fn scan_code_content(file_path: &str, content: &str) -> Vec<GateViolation> {
        let mut violations = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        // 1. Pengecekan file sensitif yang tidak boleh di-commit (.env)
        if file_path.ends_with(".env") && !file_path.ends_with(".env.example") {
            violations.push(GateViolation {
                file_path: file_path.to_string(),
                line_number: 1,
                category: GateViolationCategory::EnvFileLeakage,
                severity: GateSeverity::Critical,
                matched_pattern: "FILE_NAME: .env".to_string(),
                description: "Berkas .env berisi kredensial produksi riil terdeteksi hendak di-commit!".to_string(),
                ai_fix_recommendation: "Tambahkan .env ke .gitignore dan gunakan environment variables terisolasi.".to_string(),
            });
        }

        for (idx, line) in lines.iter().enumerate() {
            let line_no = idx + 1;
            let trimmed = line.trim();

            // Abaikan komentar dokumentasi
            if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with("/*") || trimmed.starts_with('*') {
                continue;
            }

            // A. SECRET HUNTER (API Key Duitku, Midtrans, AWS, Private Key, Telegram Bot)
            if (trimmed.contains("sk-live-") || trimmed.contains("sk_live_") || trimmed.contains("AKIA") || trimmed.contains("ghp_"))
                && (trimmed.contains('=') || trimmed.contains(':')) {
                violations.push(GateViolation {
                    file_path: file_path.to_string(),
                    line_number: line_no,
                    category: GateViolationCategory::HardcodedSecret,
                    severity: GateSeverity::Critical,
                    matched_pattern: "LIVE_API_SECRET_KEY".to_string(),
                    description: "Hardcoded production API Secret Key terdeteksi!".to_string(),
                    ai_fix_recommendation: "Gunakan std::env::var() atau Vault secret manager daripada menuliskan key langsung di kode.".to_string(),
                });
            }

            // Private Key header
            if trimmed.contains("BEGIN RSA PRIVATE KEY") || trimmed.contains("BEGIN OPENSSH PRIVATE KEY") {
                violations.push(GateViolation {
                    file_path: file_path.to_string(),
                    line_number: line_no,
                    category: GateViolationCategory::HardcodedSecret,
                    severity: GateSeverity::Critical,
                    matched_pattern: "PRIVATE_KEY_CERTIFICATE".to_string(),
                    description: "Private cryptographic key certificate bocor di source code!".to_string(),
                    ai_fix_recommendation: "Segera hapus kunci privat dari repositori dan simpan di HSM atau KMS aman.".to_string(),
                });
            }

            // B. DANGEROUS SQL INJECTION CONCATENATION
            if (trimmed.to_lowercase().contains("select ") || trimmed.to_lowercase().contains("insert into ") || trimmed.to_lowercase().contains("delete from "))
                && (trimmed.contains(" + ") || trimmed.contains(".format(") || trimmed.contains("format!(\"SELECT") || trimmed.contains("f\"SELECT ")) {
                violations.push(GateViolation {
                    file_path: file_path.to_string(),
                    line_number: line_no,
                    category: GateViolationCategory::SqlInjectionRisk,
                    severity: GateSeverity::High,
                    matched_pattern: "RAW_SQL_STRING_CONCAT".to_string(),
                    description: "Penggabungan string SQL mentah (Raw SQL Concatenation) rentan injeksi SQL!".to_string(),
                    ai_fix_recommendation: "Gunakan Parameterized Queries / Prepared Statements (misal: query(..., &[$1, $2])).".to_string(),
                });
            }

            // C. DANGEROUS EXECUTION (eval / system / exec)
            if trimmed.contains("eval(") || trimmed.contains("exec(req.") || trimmed.contains("system(req.") || trimmed.contains("child_process.exec(") {
                violations.push(GateViolation {
                    file_path: file_path.to_string(),
                    line_number: line_no,
                    category: GateViolationCategory::DangerousExecution,
                    severity: GateSeverity::Critical,
                    matched_pattern: "DYNAMIC_CODE_EVALUATION".to_string(),
                    description: "Eksekusi kode dinamis berbahaya (eval / child_process.exec) rentan Remote Code Execution (RCE)!".to_string(),
                    ai_fix_recommendation: "Hapus fungsi eval/exec dinamis dan ganti dengan parser logika yang aman dan divalidasi ketat.".to_string(),
                });
            }

            // D. PAYMENT & AUTH BYPASS LOGIC
            if (trimmed.contains("is_debug == true") && trimmed.contains("approved = true"))
                || (trimmed.contains("bypass_payment = true") || trimmed.contains("skip_auth = true")) {
                violations.push(GateViolation {
                    file_path: file_path.to_string(),
                    line_number: line_no,
                    category: GateViolationCategory::PaymentBypassLogic,
                    severity: GateSeverity::Critical,
                    matched_pattern: "HARDCODED_PAYMENT_BYPASS".to_string(),
                    description: "Celah bypass otentikasi / pembayaran fiktif tertanam di kode!".to_string(),
                    ai_fix_recommendation: "Hapus seluruh switch bypass debug dari build rilis produksi.".to_string(),
                });
            }

            // E. BACKDOOR & REVERSE SHELL PATTERNS
            if trimmed.contains("/bin/sh") && (trimmed.contains("nc -e") || trimmed.contains("bash -i >& /dev/tcp/")) {
                violations.push(GateViolation {
                    file_path: file_path.to_string(),
                    line_number: line_no,
                    category: GateViolationCategory::BackdoorTrojanPattern,
                    severity: GateSeverity::Critical,
                    matched_pattern: "REVERSE_SHELL_PAYLOAD".to_string(),
                    description: "Pola Reverse Shell Trojan terdeteksi di dalam source code!".to_string(),
                    ai_fix_recommendation: "Segera bersihkan dan karantina kode ini. Indikasi kuat infeksi backdoor pihak ketiga.".to_string(),
                });
            }
        }

        violations
    }

    /// Mengevaluasi sekumpulan berkas yang hendak di-commit ke repositori
    pub fn evaluate_commit(
        repo_name: &str,
        commit_ref: &str,
        files: &[(&str, &str)], // Array of (file_path, file_content)
    ) -> GateEvaluationReport {
        let mut all_violations = Vec::new();

        for (path, content) in files {
            let mut v = Self::scan_code_content(path, content);
            all_violations.append(&mut v);
        }

        let critical = all_violations.iter().filter(|v| v.severity == GateSeverity::Critical).count();
        let high = all_violations.iter().filter(|v| v.severity == GateSeverity::High).count();

        // Release diblokir jika terdapat pelanggaran kategori Critical atau High!
        let verdict = if critical > 0 || high > 0 {
            GateVerdict::ReleaseBlocked
        } else {
            GateVerdict::ReleaseApproved
        };

        // Buat segel kriptografis Merkle Seal Hash
        let mut hasher = Sha256::new();
        hasher.update(repo_name.as_bytes());
        hasher.update(commit_ref.as_bytes());
        hasher.update(format!("{:?}", verdict).as_bytes());
        hasher.update(format!("{}", all_violations.len()).as_bytes());
        let seal_hash = hex::encode(hasher.finalize());

        GateEvaluationReport {
            repository: repo_name.to_string(),
            commit_ref: commit_ref.to_string(),
            scan_timestamp: chrono::Utc::now().to_rfc3339(),
            total_files_scanned: files.len(),
            total_violations_found: all_violations.len(),
            critical_violations: critical,
            high_violations: high,
            verdict,
            violations: all_violations,
            merkle_seal_hash: seal_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gatekeeper_detects_secrets_and_sqli() {
        let dirty_code = r#"
            let api_key = "sk-live-99882211993344";
            let query = format!("SELECT * FROM users WHERE id = " + user_input);
            println!("Ready");
        "#;

        let clean_code = r#"
            let api_key = std::env::var("API_KEY").unwrap();
            let query = "SELECT * FROM users WHERE id = $1";
            println!("Ready");
        "#;

        let files = vec![
            ("src/db.rs", dirty_code),
            ("src/clean.rs", clean_code),
        ];

        let report = ReleaseGateEngine::evaluate_commit("zenty-fintech-repo", "commit-abc-123", &files);
        assert_eq!(report.verdict, GateVerdict::ReleaseBlocked);
        assert_eq!(report.total_violations_found, 2);
        assert_eq!(report.critical_violations, 1);
        assert_eq!(report.high_violations, 1);
    }

    #[test]
    fn test_gatekeeper_approves_clean_code() {
        let clean_code = r#"
            let safe_var = 42;
            println!("Safe execution: {}", safe_var);
        "#;

        let files = vec![("src/main.rs", clean_code)];
        let report = ReleaseGateEngine::evaluate_commit("zenty-core", "commit-clean-001", &files);
        assert_eq!(report.verdict, GateVerdict::ReleaseApproved);
        assert_eq!(report.total_violations_found, 0);
    }
}
