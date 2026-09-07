<p align="center">
  <img src="https://raw.githubusercontent.com/camanit/ZentyTeamsCore/main/logo.png" width="200" alt="ZentyTeamsCore Sovereign Shield Logo" style="border-radius:12px; box-shadow:0 0 25px rgba(56,189,248,0.5);" />
</p>

# ZentyTeams SDK
## Official Client SDK — ZentyTeamsCore DARKINT 3-IN-1 Platform

> *"Kita serang sistem kita sendiri lebih keras dari hacker manapun —*
> *supaya kita tahu di mana lubangnya SEBELUM hacker sungguhan menemukannya."*

---

## 🌐 Ekosistem CTAR.Tech yang Dilindungi SDK Ini

SDK ini dirancang untuk **menjaga semua ekosistem berikut tetap aman** — baik internal CTAR.Tech maupun ekosistem pengguna/klien:

| # | Platform | Domain / Fungsi | Risiko Utama |
|---|----------|-----------------|--------------|
| 1 | **ZentyTeamsCore** | Security Platform itu sendiri | Self-integrity |
| 2 | **SentinentalOps** | Enterprise Ops & Incident Command | Auth bypass, data leak |
| 3 | **CTARTech ZentyCore** | Zero-Trust Security Platform | Token manipulation |
| 4 | **ZentyFinSen** | AI Data Bank — Financial Intel | Payment logic, data exfil |
| 5 | **ZentyElastis** | GPU/AI Compute Cloud | Resource abuse, backdoor |
| 6 | **ZentyOps** | Operations Platform | Supply chain attack |
| 7 | **ZentyCare-ClinicalOps** | Clinical Ops & Biopharma | Patient data breach |
| 8 | **ZentyQuetry** | Query/Data Platform | SQL injection, data dump |
| 9 | **CTARTech-AIControlPlane** | AI Orchestration | Model poisoning, API abuse |
| 10 | **Nantara OS** | Custom Operating System | Kernel exploit, rootkit |
| 11 | **WebPay / QRIS Systems** | Payment Gateway | QRIS manipulation, race condition |
| 12 | **gplay.ctar.tech** | Central AI Data Bank | Central point attack |
| ∞ | **Ekosistem Klien** | Semua sistem klien CTAR.Tech | Semua vektor |

> **Prinsip**: Jika Red Team kita tidak bisa menembusnya → kita yakin hacker lain juga kesulitan.
> Jika Red Team berhasil tembus → kita segera perkuat Blue Team & Antivirus-nya.

---

## 📦 Available SDKs & Installation

| Language | Directory | Package Name | One-Line Install Command |
|----------|-----------|--------------|--------------------------|
| 🦀 **Rust** | `rust/` | `zentyteams-sdk` | `cargo add zentyteams-sdk --git https://github.com/camanit/ZentyTeamsCoreSdks` |
| 🐍 **Python** | `python/` | `zentyteams-sdk` | `pip install "git+https://github.com/camanit/ZentyTeamsCoreSdks.git#subdirectory=python"` |
| 🐹 **Go** | `go/` | `github.com/camanit/ZentyTeamsCoreSdks/go` | `go get github.com/camanit/ZentyTeamsCoreSdks/go` |
| 🟦 **Node.js/TS** | `node/` | `@ctar/zentyteams` | `npm install "https://github.com/camanit/ZentyTeamsCoreSdks.git#subdirectory=node"` |

---

## ⚡ Quick Start

### Rust
```rust
use zentyteams_sdk::{ZentyTeamsClient, AgentRole, BattlePhase, AttackResult, Severity};

#[tokio::main]
async fn main() {
    let client = ZentyTeamsClient::new(
        "https://gplay.ctar.tech",
        "sk-zenty-xxxx",
        "tenant-zentyelastis",
        AgentRole::RedTeam,
    );

    // ── PHASE 1: Red menyerang, Blue nonaktif ─────────────────────
    // Mulai sesi — Purple otomatis merekam
    let session = client.start_battle_session(
        "api.zentyelastis.ctar.tech",
        BattlePhase::UndefendedAttack,
        "RedOperator-01",
        "Full API surface, semua endpoint"
    ).await.unwrap();

    // Serang
    client.report_sqli(
        "api.zentyelastis.ctar.tech", "/api/v1/jobs",
        "' UNION SELECT * FROM users --",
        AttackResult::Breached,
        BattlePhase::UndefendedAttack,
    ).await.unwrap();

    // Akhiri — Purple generate laporan otomatis
    client.end_battle_session(&session).await.unwrap();
}
```

### Python
```python
from zentyteams import ZentyTeamsClient, AgentRole, Severity, BattlePhase, AttackResult

# Untuk ZentyFinSen (Financial AI Bank)
client = ZentyTeamsClient(
    endpoint="https://gplay.ctar.tech",
    api_key="sk-zenty-xxxx",
    tenant_id="tenant-zentyfinsen",
    role=AgentRole.RED_TEAM,
)

# Phase 2: Red vs Blue — uji apakah Blue bisa menahan
session = client.start_battle_session(
    target="gplay.ctar.tech",
    phase=BattlePhase.RED_VS_BLUE,
    operator="RedOps-FinSen",
    scope_notes="Payment endpoints, auth, data bank API"
)

# Simulasi payment logic attack (QRIS manipulation)
client.report_payment_attack(
    target="gplay.ctar.tech",
    payment_system="QRIS",
    technique="Nominal manipulation via race condition",
    result=AttackResult.PARTIAL,
    phase=BattlePhase.RED_VS_BLUE,
)

# Simulasi malware di sandbox
client.report_malware_sim(
    target_env="sandbox-zentyfinsen",
    malware_type="TROJAN",
    behavior_tested=["keylog", "data_exfil", "persistence"],
    result=AttackResult.BLOCKED,
    phase=BattlePhase.RED_VS_BLUE,
)

client.end_battle_session(session["session_id"])
```

### Go
```go
package main

import "github.com/ctartech/zentyteams-sdk/go/zentyteams"

func main() {
    // Untuk SentinentalOps
    client := zentyteams.NewClient(zentyteams.Config{
        Endpoint: "https://gplay.ctar.tech",
        APIKey:   "sk-zenty-xxxx",
        TenantID: "tenant-sentinelops",
        Role:     zentyteams.RoleBlueTeam,
    })

    // Blue Team: laporkan spyware yang terdeteksi
    client.ReportSpywareDetected(
        "suspicious-process-42",
        "KEYLOGGER",
        "QUARANTINED",
    )

    // Blue Team: laporkan ransomware yang dicegah
    client.ReportRansomwareDetected(
        "cryptolocker-sim",
        847,
        "PROCESS_KILLED_AND_ROLLBACK",
    )
}
```

---

## 🎯 3 Battle Phases

```
PHASE 1 — UNDEFENDED_ATTACK
  ✅ Red Team aktif     ❌ Blue Team off     ✅ Purple SELALU ON
  Tujuan: Temukan SEMUA kelemahan sistem tanpa ada yang menahan.
  "Seberapa lemah sistem ini jika tidak ada yang menjaganya?"

PHASE 2 — RED_VS_BLUE
  ✅ Red Team aktif     ✅ Blue Team aktif   ✅ Purple SELALU ON
  Tujuan: Uji seberapa kuat Blue Team menahan serangan Red.
  "Seberapa tangguh pertahanan kita melawan serangan yang kita tahu?"

PHASE 3 — FULL_ECOSYSTEM
  ✅ Red Team aktif     ✅ Blue Team aktif   ✅ Purple SELALU ON
  ✅ Dark Intel aktif   ✅ Antivirus aktif   ✅ SDK di semua sistem
  Tujuan: Operasi penuh 24/7 — kondisi dunia nyata.
  "Apakah ekosistem kita aman dari ancaman global yang terus berubah?"
```

---

## 🧩 SDK Architecture

```
zentyteams-sdk
│
├── client       → ZentyTeamsClient (core HTTP client)
├── types        → Semua struct: AttackEvent, DefenseEvent, ThreatIoc, dll
├── error        → ZentyError (HttpError, ConsentDenied, ScopeViolation, dll)
│
├── red          → Red Team methods:
│   ├── report_sqli(), report_xss(), report_rce(), report_ssrf()
│   ├── report_payment_attack(), report_api_fuzz(), report_mitm()
│   ├── report_brute_force(), report_jwt_attack()
│   ├── report_supply_chain_attack(), report_social_engineering()
│   ├── report_ransomware_sim() — simulasi ransomware di sandbox
│   ├── report_malware_sim()   — simulasi malware di sandbox  ← OFFENSIVE TOOL
│   └── report_spyware_sim()   — simulasi spyware di sandbox  ← OFFENSIVE TOOL
│
├── blue         → Blue Team methods:
│   ├── report_anomaly(), report_ip_blocked(), report_session_killed()
│   ├── report_patch_applied(), report_firewall_rule()
│   ├── report_quarantine(), report_av_scan()
│   ├── report_ransomware_detected()   ← ANTIVIRUS
│   ├── report_spyware_detected()      ← ANTI-SPYWARE
│   ├── report_rootkit_detected()      ← ANTI-ROOTKIT
│   ├── request_auto_remediation()     ← AI AUTO-PATCH
│   └── scan_artifact()                ← INTEGRITY SCANNER
│
├── purple       → Purple Team methods (ALWAYS ON):
│   ├── send_telemetry()     ← Merkle Chain audit log
│   ├── start_battle_session() / end_battle_session()
│   ├── correlate_events()   ← hubungkan Red event ↔ Blue event
│   ├── get_risk_matrix()    ← CVSS auto-scoring
│   ├── generate_report()    ← EXECUTIVE / TECHNICAL / COMPLIANCE
│   └── get_audit_trail()    ← full Merkle chain log
│
└── dark_intel   → Dark Intelligence methods:
    ├── report_ioc(), get_threat_feed()
    ├── check_credential_leak()        ← SURFACE WEB
    ├── report_github_leak()           ← SURFACE WEB
    ├── report_exposed_service()       ← SHODAN/CENSYS
    ├── report_underground_intel()     ← DEEP WEB
    ├── report_tor_intel()             ← DARK WEB (Tor)
    ├── report_i2p_intel()             ← DARK WEB (I2P)
    ├── report_anon_network_intel()    ← FREENET/ZERONET/LOKINET
    ├── report_zero_day()              ← ZERO-DAY INTEL
    ├── check_exploit_availability()   ← EXPLOIT MARKET MONITOR
    ├── report_red_c2_sim()            ← C2 SIMULATION
    ├── report_red_exfil_sim()         ← EXFILTRATION SIMULATION
    ├── report_apt_simulation()        ← APT MULTI-STAGE SIM
    └── map_to_mitre()                 ← MITRE ATT&CK MAPPING
```

---

## 🏛️ 5 Pilar Strategis Pertahanan Berdaulat (Pre-Adoption Immunity)

Sebelum adopsi massal oleh klien dan publik, SDK dilengkapi 5 modul pertahanan otonom:

| Pilar | Modul SDK (Rust/Multi-Lang) | Fungsi Kunci |
|---|---|---|
| **1. Ghost Sandbox** | `zentyteams_sdk::ghost_sandbox` | FinSec / QRIS EMVCo dynamic fuzzer, simulasi race-condition, balance underflow barrier. |
| **2. DevSecOps Sentinel** | `zentyteams_sdk::gatekeeper` | Git pre-commit scanner, AST & regex secret leak blocker, Merkle WORM commit attestation. |
| **3. Live Sovereign Trust Seal** | `zentyteams_sdk::trust_seal` | Dynamic SVG badge generator, ISO 27001 / BSSN verification endpoint, embedder. |
| **4. Canary Trap Matrix** | `zentyteams_sdk::canary_deception` | Active deception: Canary SQL rows, dummy API keys, decoy configs, zero false-positive quarantine. |
| **5. Air-Gapped USB Sync** | `zentyteams_sdk::airgap_sync` | NIST FIPS 203 (ML-KEM-768) & FIPS 204 (ML-DSA-65), hardware node-lock, Anti-BadUSB attestation. |

---

## 🔍 Independent Auditor & Third-Party Verification Playbook

Pihak ketiga, auditor keamanan eksternal, atau CSIRT instansi dapat memverifikasi integritas SDK dan engine secara mandiri:

### 1. Verifikasi Test Suite Rust Engine (22 Tests)
```bash
cd sdk/rust
cargo test --verbose
```
*Output yang diharapkan: `test result: ok. 22 passed; 0 failed; 0 ignored`.*

### 2. Verifikasi Rantai Merkle WORM & Segel Kriptografis
```bash
# Query status segel publik & bukti matematis tamper-evident
curl -s http://127.0.0.1:8080/api/v1/trust/verify/ctar-tech | jq .
```
*Output yang diharapkan: `"is_valid": true, "tamper_evident_check": "PASSED_WORM_CRYPTOGRAPHIC_CONSISTENCY"`.*

### 3. Verifikasi Gerbang Rilis Kode (Pre-Commit Sentinel)
```bash
cd desktop
cargo run --bin git-sentinel-hook -- --scan-staged
```

### 4. Pengujian Luring (Air-Gapped Sync & Anti-BadUSB)
```bash
# Uji coba pembongkaran paket taktis berformat .zntypkg
curl -s -X POST http://127.0.0.1:8080/api/v1/airgap/status | jq .
```
*Output yang diharapkan: `"pqc_encryption": "NIST FIPS 203 (ML-KEM-768) ACTIVE", "anti_badusb_defense": "HARDWARE_FIRMWARE_ATTESTATION_ACTIVE"`.*

---

## 🔗 Integrasi dengan Ekosistem CTAR.Tech

SDK terhubung ke **`gplay.ctar.tech`** sebagai Central AI Data Bank:

```
Sistem Klien / Ekosistem Zenty
    │
    │  (ZentyTeams SDK embedded)
    ▼
gplay.ctar.tech ──► Purple Team AI Analyst
    │             ──► Risk Matrix Builder
    │             ──► Merkle Chain Audit Ledger
    │             ──► Unified Dashboard
    │
    ├──► SentinentalOps (bidirectional — incident bridge)
    ├──► ZentyFinSen (bidirectional — financial intel context)
    ├──► ZentyElastis (telemetry dari GPU compute nodes)
    └──► Semua ekosistem Zenty lainnya
```

---

## 🛡️ Security Design & Compliance

- **Post-Quantum Cryptography**: NIST FIPS 203 (ML-KEM-768) & NIST FIPS 204 (ML-DSA-65).
- **Consent-first**: Setiap operasi Red Team memerlukan authorized consent cryptographic token.
- **Ed25519 & PQC Dual-Signing**: Setiap agen diverifikasi identitas dan integritasnya secara berdaulat.
- **Merkle DAG WORM**: Setiap event dan evaluasi dikunci ke append-only ledger anti-tamper.
- **Fail-closed (Zero Trust)**: Jika koneksi terputus atau node lock tidak cocok, sistem default ke status DENY.
- **Kepatuhan Regulasi**: UU PDP No. 27/2022, UU ITE No. 1/2024, BSSN CSIRT Framework, & ISO/IEC 27001:2022.

---

## 🏷️ Version Tagging
- **Current Stable**: `v1.0.0-sovereign`
- **Milestone Coverage**: M0 (Core), M1 (Offensive), M2 (Defensive), M3 (Forensic WORM), M4 (Command Center), M5 (DarkINT), M6 (National Interop BSSN/Polri/TNI), M7 (PQC Post-Quantum & Sovereign Deception).

---

## 📄 License
AGPL-3.0-or-later | CTARTech Engineering
`enterprise@ctar.tech` | [ctar.tech](https://ctar.tech)



---

## 🏦 Dukungan Riset Kedaulatan & Donasi Komunitas (Allo Bank)

Dukung kemandirian pertahanan siber nasional Republik Indonesia. Seluruh donasi komunitas dan pembayaran aktivasi lisensi Enterprise disalurkan untuk memperkuat riset Post-Quantum Cryptography & RASP Ring-0 CTAR.Tech.

```text
┌─────────────────────────────────────────────────────────────┐
│  REKENING RESMI DUKUNGAN KOMUNITAS & LISENSI ENTERPRISE     │
├─────────────────────────────────────────────────────────────┤
│  Bank      : PT Allo Bank Indonesia Tbk                     │
│  Layanan   : Donasi Riset Komunitas & Aktivasi Lisensi      │
│  Kontak WA : 0812 6000 6666 (Konfirmasi Cepat)              │
│  Catatan   : Harap sertakan Nama / Machine ID / Institusi   │
└─────────────────────────────────────────────────────────────┘
```
> 📱 **Konfirmasi & Hotline Aktivasi WhatsApp**: [**0812 6000 6666**](https://wa.me/6281260006666)
