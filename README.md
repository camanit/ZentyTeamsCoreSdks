# ZentyTeams SDK
## Official Client SDK ΓÇö ZentyTeamsCore DARKINT 3-IN-1 Platform

> *"Kita serang sistem kita sendiri lebih keras dari hacker manapun ΓÇö*
> *supaya kita tahu di mana lubangnya SEBELUM hacker sungguhan menemukannya."*

---

## ≡ƒîÉ Ekosistem CTAR.Tech yang Dilindungi SDK Ini

SDK ini dirancang untuk **menjaga semua ekosistem berikut tetap aman** ΓÇö baik internal CTAR.Tech maupun ekosistem pengguna/klien:

| # | Platform | Domain / Fungsi | Risiko Utama |
|---|----------|-----------------|--------------|
| 1 | **ZentyTeamsCore** | Security Platform itu sendiri | Self-integrity |
| 2 | **SentinentalOps** | Enterprise Ops & Incident Command | Auth bypass, data leak |
| 3 | **CTARTech ZentyCore** | Zero-Trust Security Platform | Token manipulation |
| 4 | **ZentyFinSen** | AI Data Bank ΓÇö Financial Intel | Payment logic, data exfil |
| 5 | **ZentyElastis** | GPU/AI Compute Cloud | Resource abuse, backdoor |
| 6 | **ZentyOps** | Operations Platform | Supply chain attack |
| 7 | **ZentyCare-ClinicalOps** | Clinical Ops & Biopharma | Patient data breach |
| 8 | **ZentyQuetry** | Query/Data Platform | SQL injection, data dump |
| 9 | **CTARTech-AIControlPlane** | AI Orchestration | Model poisoning, API abuse |
| 10 | **Nantara OS** | Custom Operating System | Kernel exploit, rootkit |
| 11 | **WebPay / QRIS Systems** | Payment Gateway | QRIS manipulation, race condition |
| 12 | **gplay.ctar.tech** | Central AI Data Bank | Central point attack |
| Γê₧ | **Ekosistem Klien** | Semua sistem klien CTAR.Tech | Semua vektor |

> **Prinsip**: Jika Red Team kita tidak bisa menembusnya ΓåÆ kita yakin hacker lain juga kesulitan.
> Jika Red Team berhasil tembus ΓåÆ kita segera perkuat Blue Team & Antivirus-nya.

---

## ≡ƒôª Available SDKs & Installation

| Language | Directory | Package Name | One-Line Install Command |
|----------|-----------|--------------|--------------------------|
| ≡ƒªÇ **Rust** | `rust/` | `zentyteams-sdk` | `cargo add zentyteams-sdk --git https://github.com/camanit/ZentyTeamsCoreSdks` |
| ≡ƒÉì **Python** | `python/` | `zentyteams-sdk` | `pip install "git+https://github.com/camanit/ZentyTeamsCoreSdks.git#subdirectory=python"` |
| ≡ƒÉ╣ **Go** | `go/` | `github.com/camanit/ZentyTeamsCoreSdks/go` | `go get github.com/camanit/ZentyTeamsCoreSdks/go` |
| ≡ƒƒª **Node.js/TS** | `node/` | `@ctar/zentyteams` | `npm install "https://github.com/camanit/ZentyTeamsCoreSdks.git#subdirectory=node"` |

---

## ΓÜí Quick Start

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

    // ΓöÇΓöÇ PHASE 1: Red menyerang, Blue nonaktif ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
    // Mulai sesi ΓÇö Purple otomatis merekam
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

    // Akhiri ΓÇö Purple generate laporan otomatis
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

# Phase 2: Red vs Blue ΓÇö uji apakah Blue bisa menahan
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

## ≡ƒÄ» 3 Battle Phases

```
PHASE 1 ΓÇö UNDEFENDED_ATTACK
  Γ£à Red Team aktif     Γ¥î Blue Team off     Γ£à Purple SELALU ON
  Tujuan: Temukan SEMUA kelemahan sistem tanpa ada yang menahan.
  "Seberapa lemah sistem ini jika tidak ada yang menjaganya?"

PHASE 2 ΓÇö RED_VS_BLUE
  Γ£à Red Team aktif     Γ£à Blue Team aktif   Γ£à Purple SELALU ON
  Tujuan: Uji seberapa kuat Blue Team menahan serangan Red.
  "Seberapa tangguh pertahanan kita melawan serangan yang kita tahu?"

PHASE 3 ΓÇö FULL_ECOSYSTEM
  Γ£à Red Team aktif     Γ£à Blue Team aktif   Γ£à Purple SELALU ON
  Γ£à Dark Intel aktif   Γ£à Antivirus aktif   Γ£à SDK di semua sistem
  Tujuan: Operasi penuh 24/7 ΓÇö kondisi dunia nyata.
  "Apakah ekosistem kita aman dari ancaman global yang terus berubah?"
```

---

## ≡ƒº⌐ SDK Architecture

```
zentyteams-sdk
Γöé
Γö£ΓöÇΓöÇ client       ΓåÆ ZentyTeamsClient (core HTTP client)
Γö£ΓöÇΓöÇ types        ΓåÆ Semua struct: AttackEvent, DefenseEvent, ThreatIoc, dll
Γö£ΓöÇΓöÇ error        ΓåÆ ZentyError (HttpError, ConsentDenied, ScopeViolation, dll)
Γöé
Γö£ΓöÇΓöÇ red          ΓåÆ Red Team methods:
Γöé   Γö£ΓöÇΓöÇ report_sqli(), report_xss(), report_rce(), report_ssrf()
Γöé   Γö£ΓöÇΓöÇ report_payment_attack(), report_api_fuzz(), report_mitm()
Γöé   Γö£ΓöÇΓöÇ report_brute_force(), report_jwt_attack()
Γöé   Γö£ΓöÇΓöÇ report_supply_chain_attack(), report_social_engineering()
Γöé   Γö£ΓöÇΓöÇ report_ransomware_sim() ΓÇö simulasi ransomware di sandbox
Γöé   Γö£ΓöÇΓöÇ report_malware_sim()   ΓÇö simulasi malware di sandbox  ΓåÉ OFFENSIVE TOOL
Γöé   ΓööΓöÇΓöÇ report_spyware_sim()   ΓÇö simulasi spyware di sandbox  ΓåÉ OFFENSIVE TOOL
Γöé
Γö£ΓöÇΓöÇ blue         ΓåÆ Blue Team methods:
Γöé   Γö£ΓöÇΓöÇ report_anomaly(), report_ip_blocked(), report_session_killed()
Γöé   Γö£ΓöÇΓöÇ report_patch_applied(), report_firewall_rule()
Γöé   Γö£ΓöÇΓöÇ report_quarantine(), report_av_scan()
Γöé   Γö£ΓöÇΓöÇ report_ransomware_detected()   ΓåÉ ANTIVIRUS
Γöé   Γö£ΓöÇΓöÇ report_spyware_detected()      ΓåÉ ANTI-SPYWARE
Γöé   Γö£ΓöÇΓöÇ report_rootkit_detected()      ΓåÉ ANTI-ROOTKIT
Γöé   Γö£ΓöÇΓöÇ request_auto_remediation()     ΓåÉ AI AUTO-PATCH
Γöé   ΓööΓöÇΓöÇ scan_artifact()                ΓåÉ INTEGRITY SCANNER
Γöé
Γö£ΓöÇΓöÇ purple       ΓåÆ Purple Team methods (ALWAYS ON):
Γöé   Γö£ΓöÇΓöÇ send_telemetry()     ΓåÉ Merkle Chain audit log
Γöé   Γö£ΓöÇΓöÇ start_battle_session() / end_battle_session()
Γöé   Γö£ΓöÇΓöÇ correlate_events()   ΓåÉ hubungkan Red event Γåö Blue event
Γöé   Γö£ΓöÇΓöÇ get_risk_matrix()    ΓåÉ CVSS auto-scoring
Γöé   Γö£ΓöÇΓöÇ generate_report()    ΓåÉ EXECUTIVE / TECHNICAL / COMPLIANCE
Γöé   ΓööΓöÇΓöÇ get_audit_trail()    ΓåÉ full Merkle chain log
Γöé
ΓööΓöÇΓöÇ dark_intel   ΓåÆ Dark Intelligence methods:
    Γö£ΓöÇΓöÇ report_ioc(), get_threat_feed()
    Γö£ΓöÇΓöÇ check_credential_leak()        ΓåÉ SURFACE WEB
    Γö£ΓöÇΓöÇ report_github_leak()           ΓåÉ SURFACE WEB
    Γö£ΓöÇΓöÇ report_exposed_service()       ΓåÉ SHODAN/CENSYS
    Γö£ΓöÇΓöÇ report_underground_intel()     ΓåÉ DEEP WEB
    Γö£ΓöÇΓöÇ report_tor_intel()             ΓåÉ DARK WEB (Tor)
    Γö£ΓöÇΓöÇ report_i2p_intel()             ΓåÉ DARK WEB (I2P)
    Γö£ΓöÇΓöÇ report_anon_network_intel()    ΓåÉ FREENET/ZERONET/LOKINET
    Γö£ΓöÇΓöÇ report_zero_day()              ΓåÉ ZERO-DAY INTEL
    Γö£ΓöÇΓöÇ check_exploit_availability()   ΓåÉ EXPLOIT MARKET MONITOR
    Γö£ΓöÇΓöÇ report_red_c2_sim()            ΓåÉ C2 SIMULATION
    Γö£ΓöÇΓöÇ report_red_exfil_sim()         ΓåÉ EXFILTRATION SIMULATION
    Γö£ΓöÇΓöÇ report_apt_simulation()        ΓåÉ APT MULTI-STAGE SIM
    ΓööΓöÇΓöÇ map_to_mitre()                 ΓåÉ MITRE ATT&CK MAPPING
```

---

## ≡ƒÅ¢∩╕Å 5 Pilar Strategis Pertahanan Berdaulat (Pre-Adoption Immunity)

Sebelum adopsi massal oleh klien dan publik, SDK dilengkapi 5 modul pertahanan otonom:

| Pilar | Modul SDK (Rust/Multi-Lang) | Fungsi Kunci |
|---|---|---|
| **1. Ghost Sandbox** | `zentyteams_sdk::ghost_sandbox` | FinSec / QRIS EMVCo dynamic fuzzer, simulasi race-condition, balance underflow barrier. |
| **2. DevSecOps Sentinel** | `zentyteams_sdk::gatekeeper` | Git pre-commit scanner, AST & regex secret leak blocker, Merkle WORM commit attestation. |
| **3. Live Sovereign Trust Seal** | `zentyteams_sdk::trust_seal` | Dynamic SVG badge generator, ISO 27001 / BSSN verification endpoint, embedder. |
| **4. Canary Trap Matrix** | `zentyteams_sdk::canary_deception` | Active deception: Canary SQL rows, dummy API keys, decoy configs, zero false-positive quarantine. |
| **5. Air-Gapped USB Sync** | `zentyteams_sdk::airgap_sync` | NIST FIPS 203 (ML-KEM-768) & FIPS 204 (ML-DSA-65), hardware node-lock, Anti-BadUSB attestation. |

---

## ≡ƒöì Independent Auditor & Third-Party Verification Playbook

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

## ≡ƒöù Integrasi dengan Ekosistem CTAR.Tech

SDK terhubung ke **`gplay.ctar.tech`** sebagai Central AI Data Bank:

```
Sistem Klien / Ekosistem Zenty
    Γöé
    Γöé  (ZentyTeams SDK embedded)
    Γû╝
gplay.ctar.tech ΓöÇΓöÇΓû║ Purple Team AI Analyst
    Γöé             ΓöÇΓöÇΓû║ Risk Matrix Builder
    Γöé             ΓöÇΓöÇΓû║ Merkle Chain Audit Ledger
    Γöé             ΓöÇΓöÇΓû║ Unified Dashboard
    Γöé
    Γö£ΓöÇΓöÇΓû║ SentinentalOps (bidirectional ΓÇö incident bridge)
    Γö£ΓöÇΓöÇΓû║ ZentyFinSen (bidirectional ΓÇö financial intel context)
    Γö£ΓöÇΓöÇΓû║ ZentyElastis (telemetry dari GPU compute nodes)
    ΓööΓöÇΓöÇΓû║ Semua ekosistem Zenty lainnya
```

---

## ≡ƒ¢í∩╕Å Security Design & Compliance

- **Post-Quantum Cryptography**: NIST FIPS 203 (ML-KEM-768) & NIST FIPS 204 (ML-DSA-65).
- **Consent-first**: Setiap operasi Red Team memerlukan authorized consent cryptographic token.
- **Ed25519 & PQC Dual-Signing**: Setiap agen diverifikasi identitas dan integritasnya secara berdaulat.
- **Merkle DAG WORM**: Setiap event dan evaluasi dikunci ke append-only ledger anti-tamper.
- **Fail-closed (Zero Trust)**: Jika koneksi terputus atau node lock tidak cocok, sistem default ke status DENY.
- **Kepatuhan Regulasi**: UU PDP No. 27/2022, UU ITE No. 1/2024, BSSN CSIRT Framework, & ISO/IEC 27001:2022.

---

## ≡ƒÅ╖∩╕Å Version Tagging
- **Current Stable**: `v1.0.0-sovereign`
- **Milestone Coverage**: M0 (Core), M1 (Offensive), M2 (Defensive), M3 (Forensic WORM), M4 (Command Center), M5 (DarkINT), M6 (National Interop BSSN/Polri/TNI), M7 (PQC Post-Quantum & Sovereign Deception).

---

## ≡ƒôä License
AGPL-3.0-or-later | CTARTech Engineering
`enterprise@ctar.tech` | [ctar.tech](https://ctar.tech)

