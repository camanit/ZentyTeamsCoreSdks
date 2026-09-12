"""
ZentyTeams SDK — Python
Official client SDK for ZentyTeamsCore DARKINT 3-IN-1 Platform.

Tujuan:
  Menjaga ekosistem CTAR.Tech dan ekosistem pengguna tetap aman
  dengan memberikan kemampuan pelaporan Red/Blue/Purple/DarkIntel
  yang bisa ditanamkan ke sistem manapun.

Ikuti pola yang sama dengan SentinentalOps SDK (sentinelops.py).

Usage:
    from zentyteams import ZentyTeamsClient, AgentRole, Severity, BattlePhase

    client = ZentyTeamsClient(
        endpoint="https://gplay.ctar.tech",
        api_key="sk-zenty-xxxx",
        tenant_id="tenant-ctartech",
        role=AgentRole.RED_TEAM,
    )

    # Red Team — laporkan serangan
    client.report_sqli(
        target="api.example.com",
        endpoint="/login",
        payload="' OR 1=1 --",
        result="BREACHED",
        phase=BattlePhase.UNDEFENDED_ATTACK,
    )

    # Blue Team — laporkan mitigasi
    client.report_patch_applied(
        target="api.example.com",
        patch_description="Added prepared statements to login query",
        response_time_ms=4200,
    )
"""

import hashlib
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
import requests


# ─────────────────────────────────────────────
#  ENUMS
# ─────────────────────────────────────────────

class AgentRole(str, Enum):
    RED_TEAM    = "RED_TEAM"
    BLUE_TEAM   = "BLUE_TEAM"
    PURPLE_TEAM = "PURPLE_TEAM"
    DARK_INTEL  = "DARK_INTEL"


class Severity(str, Enum):
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class BattlePhase(str, Enum):
    # Phase 1: Red menyerang, Blue nonaktif — cari kelemahan murni
    UNDEFENDED_ATTACK = "UNDEFENDED_ATTACK"
    # Phase 2: Red vs Blue — uji pertahanan
    RED_VS_BLUE       = "RED_VS_BLUE"
    # Phase 3: Semua sistem aktif 24/7
    FULL_ECOSYSTEM    = "FULL_ECOSYSTEM"


class AttackResult(str, Enum):
    BREACHED = "BREACHED"
    BLOCKED  = "BLOCKED"
    PARTIAL  = "PARTIAL"
    FAILED   = "FAILED"


class DefenseResult(str, Enum):
    BLOCKED      = "BLOCKED"
    PATCHED      = "PATCHED"
    QUARANTINED  = "QUARANTINED"
    FAILED       = "FAILED"
    INVESTIGATING = "INVESTIGATING"


# ─────────────────────────────────────────────
#  CLIENT UTAMA
# ─────────────────────────────────────────────

class ZentyTeamsClient:
    """
    Client SDK untuk ZentyTeamsCore.
    Mengikuti pola SentinelClient dari SentinentalOps-Sdks.
    """

    def __init__(
        self,
        endpoint: str,
        api_key: str,
        tenant_id: str,
        role: AgentRole,
        service_name: str = "python-agent",
        timeout: int = 10,
    ):
        self.endpoint    = endpoint.rstrip("/")
        self.api_key     = api_key
        self.tenant_id   = tenant_id
        self.role        = role
        self.service_name = service_name
        self.timeout     = timeout

    def _headers(self) -> dict:
        return {
            "Content-Type":        "application/json",
            "Authorization":       f"Bearer {self.api_key}",
            "X-Zenty-Tenant":      self.tenant_id,
            "X-Zenty-Agent-Role":  self.role.value,
        }

    def _post(self, path: str, body: dict) -> dict:
        try:
            r = requests.post(
                f"{self.endpoint}{path}",
                json=body,
                headers=self._headers(),
                timeout=self.timeout,
            )
            return r.json()
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _get(self, path: str) -> dict:
        try:
            r = requests.get(
                f"{self.endpoint}{path}",
                headers=self._headers(),
                timeout=self.timeout,
            )
            return r.json()
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _ts(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _uid(self) -> str:
        return str(uuid.uuid4())

    # ──────────────────────────────────────────
    #  HEARTBEAT
    # ──────────────────────────────────────────

    def heartbeat(self) -> dict:
        """Pastikan agent terhubung ke gplay.ctar.tech"""
        return self._post("/api/v1/agents/heartbeat", {
            "role": self.role.value,
            "tenant_id": self.tenant_id,
            "service": self.service_name,
            "timestamp": self._ts(),
        })

    # ──────────────────────────────────────────
    #  RED TEAM — ATTACK REPORTING
    # ──────────────────────────────────────────

    def report_attack(
        self,
        target: str,
        vector: str,
        payload: str,
        result: AttackResult,
        severity: Severity,
        phase: BattlePhase,
        endpoint: Optional[str] = None,
        cve_id: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> dict:
        """Laporkan satu event serangan ke Purple Team & gplay.ctar.tech"""
        return self._post("/api/v1/red/attack", {
            "event_id":     self._uid(),
            "target":       target,
            "vector":       vector,
            "payload":      payload,
            "endpoint":     endpoint,
            "result":       result.value,
            "severity":     severity.value,
            "battle_phase": phase.value,
            "cve_id":       cve_id,
            "notes":        notes,
            "timestamp":    self._ts(),
        })

    def report_sqli(self, target: str, endpoint: str, payload: str,
                    result: AttackResult, phase: BattlePhase) -> dict:
        return self.report_attack(target, "SQL_INJECTION", payload, result,
                                  Severity.CRITICAL, phase, endpoint=endpoint)

    def report_xss(self, target: str, xss_type: str, payload: str,
                   result: AttackResult, phase: BattlePhase) -> dict:
        return self.report_attack(target, f"XSS_{xss_type.upper()}", payload,
                                  result, Severity.HIGH, phase)

    def report_rce(self, target: str, endpoint: str, payload: str,
                   result: AttackResult, phase: BattlePhase) -> dict:
        return self.report_attack(target, "RCE", payload, result,
                                  Severity.CRITICAL, phase, endpoint=endpoint)

    def report_payment_attack(self, target: str, payment_system: str,
                               technique: str, result: AttackResult,
                               phase: BattlePhase) -> dict:
        return self.report_attack(
            target, f"PAYMENT_LOGIC_{payment_system.upper()}",
            technique, result, Severity.CRITICAL, phase,
            notes=f"Payment system: {payment_system}"
        )

    def report_recon(self, target: str, open_ports: list,
                     services: list, phase: BattlePhase) -> dict:
        return self._post("/api/v1/red/recon", {
            "event_id":         self._uid(),
            "target":           target,
            "vector":           "RECONNAISSANCE",
            "open_ports":       open_ports,
            "services_detected": services,
            "battle_phase":     phase.value,
            "severity":         "INFO",
            "timestamp":        self._ts(),
        })

    def report_ransomware_sim(self, target_env: str, files_encrypted: int,
                               backup_bypassed: bool, phase: BattlePhase) -> dict:
        return self._post("/api/v1/red/ransomware-sim", {
            "target_environment":  target_env,
            "offensive_tool_type": "RANSOMWARE_SIMULATION",
            "files_encrypted":     files_encrypted,
            "backup_bypassed":     backup_bypassed,
            "result":              "BREACHED" if backup_bypassed else "PARTIAL",
            "battle_phase":        phase.value,
            "is_simulation":       True,
            "timestamp":           self._ts(),
        })

    def report_malware_sim(self, target_env: str, malware_type: str,
                            behavior_tested: list, result: AttackResult,
                            phase: BattlePhase) -> dict:
        """Red Team: laporkan simulasi malware di sandbox"""
        return self._post("/api/v1/red/offensive-tool/malware-sim", {
            "target_environment":  target_env,
            "offensive_tool_type": "MALWARE_SIMULATION",
            "malware_type":        malware_type,
            "behavior_tested":     behavior_tested,
            "result":              result.value,
            "battle_phase":        phase.value,
            "is_simulation":       True,
            "timestamp":           self._ts(),
        })

    def report_spyware_sim(self, target_env: str, spyware_type: str,
                            capabilities_tested: list, result: AttackResult,
                            phase: BattlePhase) -> dict:
        """Red Team: laporkan simulasi spyware di sandbox"""
        return self._post("/api/v1/red/offensive-tool/spyware-sim", {
            "target_environment":  target_env,
            "offensive_tool_type": "SPYWARE_SIMULATION",
            "spyware_type":        spyware_type,
            "capabilities_tested": capabilities_tested,
            "result":              result.value,
            "battle_phase":        phase.value,
            "is_simulation":       True,
            "timestamp":           self._ts(),
        })

    def report_apt_simulation(self, target_env: str, apt_profile: str,
                               stages_completed: list, dwell_time_hours: int,
                               phase: BattlePhase) -> dict:
        """Red Team: simulasi APT (Advanced Persistent Threat) multi-stage"""
        return self._post("/api/v1/red/offensive-tool/apt-sim", {
            "target_environment": target_env,
            "apt_profile":        apt_profile,
            "stages_completed":   stages_completed,
            "dwell_time_hours":   dwell_time_hours,
            "battle_phase":       phase.value,
            "is_simulation":      True,
            "timestamp":          self._ts(),
        })

    # ──────────────────────────────────────────
    #  BLUE TEAM — DEFENSE REPORTING
    # ──────────────────────────────────────────

    def report_defense(self, action: str, result: DefenseResult,
                       attack_event_id: Optional[str] = None,
                       patch_applied: Optional[str] = None,
                       response_time_ms: Optional[int] = None,
                       notes: Optional[str] = None) -> dict:
        return self._post("/api/v1/blue/defense", {
            "event_id":         self._uid(),
            "attack_event_id":  attack_event_id,
            "action":           action,
            "result":           result.value,
            "patch_applied":    patch_applied,
            "response_time_ms": response_time_ms,
            "notes":            notes,
            "timestamp":        self._ts(),
        })

    def report_anomaly(self, source_ip: str, anomaly_type: str,
                       severity: Severity, details: str) -> dict:
        return self._post("/api/v1/blue/anomaly", {
            "source_ip":    source_ip,
            "anomaly_type": anomaly_type,
            "severity":     severity.value,
            "details":      details,
            "timestamp":    self._ts(),
        })

    def report_quarantine(self, file_path: str, file_hash: str,
                          threat_name: str, threat_type: str) -> dict:
        """Blue Team: laporkan file yang dikarantina"""
        return self._post("/api/v1/blue/quarantine", {
            "file_path":          file_path,
            "file_hash_sha256":   file_hash,
            "threat_name":        threat_name,
            "threat_type":        threat_type,
            "action":             "QUARANTINED",
            "timestamp":          self._ts(),
        })

    def report_patch_applied(self, target: str, patch_description: str,
                              response_time_ms: int,
                              attack_event_id: Optional[str] = None) -> dict:
        return self.report_defense(
            action=f"PATCH_APPLIED:{target}",
            result=DefenseResult.PATCHED,
            attack_event_id=attack_event_id,
            patch_applied=patch_description,
            response_time_ms=response_time_ms,
        )

    def report_ransomware_detected(self, process_name: str,
                                    files_affected: int,
                                    action_taken: str) -> dict:
        return self._post("/api/v1/blue/ransomware-alert", {
            "process_name":   process_name,
            "files_affected": files_affected,
            "action_taken":   action_taken,
            "threat_type":    "RANSOMWARE",
            "severity":       "CRITICAL",
            "timestamp":      self._ts(),
        })

    def report_spyware_detected(self, process_name: str,
                                 spyware_type: str, action_taken: str) -> dict:
        return self._post("/api/v1/blue/spyware-alert", {
            "process_name":  process_name,
            "spyware_type":  spyware_type,
            "action_taken":  action_taken,
            "threat_type":   "SPYWARE",
            "severity":      "CRITICAL",
            "timestamp":     self._ts(),
        })

    # ──────────────────────────────────────────
    #  PURPLE TEAM — ALWAYS ON
    # ──────────────────────────────────────────

    def send_telemetry(self, category: str, payload: dict,
                       previous_hash: Optional[str] = None) -> dict:
        """Kirim event ke Merkle Chain Audit Ledger — Purple Team selalu aktif"""
        payload_hash = hashlib.sha256(
            str(payload).encode()
        ).hexdigest()
        return self._post("/api/v1/purple/telemetry", {
            "event_id":      self._uid(),
            "source":        self.role.value,
            "category":      category,
            "payload":       payload,
            "payload_hash":  payload_hash,
            "previous_hash": previous_hash,
            "timestamp":     self._ts(),
        })

    def start_battle_session(self, target: str, phase: BattlePhase,
                              operator: str, scope_notes: str) -> dict:
        return self._post("/api/v1/purple/session/start", {
            "target":      target,
            "phase":       phase.value,
            "operator":    operator,
            "scope_notes": scope_notes,
            "started_at":  self._ts(),
        })

    def end_battle_session(self, session_id: str) -> dict:
        return self._post("/api/v1/purple/session/end", {
            "session_id": session_id,
            "ended_at":   self._ts(),
        })

    def generate_report(self, session_id: str, report_type: str = "FULL") -> dict:
        """report_type: EXECUTIVE | TECHNICAL | COMPLIANCE | FULL"""
        return self._get(f"/api/v1/purple/report/{session_id}/{report_type}")

    # ──────────────────────────────────────────
    #  DARK INTELLIGENCE
    # ──────────────────────────────────────────

    def check_credential_leak(self, identifier: str,
                               identifier_type: str) -> dict:
        return self._post("/api/v1/dark-intel/check-leak", {
            "identifier":      identifier,
            "identifier_type": identifier_type,
            "check_sources":   ["HIBP", "DEHASHED", "LEAKIX", "INTELX", "CUSTOM_DB"],
        })

    def report_tor_intel(self, onion_address: str, content_type: str,
                          subject: str, confidence: int,
                          severity: Severity) -> dict:
        return self._post("/api/v1/dark-intel/dark-web", {
            "source_platform": "TOR_ONION",
            "onion_address":   onion_address,
            "content_type":    content_type,
            "subject":         subject,
            "confidence_score": confidence,
            "severity":        severity.value,
            "layer":           "DARK_WEB_TOR",
            "timestamp":       self._ts(),
        })

    def report_i2p_intel(self, eepsite: str, content_type: str,
                          subject: str, confidence: int,
                          severity: Severity) -> dict:
        return self._post("/api/v1/dark-intel/dark-web", {
            "source_platform": "I2P_NETWORK",
            "eepsite":         eepsite,
            "content_type":    content_type,
            "subject":         subject,
            "confidence_score": confidence,
            "severity":        severity.value,
            "layer":           "DARK_WEB_I2P",
            "timestamp":       self._ts(),
        })

    def report_zero_day(self, target_software: str, version: str,
                         description: str, severity: Severity,
                         discovered_in: str,
                         proof_of_concept: Optional[str] = None) -> dict:
        return self._post("/api/v1/dark-intel/zero-day", {
            "target_software":    target_software,
            "version":            version,
            "description":        description,
            "proof_of_concept":   proof_of_concept,
            "severity":           severity.value,
            "discovered_in":      discovered_in,
            "cve_assigned":       False,
            "timestamp":          self._ts(),
        })

    def get_threat_feed(self, limit: int = 50) -> dict:
        return self._get(f"/api/v1/dark-intel/feed?limit={limit}")


# ═══════════════════════════════════════════════════════════════════════════════
# AUTONOMOUS DEFENSE AI SENTINEL (BLUE SHIELD & DISTRESS BEACON)
#
# Modul kecerdasan otonom sisi client:
# 1. Memeriksa setiap payload & transaksi secara otonom (sub-1ms RASP).
# 2. Menghitung skor anomali & entropi payload (anti-obfuscated attack).
# 3. Memblokir serangan secara lokal (Auto-Containment) sebelum menyentuh DB.
# 4. Memancarkan "Sovereign Distress Signal" ke Command Center jika sistem
#    klien diserang masif atau terindikasi lockout/ransomware.
# ═══════════════════════════════════════════════════════════════════════════════

import math
from dataclasses import dataclass, field
from typing import Union


class SentinelVerdict(Enum):
    ALLOW             = "Allow"
    WATCH             = "Watch"
    BLOCK_AND_CONTAIN = "BlockAndContain"
    EMERGENCY_LOCKDOWN = "EmergencyLockdown"


@dataclass
class SentinelResult:
    verdict: SentinelVerdict
    score: float = 0.0
    attack_type: str = ""
    reason: str = ""
    distress_signal_id: str = ""
    indicator: str = ""


@dataclass
class SovereignDistressSignal:
    signal_id: str
    tenant_id: str
    node_target: str
    threat_level: str
    attack_footprint_hash: str
    recommended_action: str
    timestamp: str
    details: dict = field(default_factory=dict)


class AutonomousSentinel:
    """
    AutonomousSentinel — AI pertahanan otonom sisi klien (Blue & Purple Shield).

    Dirancang untuk ditanamkan ke sistem siapapun sebagai lapisan keamanan
    pertama yang berjalan sepenuhnya di sisi klien (zero-server-dependency).

    Jika klien diserang, sentinel akan:
    - Memblokir payload berbahaya sebelum menyentuh database / business logic.
    - Memancarkan Sinyal Darurat Kedaulatan ke AIControlPlane CTARTech.

    Contoh penggunaan (Flask / FastAPI):
    ```python
    sentinel = AutonomousSentinel(client)

    @app.before_request
    def check_incoming():
        body = request.get_data(as_text=True)
        result = sentinel.inspect_payload(request.remote_addr, request.path, body)
        if result.verdict == SentinelVerdict.BLOCK_AND_CONTAIN:
            abort(403, result.reason)
        elif result.verdict == SentinelVerdict.EMERGENCY_LOCKDOWN:
            # Pancarkan sinyal darurat secara async
            import asyncio
            asyncio.create_task(sentinel.emit_distress_beacon(
                request.host, result.reason, body
            ))
            abort(503, "Sistem sementara dikunci karena ancaman skala sindikat.")
    ```
    """

    def __init__(self, client: ZentyTeamsClient):
        self._client = client
        self._consecutive_threats: int = 0

    # ─────────────────────────────────────────────
    #  RASP Micro-Engine — berjalan di memori, zero I/O
    # ─────────────────────────────────────────────

    def inspect_payload(
        self,
        source_ip: str,
        endpoint: str,
        payload: str,
    ) -> SentinelResult:
        """
        Evaluasi muatan request secara otonom.

        Args:
            source_ip: IP address pengirim request.
            endpoint:  URL path / endpoint yang dituju.
            payload:   Isi body request (JSON string, form data, dll).

        Returns:
            SentinelResult dengan verdict otonom.
        """
        entropy = self._shannon_entropy(payload)
        score = 0.0
        attack_type = "UNKNOWN"
        reason = "Normal behavioral baseline"
        lower = payload.lower()

        # 1. FinSec & QRIS Negative Balance Manipulation Check
        if any(k in lower for k in ("amount", "nominal", "saldo")):
            if any(k in lower for k in ("-", "0x", "nan", "infinity")):
                score += 0.85
                attack_type = "FINSEC_NEGATIVE_BALANCE_TAMPER"
                reason = "Upaya manipulasi nilai transaksi / race condition saldo"

        # 2. High-Entropy Obfuscation (Shellcode / Hex Encoded Exploit)
        if entropy > 4.8 and len(payload) > 32:
            score += 0.65
            attack_type = "OBFUSCATED_PAYLOAD_DETECTED"
            reason = f"Entropi data mencurigakan ({entropy:.2f}) terindikasi payload terselubung"

        # 3. SQL Injection & Bypass Pattern
        sqli_patterns = ("union select", "' or '1'='1", "xp_cmdshell", "or 1=1", "drop table")
        if any(p in lower for p in sqli_patterns) or lower.count("--") > 1:
            score += 0.80
            attack_type = "SQL_INJECTION_AUTOBREACH"
            reason = "Vektor injeksi database terdeteksi pada muatan request"

        # 4. Path Traversal & Hostage File Probing
        if "../" in payload or "..\\" in payload or "/etc/shadow" in lower or "c:\\windows\\system32" in lower:
            score += 0.88
            attack_type = "PATH_TRAVERSAL_RANSOM_PROBE"
            reason = "Penyusupan direktori sistem terdeteksi"

        # 5. XSS & Script Injection
        xss_patterns = ("<script", "javascript:", "onerror=", "onload=", "eval(", "document.cookie")
        if any(p in lower for p in xss_patterns):
            score += 0.70
            attack_type = "XSS_SCRIPT_INJECTION"
            reason = "Injeksi skrip berbahaya terdeteksi"

        # 6. Command Injection
        cmd_patterns = ("; ls", "| cat", "&& rm", "$(", "`id`", "wget http", "curl http")
        if any(p in lower for p in cmd_patterns):
            score += 0.90
            attack_type = "COMMAND_INJECTION_HOSTAGE"
            reason = "Percobaan eksekusi perintah sistem (command injection)"

        # Keputusan Otonom
        if score >= 0.80:
            self._consecutive_threats += 1
            if self._consecutive_threats >= 3:
                sig_id = f"SIG-DISTRESS-{uuid.uuid4()}"
                return SentinelResult(
                    verdict=SentinelVerdict.EMERGENCY_LOCKDOWN,
                    score=score,
                    attack_type=attack_type,
                    reason=(
                        f"Serangan masif berulang ({self._consecutive_threats} ancaman). "
                        "Sinyal darurat kedaulatan dipancarkan!"
                    ),
                    distress_signal_id=sig_id,
                )
            return SentinelResult(
                verdict=SentinelVerdict.BLOCK_AND_CONTAIN,
                score=score,
                attack_type=attack_type,
                reason=reason,
            )
        elif score >= 0.40:
            return SentinelResult(
                verdict=SentinelVerdict.WATCH,
                score=score,
                indicator=attack_type,
                reason=reason,
            )
        else:
            self._consecutive_threats = 0
            return SentinelResult(
                verdict=SentinelVerdict.ALLOW,
                score=score,
            )

    # ─────────────────────────────────────────────
    #  Sinyal Darurat Kedaulatan → AIControlPlane
    # ─────────────────────────────────────────────

    def emit_distress_beacon(
        self,
        node_target: str,
        incident_summary: str,
        raw_evidence: str,
    ) -> dict:
        """
        Pancarkan Sinyal Darurat Kedaulatan ke Markas Komando CTARTech.

        Dipanggil otomatis saat EmergencyLockdown, atau dapat dipanggil
        secara manual oleh tim keamanan klien.

        Returns:
            dict dengan `ok` (bool) dan `signal_id` (str).
        """
        footprint_hash = hashlib.sha256(raw_evidence.encode()).hexdigest()
        signal_id = f"SIG-DISTRESS-{uuid.uuid4()}"

        signal = SovereignDistressSignal(
            signal_id=signal_id,
            tenant_id=self._client._tenant_id,
            node_target=node_target,
            threat_level="CRITICAL_HOSTAGE_RISK",
            attack_footprint_hash=footprint_hash,
            recommended_action="MOBILIZE_SOVEREIGN_RED_RESCUE_PATHFINDER",
            timestamp=datetime.now(timezone.utc).isoformat(),
            details={
                "incident_summary": incident_summary,
                "doctrine_trigger": "DEFENSE_BREACH_RECLAIM_SIGNAL",
                "client_timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )

        try:
            resp = self._client._post("/api/v1/sentinel/distress", {
                "signal_id":              signal.signal_id,
                "tenant_id":              signal.tenant_id,
                "node_target":            signal.node_target,
                "threat_level":           signal.threat_level,
                "attack_footprint_hash":  signal.attack_footprint_hash,
                "recommended_action":     signal.recommended_action,
                "timestamp":              signal.timestamp,
                "details":                signal.details,
            })
            return {"ok": True, "signal_id": signal_id, "response": resp}
        except Exception as exc:
            return {"ok": False, "signal_id": signal_id, "error": str(exc)}

    # ─────────────────────────────────────────────
    #  Internal Helpers
    # ─────────────────────────────────────────────

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        """Hitung Shannon Entropy dari sebuah string payload."""
        if not data:
            return 0.0
        from collections import Counter
        freq = Counter(data)
        length = len(data)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
            if count > 0
        )
