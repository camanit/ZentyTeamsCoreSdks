package zentyteams

// ZentyTeams SDK — Go
// Official client SDK for ZentyTeamsCore DARKINT 3-IN-1 Platform.
//
// Tujuan:
//   Menjaga ekosistem CTAR.Tech dan ekosistem pengguna tetap aman
//   dengan kemampuan Red/Blue/Purple/DarkIntel yang bisa ditanam ke sistem manapun.
//
// Mengikuti pola yang sama dengan sentinelops.go dari SentinentalOps-Sdks.
//
// Usage:
//   client := zentyteams.NewClient(zentyteams.Config{
//       Endpoint: "https://gplay.ctar.tech",
//       APIKey:   "sk-zenty-xxxx",
//       TenantID: "tenant-ctartech",
//       Role:     zentyteams.RoleRedTeam,
//   })
//   client.ReportSQLi("api.example.com", "/login", "' OR 1=1 --",
//       zentyteams.ResultBreached, zentyteams.PhaseUndefendedAttack)

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// ─────────────────────────────────────────────
//  ENUMS
// ─────────────────────────────────────────────

type AgentRole string

const (
	RoleRedTeam    AgentRole = "RED_TEAM"
	RoleBlueTeam   AgentRole = "BLUE_TEAM"
	RolePurpleTeam AgentRole = "PURPLE_TEAM"
	RoleDarkIntel  AgentRole = "DARK_INTEL"
)

type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

type BattlePhase string

const (
	// Phase 1: Red menyerang, Blue nonaktif — temukan kelemahan murni
	PhaseUndefendedAttack BattlePhase = "UNDEFENDED_ATTACK"
	// Phase 2: Red vs Blue — uji pertahanan nyata
	PhaseRedVsBlue        BattlePhase = "RED_VS_BLUE"
	// Phase 3: Semua sistem aktif — operasi penuh 24/7
	PhaseFullEcosystem    BattlePhase = "FULL_ECOSYSTEM"
)

type AttackResult string

const (
	ResultBreached AttackResult = "BREACHED"
	ResultBlocked  AttackResult = "BLOCKED"
	ResultPartial  AttackResult = "PARTIAL"
	ResultFailed   AttackResult = "FAILED"
)

type DefenseResult string

const (
	DefenseBlocked      DefenseResult = "BLOCKED"
	DefensePatched      DefenseResult = "PATCHED"
	DefenseQuarantined  DefenseResult = "QUARANTINED"
	DefenseFailed       DefenseResult = "FAILED"
	DefenseInvestigating DefenseResult = "INVESTIGATING"
)

// ─────────────────────────────────────────────
//  STRUCTS
// ─────────────────────────────────────────────

type Config struct {
	Endpoint    string
	APIKey      string
	TenantID    string
	Role        AgentRole
	ServiceName string
}

type Client struct {
	cfg Config
	hc  *http.Client
}

type AttackEvent struct {
	EventID     string      `json:"event_id"`
	Target      string      `json:"target"`
	Vector      string      `json:"vector"`
	Payload     string      `json:"payload"`
	Endpoint    string      `json:"endpoint,omitempty"`
	Result      AttackResult `json:"result"`
	Severity    Severity    `json:"severity"`
	BattlePhase BattlePhase `json:"battle_phase"`
	CveID       string      `json:"cve_id,omitempty"`
	Notes       string      `json:"notes,omitempty"`
	Timestamp   string      `json:"timestamp"`
}

type DefenseEvent struct {
	EventID         string        `json:"event_id"`
	AttackEventID   string        `json:"attack_event_id,omitempty"`
	Action          string        `json:"action"`
	Result          DefenseResult `json:"result"`
	PatchApplied    string        `json:"patch_applied,omitempty"`
	ResponseTimeMs  int64         `json:"response_time_ms,omitempty"`
	Notes           string        `json:"notes,omitempty"`
	Timestamp       string        `json:"timestamp"`
}

type ApiResponse struct {
	Success bool   `json:"success"`
	ID      string `json:"id,omitempty"`
	Message string `json:"message,omitempty"`
}

// ─────────────────────────────────────────────
//  CLIENT
// ─────────────────────────────────────────────

func NewClient(cfg Config) *Client {
	if cfg.ServiceName == "" {
		cfg.ServiceName = "go-agent"
	}
	return &Client{
		cfg: cfg,
		hc:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) post(path string, body interface{}) (ApiResponse, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return ApiResponse{}, err
	}
	req, err := http.NewRequest("POST", c.cfg.Endpoint+path, bytes.NewBuffer(data))
	if err != nil {
		return ApiResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	req.Header.Set("X-Zenty-Tenant", c.cfg.TenantID)
	req.Header.Set("X-Zenty-Agent-Role", string(c.cfg.Role))

	resp, err := c.hc.Do(req)
	if err != nil {
		return ApiResponse{}, err
	}
	defer resp.Body.Close()

	var result ApiResponse
	json.NewDecoder(resp.Body).Decode(&result)
	return result, nil
}

func ts() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func uid() string {
	return uuid.New().String()
}

func sha256hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// ─────────────────────────────────────────────
//  HEARTBEAT
// ─────────────────────────────────────────────

func (c *Client) Heartbeat() (ApiResponse, error) {
	return c.post("/api/v1/agents/heartbeat", map[string]interface{}{
		"role":      c.cfg.Role,
		"tenant_id": c.cfg.TenantID,
		"service":   c.cfg.ServiceName,
		"timestamp": ts(),
	})
}

// ─────────────────────────────────────────────
//  RED TEAM
// ─────────────────────────────────────────────

func (c *Client) ReportAttack(event AttackEvent) (ApiResponse, error) {
	if event.EventID == "" {
		event.EventID = uid()
	}
	event.Timestamp = ts()
	return c.post("/api/v1/red/attack", event)
}

func (c *Client) ReportSQLi(target, endpoint, payload string,
	result AttackResult, phase BattlePhase) (ApiResponse, error) {
	return c.ReportAttack(AttackEvent{
		Target: target, Vector: "SQL_INJECTION", Payload: payload,
		Endpoint: endpoint, Result: result, Severity: SeverityCritical,
		BattlePhase: phase,
	})
}

func (c *Client) ReportXSS(target, xssType, payload string,
	result AttackResult, phase BattlePhase) (ApiResponse, error) {
	return c.ReportAttack(AttackEvent{
		Target: target, Vector: fmt.Sprintf("XSS_%s", xssType),
		Payload: payload, Result: result, Severity: SeverityHigh,
		BattlePhase: phase,
	})
}

func (c *Client) ReportRCE(target, endpoint, payload string,
	result AttackResult, phase BattlePhase) (ApiResponse, error) {
	return c.ReportAttack(AttackEvent{
		Target: target, Vector: "RCE", Payload: payload,
		Endpoint: endpoint, Result: result, Severity: SeverityCritical,
		BattlePhase: phase,
	})
}

func (c *Client) ReportMalwareSim(targetEnv, malwareType string,
	behaviorTested []string, result AttackResult, phase BattlePhase) (ApiResponse, error) {
	return c.post("/api/v1/red/offensive-tool/malware-sim", map[string]interface{}{
		"target_environment":  targetEnv,
		"offensive_tool_type": "MALWARE_SIMULATION",
		"malware_type":        malwareType,
		"behavior_tested":     behaviorTested,
		"result":              result,
		"battle_phase":        phase,
		"is_simulation":       true,
		"timestamp":           ts(),
	})
}

func (c *Client) ReportSpywareSim(targetEnv, spywareType string,
	capabilities []string, result AttackResult, phase BattlePhase) (ApiResponse, error) {
	return c.post("/api/v1/red/offensive-tool/spyware-sim", map[string]interface{}{
		"target_environment":  targetEnv,
		"offensive_tool_type": "SPYWARE_SIMULATION",
		"spyware_type":        spywareType,
		"capabilities_tested": capabilities,
		"result":              result,
		"battle_phase":        phase,
		"is_simulation":       true,
		"timestamp":           ts(),
	})
}

func (c *Client) ReportAPTSimulation(targetEnv, aptProfile string,
	stages []string, dwellHours int, phase BattlePhase) (ApiResponse, error) {
	return c.post("/api/v1/red/offensive-tool/apt-sim", map[string]interface{}{
		"target_environment": targetEnv,
		"apt_profile":        aptProfile,
		"stages_completed":   stages,
		"dwell_time_hours":   dwellHours,
		"battle_phase":       phase,
		"is_simulation":      true,
		"timestamp":          ts(),
	})
}

// ─────────────────────────────────────────────
//  BLUE TEAM
// ─────────────────────────────────────────────

func (c *Client) ReportDefense(event DefenseEvent) (ApiResponse, error) {
	if event.EventID == "" {
		event.EventID = uid()
	}
	event.Timestamp = ts()
	return c.post("/api/v1/blue/defense", event)
}

func (c *Client) ReportAnomaly(sourceIP, anomalyType string,
	severity Severity, details string) (ApiResponse, error) {
	return c.post("/api/v1/blue/anomaly", map[string]interface{}{
		"source_ip":    sourceIP,
		"anomaly_type": anomalyType,
		"severity":     severity,
		"details":      details,
		"timestamp":    ts(),
	})
}

func (c *Client) ReportQuarantine(filePath, fileHash,
	threatName, threatType string) (ApiResponse, error) {
	return c.post("/api/v1/blue/quarantine", map[string]interface{}{
		"file_path":        filePath,
		"file_hash_sha256": fileHash,
		"threat_name":      threatName,
		"threat_type":      threatType,
		"action":           "QUARANTINED",
		"timestamp":        ts(),
	})
}

func (c *Client) ReportRansomwareDetected(processName string,
	filesAffected int, actionTaken string) (ApiResponse, error) {
	return c.post("/api/v1/blue/ransomware-alert", map[string]interface{}{
		"process_name":   processName,
		"files_affected": filesAffected,
		"action_taken":   actionTaken,
		"threat_type":    "RANSOMWARE",
		"severity":       "CRITICAL",
		"timestamp":      ts(),
	})
}

func (c *Client) ReportSpywareDetected(processName, spywareType,
	actionTaken string) (ApiResponse, error) {
	return c.post("/api/v1/blue/spyware-alert", map[string]interface{}{
		"process_name": processName,
		"spyware_type": spywareType,
		"action_taken": actionTaken,
		"threat_type":  "SPYWARE",
		"severity":     "CRITICAL",
		"timestamp":    ts(),
	})
}

// ─────────────────────────────────────────────
//  PURPLE TEAM — ALWAYS ON
// ─────────────────────────────────────────────

func (c *Client) SendTelemetry(category string, payload map[string]interface{},
	previousHash string) (ApiResponse, error) {
	payloadBytes, _ := json.Marshal(payload)
	payloadHash := sha256hex(string(payloadBytes))
	return c.post("/api/v1/purple/telemetry", map[string]interface{}{
		"event_id":      uid(),
		"source":        c.cfg.Role,
		"category":      category,
		"payload":       payload,
		"payload_hash":  payloadHash,
		"previous_hash": previousHash,
		"timestamp":     ts(),
	})
}

func (c *Client) StartBattleSession(target string, phase BattlePhase,
	operator, scopeNotes string) (string, error) {
	type Resp struct{ SessionID string `json:"session_id"` }
	data, _ := json.Marshal(map[string]interface{}{
		"target": target, "phase": phase,
		"operator": operator, "scope_notes": scopeNotes,
		"started_at": ts(),
	})
	req, _ := http.NewRequest("POST", c.cfg.Endpoint+"/api/v1/purple/session/start",
		bytes.NewBuffer(data))
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var r Resp
	json.NewDecoder(resp.Body).Decode(&r)
	return r.SessionID, nil
}

func (c *Client) EndBattleSession(sessionID string) (ApiResponse, error) {
	return c.post("/api/v1/purple/session/end", map[string]interface{}{
		"session_id": sessionID,
		"ended_at":   ts(),
	})
}

// ─────────────────────────────────────────────
//  DARK INTELLIGENCE
// ─────────────────────────────────────────────

func (c *Client) CheckCredentialLeak(identifier, identifierType string) (ApiResponse, error) {
	return c.post("/api/v1/dark-intel/check-leak", map[string]interface{}{
		"identifier":      identifier,
		"identifier_type": identifierType,
		"check_sources":   []string{"HIBP", "DEHASHED", "LEAKIX", "INTELX", "CUSTOM_DB"},
	})
}

func (c *Client) ReportTorIntel(onionAddress, contentType, subject string,
	confidence int, severity Severity) (ApiResponse, error) {
	return c.post("/api/v1/dark-intel/dark-web", map[string]interface{}{
		"source_platform":  "TOR_ONION",
		"onion_address":    onionAddress,
		"content_type":     contentType,
		"subject":          subject,
		"confidence_score": confidence,
		"severity":         severity,
		"layer":            "DARK_WEB_TOR",
		"timestamp":        ts(),
	})
}

func (c *Client) ReportI2PIntel(eepsite, contentType, subject string,
	confidence int, severity Severity) (ApiResponse, error) {
	return c.post("/api/v1/dark-intel/dark-web", map[string]interface{}{
		"source_platform":  "I2P_NETWORK",
		"eepsite":          eepsite,
		"content_type":     contentType,
		"subject":          subject,
		"confidence_score": confidence,
		"severity":         severity,
		"layer":            "DARK_WEB_I2P",
		"timestamp":        ts(),
	})
}

func (c *Client) ReportZeroDay(targetSoftware, version, description string,
	severity Severity, discoveredIn string) (ApiResponse, error) {
	return c.post("/api/v1/dark-intel/zero-day", map[string]interface{}{
		"target_software": targetSoftware,
		"version":         version,
		"description":     description,
		"severity":        severity,
		"discovered_in":   discoveredIn,
		"cve_assigned":    false,
		"timestamp":       ts(),
	})
}
