//! # ZentyTeams SDK — Rust
//!
//! Official Rust client SDK for **ZentyTeamsCore DARKINT 3-IN-1 Platform**.
//!
//! ## Overview
//! SDK ini digunakan untuk menanamkan kemampuan pelaporan dan telemetri
//! ke dalam sistem manapun — baik milik CTARTech maupun klien.
//!
//! SDK mendukung 4 agent role:
//! - **Red Team**: Laporkan serangan, payload, dan temuan vulnerability
//! - **Blue Team**: Laporkan mitigasi, patch, dan aksi pertahanan
//! - **Purple Team**: Selalu aktif — rekam semua event dari Red & Blue
//! - **Dark Intel**: Kirim dan tarik IoC, threat feed, credential leak
//!
//! ## Quick Start
//! ```rust,no_run
//! use zentyteams_sdk::{ZentyTeamsClient, AgentRole, Severity};
//!
//! #[tokio::main]
//! async fn main() {
//!     let client = ZentyTeamsClient::new(
//!         "https://gplay.ctar.tech",
//!         "your-api-key",
//!         "tenant-id",
//!         AgentRole::RedTeam,
//!     );
//!
//!     client.report_attack(zentyteams_sdk::AttackEvent {
//!         target: "api.example.com".to_string(),
//!         vector: "SQLi".to_string(),
//!         payload: "' OR 1=1 --".to_string(),
//!         result: zentyteams_sdk::AttackResult::Breached,
//!         severity: Severity::Critical,
//!         ..Default::default()
//!     }).await.unwrap();
//! }
//! ```

pub mod client;
pub mod types;
pub mod red;
pub mod blue;
pub mod purple;
pub mod dark_intel;
pub mod error;
pub mod fuzzer;
pub mod ancaman_bridge;
pub mod merkle;
pub mod ecosystem;
pub mod command_center;
pub mod allied_mesh;
pub mod validation;
pub mod ghost_sandbox;
pub mod gatekeeper;
pub mod trust_seal;
pub mod canary_deception;
pub mod airgap_sync;
pub mod autonomous_sentinel;
pub mod ai_fingerprint;
pub mod mtd_engine;
pub mod ai_lure_engine;
pub mod ml_defense;
pub mod swarm_neutralizer;
pub mod deepfake_sentinel;
pub mod zero_day_synthesizer;
pub mod predictive_intel;

// Re-export utama agar mudah diakses
pub use client::ZentyTeamsClient;
pub use autonomous_sentinel::{AutonomousSentinel, SentinelVerdict, SovereignDistressSignal};
pub use ai_fingerprint::{AiBehavioralClassifier, AiBehaviorScore, AiAgentArchetype, RequestObservation};
pub use mtd_engine::{MtdShieldEngine, MtdConfig, ShapeshiftRoute, RaspSignatureVariant, MtdStatusReport};
pub use ai_lure_engine::{AiLureEngine, AiLureConfig, TrappedAgentProfile};
pub use ml_defense::{AdversarialMlDefenseEngine, TrainingDataProvenance, GradientDistributionCheck, ModelCheckpointSeal, AdversarialAuditResult};
pub use swarm_neutralizer::{SwarmNeutralizerEngine, SwarmThreatAssessment, AlliedSwarmBeacon, SwarmObservation};
pub use deepfake_sentinel::{DeepfakeSentinelEngine, AudioLivenessMetrics, DualPartySignSeal, OutOfBandChallenge};
pub use zero_day_synthesizer::{ZeroDayPatchSynthesizer, CveVulnerabilityReport, VirtualRaspPatch, MeshPatchBroadcast};
pub use predictive_intel::{PredictiveIntelEngine, MicroReconObservation, CampaignPrediction, PreemptiveDecoy, BaselineDriftMetric};
pub use fuzzer::{LogicFuzzer, FuzzResult, FuzzTestCase, ConcurrencyBurstReport};
pub use ghost_sandbox::{
    GhostTransactionEngine, GhostScenario, GhostAuditReport,
    GhostScenarioResult, FinSecMutationCategory,
};
pub use gatekeeper::{
    ReleaseGateEngine, GateEvaluationReport, GateVerdict,
    GateViolation, GateViolationCategory, GateSeverity,
};
pub use trust_seal::{
    TrustSealEngine, PublicTrustSeal, TrustVerificationResult,
};
pub use canary_deception::{
    CanaryDeceptionEngine, CanaryToken, CanaryType, CanaryStatus, CanaryTriggerAlert,
};
pub use airgap_sync::{
    AirGapSyncEngine, AirGapBundleManifest, AirGapClassification, AirGapUpdatePayload, AirGapUnpackResult,
};
pub use ancaman_bridge::{AncamanBridge, AncamanThreatReport};
pub use merkle::{ForensicLogEntry, MerkleLedgerEngine, ChainOfCustodyReport};
pub use ecosystem::{EcosystemBridge, EcosystemTarget, EcosystemNodeStatus};
pub use command_center::{
    CommandCenterBridge, NationalAgency, ClassificationLevel,
    NationalAlertPayload, BapDigitalForensicDoc, MaritimeAisAnomaly,
};
pub use allied_mesh::{
    AlliedMeshBridge, PqcAlgorithm, AlliedCertChannel,
    ZkpThreatProof, FederatedSwarmDelta,
};
pub use validation::{
    BasValidator, BasCategory, BasTestResult, BasSecurityValidationReport,
};
pub use types::{
    AgentRole, Severity, AttackResult, DefenseResult,
    AttackEvent, DefenseEvent, TelemetryEvent,
    ThreatIoc, VulnerabilityReport, ArtefactScanResult,
};
pub use error::ZentyError;
