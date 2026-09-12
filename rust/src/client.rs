use reqwest::Client;
use serde_json::json;
use crate::types::*;
use crate::error::ZentyError;

/// Client utama ZentyTeamsCore SDK.
///
/// Ikuti pola yang sama dengan ZeroTrustClient (ZentyCore)
/// dan SentinelClient (SentinentalOps).
///
/// # Contoh
/// ```rust,no_run
/// use zentyteams_sdk::{ZentyTeamsClient, AgentRole};
///
/// let client = ZentyTeamsClient::new(
///     "https://gplay.ctar.tech",
///     "sk-zenty-xxxx",
///     "tenant-ctartech",
///     AgentRole::RedTeam,
/// );
/// ```
#[derive(Clone)]
pub struct ZentyTeamsClient {
    pub(crate) http:      Client,
    pub(crate) base_url:  String,
    pub(crate) api_key:   String,
    pub(crate) tenant_id: String,
    pub(crate) role:      AgentRole,
}

impl ZentyTeamsClient {
    /// Buat client baru yang terhubung ke gplay.ctar.tech
    pub fn new(
        base_url:  &str,
        api_key:   &str,
        tenant_id: &str,
        role:      AgentRole,
    ) -> Self {
        Self {
            http:      Client::new(),
            base_url:  base_url.trim_end_matches('/').to_string(),
            api_key:   api_key.to_string(),
            tenant_id: tenant_id.to_string(),
            role,
        }
    }

    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn api_key(&self) -> &str {
        &self.api_key
    }

    pub fn role(&self) -> &AgentRole {
        &self.role
    }

    /// Helper: buat header standar untuk setiap request
    pub(crate) fn auth_headers(&self) -> [(&'static str, String); 3] {
        [
            ("Authorization",     format!("Bearer {}", self.api_key)),
            ("X-Zenty-Tenant",    self.tenant_id.clone()),
            ("X-Zenty-Agent-Role", self.role.to_string()),
        ]
    }

    /// Helper: kirim POST request ke endpoint ZentyTeamsCore
    pub(crate) async fn post<T: serde::Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<ApiResponse, ZentyError> {
        let url = format!("{}{}", self.base_url, path);
        let [auth, tenant, agent_role] = self.auth_headers();

        let res = self.http
            .post(&url)
            .header("Content-Type", "application/json")
            .header(auth.0, auth.1)
            .header(tenant.0, tenant.1)
            .header(agent_role.0, agent_role.1)
            .json(body)
            .send()
            .await?;

        if res.status().is_success() {
            Ok(res.json::<ApiResponse>().await?)
        } else {
            let status = res.status().as_u16();
            let body   = res.text().await.unwrap_or_default();
            Err(ZentyError::ApiError { status, body })
        }
    }

    /// Helper: kirim GET request
    pub(crate) async fn get<R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<R, ZentyError> {
        let url = format!("{}{}", self.base_url, path);
        let [auth, tenant, agent_role] = self.auth_headers();

        let res = self.http
            .get(&url)
            .header("Authorization", auth.1)
            .header("X-Zenty-Tenant", tenant.1)
            .header("X-Zenty-Agent-Role", agent_role.1)
            .send()
            .await?;

        if res.status().is_success() {
            Ok(res.json::<R>().await?)
        } else {
            let status = res.status().as_u16();
            let body   = res.text().await.unwrap_or_default();
            Err(ZentyError::ApiError { status, body })
        }
    }

    // ─── HEARTBEAT ──────────────────────────────────────────
    /// Kirim heartbeat — pastikan agent terhubung ke gplay.ctar.tech
    pub async fn heartbeat(&self) -> Result<bool, ZentyError> {
        let body = json!({
            "role": self.role,
            "tenant_id": self.tenant_id,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        let res = self.post("/api/v1/agents/heartbeat", &body).await?;
        Ok(res.success)
    }
}
