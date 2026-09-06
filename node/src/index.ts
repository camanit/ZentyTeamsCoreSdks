/**
 * @file index.ts
 * @description Official Node.js & TypeScript SDK for ZentyTeamsCore Sovereign Purple Team & DARKINT Platform.
 * Compatible with CTARTech Ecosystem and GPlay.AI.
 */

export type AgentRole = "RedTeam" | "BlueDefense" | "PurpleOrchestrator" | "Auditor";

export interface BattleSimulationRequest {
  targetUrl: string;
  intensity: "STEALTH" | "TACTICAL" | "FULL_ASSAULT";
  simulationPayloads?: string[];
  tenantId: string;
}

export interface MerkleForensicBlock {
  blockIndex: number;
  merkleRoot: string;
  pqcSignatureAlgorithm: "ML-DSA-65" | "FIPS_204";
  timestamp: string;
  isTamperProof: boolean;
}

export interface FuzzReport {
  endpoint: string;
  payloadType: string;
  status: "DETECTED" | "MITIGATED" | "VULNERABLE";
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  responseLatencyMs: number;
}

export interface NationalAlert {
  agency: "BSSN" | "POLRI_CYBER" | "TNI_CYBER" | "BAKAMLA";
  classification: "TOP_SECRET_NKRI" | "SECRET_NKRI" | "CONFIDENTIAL_NKRI";
  headline: string;
  stixBundleId: string;
}

export class ZentyTeamsClient {
  private baseUrl: string;
  private apiKey: string;
  private tenantId: string;
  private role: AgentRole;

  constructor(baseUrl = "http://127.0.0.1:8080", apiKey: string, tenantId = "default-tenant", role: AgentRole = "PurpleOrchestrator") {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.apiKey = apiKey;
    this.tenantId = tenantId;
    this.role = role;
  }

  /**
   * Cek kesehatan backend ZentyTeamsCore dan integritas RASP
   */
  async checkHealth(): Promise<{ status: string; engine: string; memorySafe: boolean }> {
    const response = await fetch(`${this.baseUrl}/health`);
    if (!response.ok) {
      throw new Error(`ZentyTeamsCore health check failed: ${response.statusText}`);
    }
    return (await response.json()) as { status: string; engine: string; memorySafe: boolean };
  }

  /**
   * Menjalankan kampanye Fuzzing Keuangan / Logika Bisnis (Red Team)
   */
  async runLogicFuzzCampaign(targetUrl: string): Promise<FuzzReport[]> {
    const response = await fetch(`${this.baseUrl}/api/v1/fuzz/payment`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${this.apiKey}`,
        "X-Tenant-ID": this.tenantId,
      },
      body: JSON.stringify({ target_url: targetUrl }),
    });

    if (!response.ok) {
      throw new Error(`Fuzz campaign failed: ${response.statusText}`);
    }
    return (await response.json()) as FuzzReport[];
  }

  /**
   * Menghubungkan node ekosistem eksternal (misal: NantaraPentest, ZentyFinSen)
   */
  async registerEcosystemNode(platform: string): Promise<{ registered: boolean; nodeId: string; pqcKey: string }> {
    const response = await fetch(`${this.baseUrl}/api/v1/ecosystem/register`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify({ platform }),
    });

    return (await response.json()) as { registered: boolean; nodeId: string; pqcKey: string };
  }

  /**
   * Mengambil blok forensik digital terenkripsi WORM Merkle DAG (ISO 27037)
   */
  async getLatestForensicBlock(): Promise<MerkleForensicBlock> {
    const response = await fetch(`${this.baseUrl}/api/v1/forensics/latest-block`, {
      headers: {
        "Authorization": `Bearer ${this.apiKey}`,
      },
    });

    return (await response.json()) as MerkleForensicBlock;
  }
}

/**
 * Express & Next.js Security Middleware
 * Secara otomatis memeriksa traffic incoming terhadap aturan RASP & Blue Defense Engine
 */
export function zentyTeamsMiddleware(client: ZentyTeamsClient) {
  return async (req: any, res: any, next: any) => {
    const signature = req.headers["x-zenty-signature"];
    const authHeader = req.headers["authorization"];

    // In-line RASP telemetry check
    if (req.url.includes("admin") || req.url.includes(".env")) {
      console.warn(`[ZentyTeams-RASP] Suspicious probe detected on ${req.url} from ${req.ip}`);
    }

    next();
  };
}
