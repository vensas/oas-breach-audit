import type { CompressionCheck, OracleProofResult, ReflectionResult, RiskLevel, SecretMatch, TlsCheck } from "../types.js";

export interface RiskInputs {
  tls: TlsCheck;
  compression: CompressionCheck;
  reflections: ReflectionResult[];
  secrets: SecretMatch[];
  oracle: OracleProofResult;
}

export interface RiskResult {
  risk: RiskLevel;
  reasons: string[];
}

/**
 * BREACH needs, jointly: HTTPS transport, compressed responses, a reflected
 * attacker-controlled parameter, and a worthwhile secret in the response.
 * Each missing precondition caps the achievable risk level; the oracle proof
 * and a *varying* secret are what push a finding from "plausible" to
 * "demonstrated".
 */
export function scoreRisk(inputs: RiskInputs): RiskResult {
  const { tls, compression, reflections, secrets, oracle } = inputs;
  const reasons: string[] = [];
  const hasReflection = reflections.some((r) => r.reflected);
  const hasSecret = secrets.length > 0;
  const hasVaryingSecret = secrets.some((s) => s.varies);

  if (!tls.isHttps) {
    reasons.push("Endpoint is not served over HTTPS; BREACH targets encrypted responses.");
    return { risk: "info", reasons };
  }
  if (!compression.supported) {
    reasons.push("Response is not compressed (no Content-Encoding); the compression oracle does not exist here.");
    return { risk: "info", reasons };
  }

  reasons.push(`Response is compressed with Content-Encoding: ${compression.contentEncoding}.`);

  if (!hasReflection) {
    reasons.push("No tested parameter was reflected in the response body.");
    return { risk: "low", reasons };
  }
  reasons.push("At least one request parameter is reflected in the response body.");

  if (!hasSecret) {
    reasons.push("No session token, CSRF token, JWT, or similar secret-shaped value was found in the response.");
    return { risk: "medium", reasons };
  }
  reasons.push(`Found ${secrets.length} secret-shaped value(s) in the response (${[...new Set(secrets.map((s) => s.kind))].join(", ")}).`);

  if (hasVaryingSecret) reasons.push("At least one of those values changes between requests, consistent with a live session/CSRF token.");

  if (oracle.correlationObserved) {
    reasons.push(oracle.detail);
    return { risk: hasVaryingSecret ? "critical" : "high", reasons };
  }
  reasons.push(oracle.attempted ? oracle.detail : `Oracle proof not run: ${oracle.detail}`);

  return { risk: hasVaryingSecret ? "high" : "medium", reasons };
}
