import { analyzeReflections } from "./analysis/reflection.js";
import { proveOracle } from "./analysis/oracle.js";
import { detectSecrets, mergeSecretSamples } from "./analysis/secretDetector.js";
import { scoreRisk } from "./analysis/riskScorer.js";
import { checkCompression } from "./probe/compression.js";
import { probe } from "./probe/httpClient.js";
import { buildRequest } from "./probe/requestBuilder.js";
import { checkTls } from "./probe/tlsCheck.js";
import type { Operation, OperationFinding, RiskLevel, ScanReport } from "./types.js";

export interface ScanOptions {
  baseUrl: string;
  operations: Operation[];
  extraHeaders?: Record<string, string>;
  timeoutMs?: number;
  /** Set true to accept self-signed/invalid certs, e.g. when auditing a staging environment. */
  insecureTls?: boolean;
  onProgress?: (done: number, total: number, operation: Operation) => void;
}

export async function scan(options: ScanOptions): Promise<ScanReport> {
  const findings: OperationFinding[] = [];

  for (let i = 0; i < options.operations.length; i++) {
    const operation = options.operations[i]!;
    findings.push(await scanOperation(options.baseUrl, operation, options));
    options.onProgress?.(i + 1, options.operations.length, operation);
  }

  const summary: Record<RiskLevel, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const finding of findings) summary[finding.risk]++;

  return { baseUrl: options.baseUrl, generatedAt: new Date().toISOString(), findings, summary };
}

async function scanOperation(baseUrl: string, operation: Operation, options: ScanOptions): Promise<OperationFinding> {
  const baseline = buildRequest(baseUrl, operation, {});
  Object.assign(baseline.headers, options.extraHeaders ?? {});
  const probeOptions = { timeoutMs: options.timeoutMs, rejectUnauthorized: !options.insecureTls };

  try {
    const [first, second] = await Promise.all([probe(baseline, probeOptions), probe(baseline, probeOptions)]);

    const tls = checkTls(first);
    const compression = checkCompression(first);
    const reflections = operation.params.length > 0 ? await analyzeReflections(baseUrl, operation, probeOptions) : [];
    const secrets = mergeSecretSamples(
      detectSecrets(first.decodedBody, first.headers as Record<string, string | string[] | undefined>),
      detectSecrets(second.decodedBody, second.headers as Record<string, string | string[] | undefined>),
    );
    const oracle =
      compression.supported && reflections.some((r) => r.reflected)
        ? await proveOracle(baseUrl, operation, reflections, first.decodedBody, probeOptions)
        : { attempted: false, landmarkFound: false, correlationObserved: false, detail: "Skipped: compression or reflection precondition not met." };

    const { risk, reasons } = scoreRisk({ tls, compression, reflections, secrets, oracle });

    return { operation, url: baseline.url, tls, compression, reflections, secrets, oracle, risk, reasons };
  } catch (error) {
    return {
      operation,
      url: baseline.url,
      tls: { isHttps: baseUrl.startsWith("https:"), protocol: null, tlsVersion: null },
      compression: { supported: false, contentEncoding: null },
      reflections: [],
      secrets: [],
      oracle: { attempted: false, landmarkFound: false, correlationObserved: false, detail: "Not run: request failed." },
      risk: "info",
      reasons: [],
      error: error instanceof Error ? error.message : String(error),
    };
  }
}
