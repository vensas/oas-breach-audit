import { probe, type ProbeOptions } from "../probe/httpClient.js";
import { buildRequest } from "../probe/requestBuilder.js";
import type { Operation, OracleProofResult, ReflectionResult } from "../types.js";

const FILLER_CHAR = "~";
const MAX_SAMPLES = 8;

/**
 * Finds a distinctive, non-numeric token (>= 8 word chars, appearing exactly
 * once) in a baseline body to stand in for a "secret" during the oracle
 * test. It doesn't need to be an actual secret — any static text unique to
 * the response works to demonstrate that compression ratio leaks information
 * about content the attacker doesn't yet know.
 */
function findLandmark(body: string): string | null {
  const counts = new Map<string, number>();
  for (const token of body.matchAll(/[A-Za-z0-9_-]{8,}/g)) {
    const word = token[0];
    if (/^oasbr/.test(word) || /^[0-9]+$/.test(word)) continue;
    counts.set(word, (counts.get(word) ?? 0) + 1);
  }
  let best: string | null = null;
  for (const [word, count] of counts) {
    if (count !== 1) continue;
    if (!best || word.length > best.length) best = word;
  }
  return best;
}

function pearsonCorrelation(xs: number[], ys: number[]): number {
  const n = xs.length;
  const meanX = xs.reduce((a, b) => a + b, 0) / n;
  const meanY = ys.reduce((a, b) => a + b, 0) / n;
  let cov = 0;
  let varX = 0;
  let varY = 0;
  for (let i = 0; i < n; i++) {
    const dx = xs[i]! - meanX;
    const dy = ys[i]! - meanY;
    cov += dx * dy;
    varX += dx * dx;
    varY += dy * dy;
  }
  if (varX === 0 || varY === 0) return 0;
  return cov / Math.sqrt(varX * varY);
}

function sampleSteps(length: number): number[] {
  if (length <= MAX_SAMPLES) return Array.from({ length: length + 1 }, (_, i) => i);
  const steps: number[] = [];
  for (let i = 0; i < MAX_SAMPLES; i++) steps.push(Math.round((i * length) / (MAX_SAMPLES - 1)));
  return [...new Set(steps)];
}

/**
 * Proves (or disproves) that the classic BREACH compression side-channel is
 * exploitable against this operation: a reflected, attacker-controlled
 * parameter whose growing prefix-match against fixed response content
 * measurably shrinks the compressed response size. This is the generic
 * precondition for byte-at-a-time secret extraction — it deliberately stops
 * short of extracting any real secret value.
 */
export async function proveOracle(
  baseUrl: string,
  operation: Operation,
  reflections: ReflectionResult[],
  baselineBody: string,
  probeOptions: ProbeOptions = {},
): Promise<OracleProofResult> {
  const reflectedParam = reflections.find((r) => r.reflected)?.param;
  if (!reflectedParam) {
    return { attempted: false, landmarkFound: false, correlationObserved: false, detail: "No reflected parameter to drive the oracle." };
  }

  const landmark = findLandmark(baselineBody);
  if (!landmark) {
    return {
      attempted: false,
      landmarkFound: false,
      correlationObserved: false,
      detail: "No distinctive static content found in the response to correlate against.",
    };
  }

  const steps = sampleSteps(landmark.length);
  const samples: { matched: number; bytes: number }[] = [];

  for (const matched of steps) {
    const guess = landmark.slice(0, matched) + FILLER_CHAR.repeat(landmark.length - matched);
    const request = buildRequest(baseUrl, operation, { [reflectedParam.name]: guess });
    try {
      const response = await probe({ url: request.url, headers: request.headers }, probeOptions);
      samples.push({ matched, bytes: response.rawByteLength });
    } catch {
      // Skip failed samples; correlation is computed over whatever succeeded.
    }
  }

  if (samples.length < 3) {
    return {
      attempted: true,
      landmarkFound: true,
      correlationObserved: false,
      detail: `Only ${samples.length} of ${steps.length} probe(s) succeeded; not enough data to correlate.`,
    };
  }

  const correlation = pearsonCorrelation(
    samples.map((s) => s.matched),
    samples.map((s) => s.bytes),
  );
  const correlationObserved = correlation <= -0.3;

  return {
    attempted: true,
    landmarkFound: true,
    correlationObserved,
    detail: correlationObserved
      ? `Compressed response size shrank as the "${reflectedParam.name}" parameter's prefix matched more of a static response landmark (Pearson r = ${correlation.toFixed(2)}), confirming a compression oracle.`
      : `No significant size/prefix-match correlation observed (Pearson r = ${correlation.toFixed(2)}).`,
  };
}
