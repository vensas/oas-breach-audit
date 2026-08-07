import { probe, type ProbeOptions } from "../probe/httpClient.js";
import { buildRequest } from "../probe/requestBuilder.js";
import type { Operation, ReflectionResult, TestableParam } from "../types.js";

function nonce(seed: string): string {
  const random = Math.random().toString(36).slice(2, 10);
  return `oasbr${seed}${random}`;
}

/**
 * BREACH needs at least one parameter whose value the attacker controls (via
 * a lured request) to end up reflected in the response body alongside the
 * secret. This probes each testable parameter in isolation with a unique
 * nonce and checks whether it comes back in the response.
 */
export async function analyzeReflections(
  baseUrl: string,
  operation: Operation,
  probeOptions: ProbeOptions = {},
): Promise<ReflectionResult[]> {
  const results: ReflectionResult[] = [];
  for (const param of operation.params) {
    results.push(await checkOne(baseUrl, operation, param, probeOptions));
  }
  return results;
}

async function checkOne(
  baseUrl: string,
  operation: Operation,
  param: TestableParam,
  probeOptions: ProbeOptions,
): Promise<ReflectionResult> {
  const marker = nonce(param.name.replace(/[^a-z0-9]/gi, ""));
  const request = buildRequest(baseUrl, operation, { [param.name]: marker });
  try {
    const response = await probe({ url: request.url, headers: request.headers }, probeOptions);
    return { param, reflected: response.decodedBody.includes(marker) };
  } catch {
    return { param, reflected: false };
  }
}
