import { describe, expect, it } from "vitest";
import { scoreRisk } from "../../src/analysis/riskScorer.js";
import type { ReflectionResult, SecretMatch, TestableParam } from "../../src/types.js";

const param: TestableParam = { name: "q", location: "query" };
const reflected: ReflectionResult[] = [{ param, reflected: true }];
const notReflected: ReflectionResult[] = [{ param, reflected: false }];
const noOracle = { attempted: false, landmarkFound: false, correlationObserved: false, detail: "n/a" };
const oracleConfirmed = { attempted: true, landmarkFound: true, correlationObserved: true, detail: "correlated" };

function secret(varies: boolean): SecretMatch {
  return { kind: "session-cookie", location: "header", sample: "abcdef123456", varies };
}

describe("scoreRisk", () => {
  it("is info when not served over https", () => {
    const result = scoreRisk({
      tls: { isHttps: false, protocol: "http:", tlsVersion: null },
      compression: { supported: true, contentEncoding: "gzip" },
      reflections: reflected,
      secrets: [secret(true)],
      oracle: oracleConfirmed,
    });
    expect(result.risk).toBe("info");
  });

  it("is info when the response is not compressed", () => {
    const result = scoreRisk({
      tls: { isHttps: true, protocol: "https:", tlsVersion: "TLSv1.3" },
      compression: { supported: false, contentEncoding: null },
      reflections: reflected,
      secrets: [secret(true)],
      oracle: oracleConfirmed,
    });
    expect(result.risk).toBe("info");
  });

  it("is low when compressed but nothing is reflected", () => {
    const result = scoreRisk({
      tls: { isHttps: true, protocol: "https:", tlsVersion: "TLSv1.3" },
      compression: { supported: true, contentEncoding: "gzip" },
      reflections: notReflected,
      secrets: [],
      oracle: noOracle,
    });
    expect(result.risk).toBe("low");
  });

  it("is medium when reflected and compressed but no secret is present", () => {
    const result = scoreRisk({
      tls: { isHttps: true, protocol: "https:", tlsVersion: "TLSv1.3" },
      compression: { supported: true, contentEncoding: "gzip" },
      reflections: reflected,
      secrets: [],
      oracle: noOracle,
    });
    expect(result.risk).toBe("medium");
  });

  it("is medium when a secret is present but the oracle proof did not correlate", () => {
    const result = scoreRisk({
      tls: { isHttps: true, protocol: "https:", tlsVersion: "TLSv1.3" },
      compression: { supported: true, contentEncoding: "gzip" },
      reflections: reflected,
      secrets: [secret(false)],
      oracle: { attempted: true, landmarkFound: true, correlationObserved: false, detail: "no correlation" },
    });
    expect(result.risk).toBe("medium");
  });

  it("is high when the secret varies but the oracle proof did not run", () => {
    const result = scoreRisk({
      tls: { isHttps: true, protocol: "https:", tlsVersion: "TLSv1.3" },
      compression: { supported: true, contentEncoding: "gzip" },
      reflections: reflected,
      secrets: [secret(true)],
      oracle: noOracle,
    });
    expect(result.risk).toBe("high");
  });

  it("is high when the oracle correlates but the secret does not vary", () => {
    const result = scoreRisk({
      tls: { isHttps: true, protocol: "https:", tlsVersion: "TLSv1.3" },
      compression: { supported: true, contentEncoding: "gzip" },
      reflections: reflected,
      secrets: [secret(false)],
      oracle: oracleConfirmed,
    });
    expect(result.risk).toBe("high");
  });

  it("is critical when the secret varies and the oracle proof correlates", () => {
    const result = scoreRisk({
      tls: { isHttps: true, protocol: "https:", tlsVersion: "TLSv1.3" },
      compression: { supported: true, contentEncoding: "gzip" },
      reflections: reflected,
      secrets: [secret(true)],
      oracle: oracleConfirmed,
    });
    expect(result.risk).toBe("critical");
  });
});
