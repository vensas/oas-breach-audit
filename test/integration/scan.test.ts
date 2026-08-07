import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { scan } from "../../src/scanner.js";
import type { Operation } from "../../src/types.js";
import { startTestServer, type TestServer } from "../fixtures/testServer.js";

function op(path: string): Operation {
  return {
    operationId: path,
    method: "get",
    path,
    params: [{ name: "q", location: "query", example: "1" }],
    responseContentTypes: ["application/json"],
  };
}

describe("scan (integration)", () => {
  let server: TestServer;

  beforeAll(async () => {
    server = await startTestServer();
  }, 30_000);

  afterAll(async () => {
    await server.close();
  });

  it("marks an uncompressed endpoint as info", async () => {
    const report = await scan({
      baseUrl: server.baseUrl,
      operations: [{ ...op("/safe"), params: [] }],
      insecureTls: true,
    });
    expect(report.findings[0]?.risk).toBe("info");
    expect(report.findings[0]?.compression.supported).toBe(false);
  });

  it("marks a reflected-but-secretless endpoint as medium", async () => {
    const report = await scan({
      baseUrl: server.baseUrl,
      operations: [op("/reflect-no-secret")],
      insecureTls: true,
    });
    expect(report.findings[0]?.risk).toBe("medium");
    expect(report.findings[0]?.reflections[0]?.reflected).toBe(true);
  });

  it("proves the compression oracle and marks a varying-secret endpoint as critical", async () => {
    const report = await scan({
      baseUrl: server.baseUrl,
      operations: [op("/vulnerable")],
      insecureTls: true,
    });
    const finding = report.findings[0]!;
    expect(finding.secrets.some((s) => s.varies)).toBe(true);
    expect(finding.oracle.correlationObserved).toBe(true);
    expect(finding.risk).toBe("critical");
    expect(finding.tls.tlsVersion).toMatch(/^TLSv1\.\d$/);
  });

  it("marks a static-secret endpoint with a confirmed oracle as high, not critical", async () => {
    const report = await scan({
      baseUrl: server.baseUrl,
      operations: [op("/vulnerable-static")],
      insecureTls: true,
    });
    const finding = report.findings[0]!;
    expect(finding.secrets.some((s) => s.kind === "session-cookie")).toBe(true);
    expect(finding.secrets.every((s) => !s.varies)).toBe(true);
    expect(finding.oracle.correlationObserved).toBe(true);
    expect(finding.risk).toBe("high");
  });

  it("aggregates a per-risk-level summary across operations", async () => {
    const report = await scan({
      baseUrl: server.baseUrl,
      operations: [{ ...op("/safe"), params: [] }, op("/vulnerable")],
      insecureTls: true,
    });
    expect(report.summary.info).toBe(1);
    expect(report.summary.critical).toBe(1);
  });
});
