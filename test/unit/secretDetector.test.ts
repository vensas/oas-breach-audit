import { describe, expect, it } from "vitest";
import { detectSecrets, mergeSecretSamples } from "../../src/analysis/secretDetector.js";

describe("detectSecrets", () => {
  it("finds a JWT in the body", () => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    const matches = detectSecrets(`{"token": "${jwt}"}`, {});
    expect(matches.some((m) => m.kind === "jwt")).toBe(true);
  });

  it("finds a JSON-embedded csrf token field", () => {
    const matches = detectSecrets('{"csrf_token": "aB3dE5fG7hI9"}', {});
    expect(matches).toContainEqual({ kind: "token-field", location: "body", sample: "aB3dE5fG7hI9" });
  });

  it("finds an HTML hidden csrf input", () => {
    const html = '<input type="hidden" name="csrf_token" value="Zk9mQwErTy12">';
    const matches = detectSecrets(html, {});
    expect(matches.some((m) => m.kind === "token-field" && m.sample === "Zk9mQwErTy12")).toBe(true);
  });

  it("finds a session cookie from Set-Cookie", () => {
    const matches = detectSecrets("{}", { "set-cookie": "sessionid=abcdef123456; Path=/; HttpOnly" });
    expect(matches).toContainEqual({ kind: "session-cookie", location: "header", sample: "abcdef123456" });
  });

  it("ignores short or unrelated values", () => {
    const matches = detectSecrets('{"status": "ok", "id": "42"}', {});
    expect(matches).toHaveLength(0);
  });
});

describe("mergeSecretSamples", () => {
  it("flags a secret as varying when its value differs across two samples", () => {
    const first = [{ kind: "session-cookie", location: "header" as const, sample: "aaaaaaaaaaaa" }];
    const second = [{ kind: "session-cookie", location: "header" as const, sample: "bbbbbbbbbbbb" }];
    const merged = mergeSecretSamples(first, second);
    expect(merged[0]?.varies).toBe(true);
  });

  it("does not flag a secret as varying when the value is identical", () => {
    const first = [{ kind: "session-cookie", location: "header" as const, sample: "aaaaaaaaaaaa" }];
    const second = [{ kind: "session-cookie", location: "header" as const, sample: "aaaaaaaaaaaa" }];
    const merged = mergeSecretSamples(first, second);
    expect(merged[0]?.varies).toBe(false);
  });

  it("treats a secret missing from the second sample as not confirmed-varying", () => {
    const first = [{ kind: "jwt", location: "body" as const, sample: "aaaaaaaaaaaa" }];
    const merged = mergeSecretSamples(first, []);
    expect(merged[0]?.varies).toBe(false);
  });
});
