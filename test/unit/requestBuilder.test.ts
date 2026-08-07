import { describe, expect, it } from "vitest";
import { buildRequest } from "../../src/probe/requestBuilder.js";
import type { Operation } from "../../src/types.js";

const operation: Operation = {
  operationId: "getUser",
  method: "get",
  path: "/users/{id}/posts",
  params: [
    { name: "id", location: "path", example: "42" },
    { name: "q", location: "query" },
    { name: "x-trace", location: "header", example: "abc" },
  ],
  responseContentTypes: ["application/json"],
};

describe("buildRequest", () => {
  it("substitutes path params and fills query/header params with defaults", () => {
    const request = buildRequest("https://api.example.com", operation);
    const url = new URL(request.url);
    expect(url.pathname).toBe("/users/42/posts");
    expect(url.searchParams.get("q")).toBe("1");
    expect(request.headers["x-trace"]).toBe("abc");
  });

  it("applies overrides for a single targeted parameter", () => {
    const request = buildRequest("https://api.example.com", operation, { q: "nonce-value" });
    const url = new URL(request.url);
    expect(url.searchParams.get("q")).toBe("nonce-value");
    expect(url.pathname).toBe("/users/42/posts");
  });

  it("always sets an accept-encoding header requesting compression", () => {
    const request = buildRequest("https://api.example.com", operation);
    expect(request.headers["accept-encoding"]).toContain("gzip");
  });
});
