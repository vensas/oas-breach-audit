import { describe, expect, it } from "vitest";
import { extractOperations, inferBaseUrl } from "../../src/spec/loader.js";
import type { OpenAPI } from "openapi-types";

describe("extractOperations (OpenAPI 3)", () => {
  const doc = {
    openapi: "3.0.0",
    info: { title: "test", version: "1.0.0" },
    servers: [{ url: "https://api.example.com/v1" }],
    paths: {
      "/search": {
        get: {
          operationId: "search",
          parameters: [{ name: "q", in: "query", schema: { type: "string", example: "hello" } }],
          responses: {
            "200": { description: "ok", content: { "application/json": {} } },
          },
        },
      },
      "/users/{id}": {
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
        get: {
          operationId: "getUser",
          responses: { "200": { description: "ok", content: { "application/json": {} } } },
        },
      },
    },
  } as unknown as OpenAPI.Document;

  it("flattens path/operation combinations into Operation entries", () => {
    const operations = extractOperations(doc);
    expect(operations).toHaveLength(2);
    expect(operations.map((o) => o.operationId).sort()).toEqual(["getUser", "search"]);
  });

  it("extracts query params with their example value", () => {
    const [search] = extractOperations(doc).filter((o) => o.operationId === "search");
    expect(search?.params).toEqual([{ name: "q", location: "query", example: "hello" }]);
  });

  it("inherits path-level parameters into the operation", () => {
    const [getUser] = extractOperations(doc).filter((o) => o.operationId === "getUser");
    expect(getUser?.params).toEqual([{ name: "id", location: "path", example: undefined }]);
  });

  it("infers the base URL from servers[0]", () => {
    expect(inferBaseUrl(doc)).toBe("https://api.example.com/v1");
  });
});

describe("extractOperations (Swagger 2.0)", () => {
  const doc = {
    swagger: "2.0",
    info: { title: "test", version: "1.0.0" },
    host: "api.example.com",
    basePath: "/v1",
    schemes: ["https"],
    paths: {
      "/ping": {
        get: {
          operationId: "ping",
          parameters: [{ name: "verbose", in: "query", type: "string" }],
          produces: ["application/json"],
          responses: { "200": { description: "ok" } },
        },
      },
    },
  } as unknown as OpenAPI.Document;

  it("flattens v2 operations", () => {
    const operations = extractOperations(doc);
    expect(operations).toHaveLength(1);
    expect(operations[0]?.operationId).toBe("ping");
    expect(operations[0]?.params).toEqual([{ name: "verbose", location: "query", example: undefined }]);
  });

  it("infers the base URL from host/basePath/schemes", () => {
    expect(inferBaseUrl(doc)).toBe("https://api.example.com/v1");
  });
});
