import SwaggerParser from "@apidevtools/swagger-parser";
import type { OpenAPI, OpenAPIV2, OpenAPIV3, OpenAPIV3_1 } from "openapi-types";
import type { HttpMethod, Operation, ParamLocation, TestableParam } from "../types.js";

const HTTP_METHODS: HttpMethod[] = ["get", "put", "post", "delete", "options", "head", "patch", "trace"];

const TLS_ERROR_CODES = new Set([
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "CERT_HAS_EXPIRED",
  "ERR_TLS_CERT_ALTNAME_INVALID",
]);

export interface LoadSpecOptions {
  /** Skip TLS certificate verification when downloading the spec itself, e.g. from a self-signed staging host. */
  insecure?: boolean;
}

/**
 * Loads and fully dereferences an OpenAPI 2.0 or 3.x document from a file path
 * or URL, so every $ref in the returned document is inlined.
 */
export async function loadSpec(pathOrUrl: string, options: LoadSpecOptions = {}): Promise<OpenAPI.Document> {
  if (!options.insecure) {
    try {
      return (await SwaggerParser.dereference(pathOrUrl)) as OpenAPI.Document;
    } catch (error) {
      throw await withTlsHint(pathOrUrl, error);
    }
  }

  // swagger-parser's HTTP resolver uses the global `fetch`, which has no
  // per-call TLS option — toggling this env var is the only way to relax
  // certificate verification for that download.
  const previousTlsSetting = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  try {
    return (await SwaggerParser.dereference(pathOrUrl)) as OpenAPI.Document;
  } finally {
    if (previousTlsSetting === undefined) {
      delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    } else {
      process.env.NODE_TLS_REJECT_UNAUTHORIZED = previousTlsSetting;
    }
  }
}

/**
 * swagger-parser wraps download failures in a generic "fetch failed" error
 * and discards the underlying TLS error code. Re-probe the URL directly (with
 * verification still on) to recover that detail and surface an actionable hint.
 */
async function withTlsHint(pathOrUrl: string, error: unknown): Promise<Error> {
  const cause = error instanceof Error ? error : new Error(String(error));
  if (!/^https:\/\//i.test(pathOrUrl) || !cause.message.includes("fetch failed")) {
    return cause;
  }

  try {
    await fetch(pathOrUrl);
  } catch (rawError) {
    const code = (rawError as { cause?: { code?: string } })?.cause?.code;
    if (code && TLS_ERROR_CODES.has(code)) {
      return new Error(
        `Could not download spec from ${pathOrUrl}: TLS certificate rejected (${code}). ` +
          `If this is a trusted self-signed/staging certificate, retry with --insecure.`,
      );
    }
  }
  return cause;
}

/**
 * Best-effort base URL derived from the spec itself (OpenAPI 3 `servers[0]`,
 * or Swagger 2 `schemes`/`host`/`basePath`). Callers should still let users
 * override this explicitly, since specs often list placeholder servers.
 */
export function inferBaseUrl(doc: OpenAPI.Document): string | undefined {
  if (isV3(doc)) {
    return doc.servers?.[0]?.url;
  }
  const v2doc = doc as OpenAPIV2.Document;
  if (!v2doc.host) return undefined;
  const scheme = v2doc.schemes?.[0] ?? "https";
  return `${scheme}://${v2doc.host}${v2doc.basePath ?? ""}`;
}

function isV3(doc: OpenAPI.Document): doc is OpenAPIV3.Document | OpenAPIV3_1.Document {
  return "openapi" in doc;
}

function paramLocation(inValue: string): ParamLocation | null {
  if (inValue === "query" || inValue === "header" || inValue === "path") return inValue;
  return null;
}

function extractParamsV2(op: OpenAPIV2.OperationObject, pathItem: OpenAPIV2.PathItemObject): TestableParam[] {
  const all = [...(pathItem.parameters ?? []), ...(op.parameters ?? [])] as OpenAPIV2.Parameter[];
  const params: TestableParam[] = [];
  for (const p of all) {
    if (!("in" in p)) continue;
    const location = paramLocation(p.in);
    if (!location) continue;
    params.push({
      name: p.name,
      location,
      example: typeof (p as { default?: unknown }).default === "string" ? (p as { default?: string }).default : undefined,
    });
  }
  return params;
}

function extractParamsV3(
  op: OpenAPIV3.OperationObject | OpenAPIV3_1.OperationObject,
  pathItem: OpenAPIV3.PathItemObject | OpenAPIV3_1.PathItemObject,
): TestableParam[] {
  const all = [
    ...((pathItem.parameters ?? []) as OpenAPIV3.ParameterObject[]),
    ...((op.parameters ?? []) as OpenAPIV3.ParameterObject[]),
  ];
  const params: TestableParam[] = [];
  for (const p of all) {
    const location = paramLocation(p.in);
    if (!location) continue;
    const schema = p.schema as OpenAPIV3.SchemaObject | undefined;
    const example =
      typeof p.example === "string"
        ? p.example
        : typeof schema?.example === "string"
          ? schema.example
          : typeof schema?.default === "string"
            ? schema.default
            : undefined;
    params.push({ name: p.name, location, example });
  }
  return params;
}

function responseContentTypesV2(op: OpenAPIV2.OperationObject, doc: OpenAPIV2.Document): string[] {
  const produces = op.produces ?? doc.produces ?? [];
  return produces.length > 0 ? produces : ["application/json"];
}

function responseContentTypesV3(op: OpenAPIV3.OperationObject | OpenAPIV3_1.OperationObject): string[] {
  const types = new Set<string>();
  const responses = op.responses ?? {};
  for (const [status, response] of Object.entries(responses)) {
    if (!status.startsWith("2")) continue;
    const content = (response as OpenAPIV3.ResponseObject)?.content;
    if (!content) continue;
    for (const type of Object.keys(content)) types.add(type);
  }
  return types.size > 0 ? [...types] : ["application/json"];
}

/**
 * Flattens a dereferenced OpenAPI document into a list of operations carrying
 * only what the scanner needs: method, path template, testable parameters,
 * and declared 2xx response content-types.
 */
export function extractOperations(doc: OpenAPI.Document): Operation[] {
  const operations: Operation[] = [];

  if (isV3(doc)) {
    for (const [path, pathItem] of Object.entries(doc.paths ?? {})) {
      if (!pathItem) continue;
      for (const method of HTTP_METHODS) {
        const op = (pathItem as Record<string, unknown>)[method] as
          | OpenAPIV3.OperationObject
          | OpenAPIV3_1.OperationObject
          | undefined;
        if (!op) continue;
        operations.push({
          operationId: op.operationId ?? `${method.toUpperCase()} ${path}`,
          method,
          path,
          params: extractParamsV3(op, pathItem as OpenAPIV3.PathItemObject),
          responseContentTypes: responseContentTypesV3(op),
        });
      }
    }
  } else {
    const v2doc = doc as OpenAPIV2.Document;
    for (const [path, pathItem] of Object.entries(v2doc.paths ?? {})) {
      if (!pathItem) continue;
      for (const method of HTTP_METHODS) {
        const op = (pathItem as Record<string, unknown>)[method] as OpenAPIV2.OperationObject | undefined;
        if (!op) continue;
        operations.push({
          operationId: op.operationId ?? `${method.toUpperCase()} ${path}`,
          method,
          path,
          params: extractParamsV2(op, pathItem as OpenAPIV2.PathItemObject),
          responseContentTypes: responseContentTypesV2(op, v2doc),
        });
      }
    }
  }

  return operations;
}
