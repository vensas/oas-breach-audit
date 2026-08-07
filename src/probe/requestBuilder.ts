import type { Operation } from "../types.js";

const DEFAULT_FILLER = "1";

export interface BuiltRequest {
  url: string;
  headers: Record<string, string>;
}

/**
 * Builds a concrete request for an operation, filling every parameter with a
 * placeholder value (its spec example, or a generic filler) except for
 * `overrides`, which take the given literal value. Used both for baseline
 * probes and for reflection/oracle probes that vary exactly one parameter.
 */
export function buildRequest(
  baseUrl: string,
  operation: Operation,
  overrides: Record<string, string> = {},
  acceptEncoding = "gzip, deflate, br",
): BuiltRequest {
  let path = operation.path;
  const query = new URLSearchParams();
  const headers: Record<string, string> = {
    accept: operation.responseContentTypes.join(", ") || "*/*",
    "accept-encoding": acceptEncoding,
  };

  for (const param of operation.params) {
    const value = overrides[param.name] ?? param.example ?? DEFAULT_FILLER;
    switch (param.location) {
      case "path":
        path = path.replace(`{${param.name}}`, encodeURIComponent(value));
        break;
      case "query":
        query.append(param.name, value);
        break;
      case "header":
        headers[param.name.toLowerCase()] = value;
        break;
    }
  }

  const url = new URL(path.replace(/^\/?/, "/"), baseUrl);
  for (const [key, value] of query) url.searchParams.append(key, value);

  return { url: url.toString(), headers };
}
