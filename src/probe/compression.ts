import type { CompressionCheck } from "../types.js";
import type { ProbeResponse } from "./httpClient.js";

const COMPRESSIBLE_ENCODINGS = new Set(["gzip", "x-gzip", "deflate", "br"]);

/**
 * BREACH requires the server to compress the HTTP response body (independent
 * of TLS-level compression, which is disabled in modern TLS stacks). This
 * inspects the Content-Encoding of a response fetched with a compression-
 * accepting client.
 */
export function checkCompression(response: ProbeResponse): CompressionCheck {
  const header = response.headers["content-encoding"];
  const contentEncoding = Array.isArray(header) ? (header[0] ?? null) : (header ?? null);
  return {
    supported: contentEncoding !== null && COMPRESSIBLE_ENCODINGS.has(contentEncoding),
    contentEncoding,
  };
}
