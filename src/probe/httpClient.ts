import * as http from "node:http";
import * as https from "node:https";
import * as tls from "node:tls";
import * as zlib from "node:zlib";
import type { TlsCheck } from "../types.js";

export interface ProbeRequest {
  url: string;
  method?: string;
  headers?: Record<string, string>;
}

export interface ProbeResponse {
  statusCode: number;
  headers: http.IncomingHttpHeaders;
  /** Exact byte length of the body as it arrived on the wire, before any decompression. */
  rawByteLength: number;
  /** Best-effort UTF-8 decoded body, after undoing Content-Encoding if present. */
  decodedBody: string;
  tls: TlsCheck;
}

export interface ProbeOptions {
  timeoutMs?: number;
  /** Set false to accept self-signed/invalid certs, e.g. when auditing a staging environment. */
  rejectUnauthorized?: boolean;
}

/**
 * Sends a single HTTP(S) request using Node's core client so the response body
 * is never auto-decompressed — the raw wire byte count is what a BREACH-style
 * observer would see (a proxy for the encrypted TLS record size).
 */
export function probe(req: ProbeRequest, options: ProbeOptions = {}): Promise<ProbeResponse> {
  const timeoutMs = options.timeoutMs ?? 10_000;
  return new Promise((resolve, reject) => {
    const url = new URL(req.url);
    const isHttps = url.protocol === "https:";
    const client = isHttps ? https : http;

    const request = client.request(
      url,
      {
        method: req.method ?? "GET",
        headers: req.headers,
        timeout: timeoutMs,
        ...(isHttps ? { rejectUnauthorized: options.rejectUnauthorized ?? true } : {}),
        // We intentionally do NOT set decompress/auto-gunzip — Node's core
        // http/https clients never do this on their own.
      },
      (res) => {
        // The socket is captured here, not in the "end" handler: once the
        // response fully completes, Node may detach/reuse it (keep-alive),
        // and getProtocol() would otherwise be unreliable.
        const socket = res.socket;
        const tlsInfo: TlsCheck = {
          isHttps,
          protocol: url.protocol,
          tlsVersion: socket instanceof tls.TLSSocket ? socket.getProtocol() : null,
        };

        const chunks: Buffer[] = [];
        let byteLength = 0;
        res.on("data", (chunk: Buffer) => {
          chunks.push(chunk);
          byteLength += chunk.length;
        });
        res.on("end", () => {
          const rawBody = Buffer.concat(chunks);
          const decodedBody = decodeBody(rawBody, res.headers["content-encoding"]);
          resolve({
            statusCode: res.statusCode ?? 0,
            headers: res.headers,
            rawByteLength: byteLength,
            decodedBody,
            tls: tlsInfo,
          });
        });
        res.on("error", reject);
      },
    );

    request.on("timeout", () => request.destroy(new Error(`Request timed out after ${timeoutMs}ms: ${req.url}`)));
    request.on("error", reject);
    request.end();
  });
}

function decodeBody(rawBody: Buffer, contentEncoding: string | string[] | undefined): string {
  const encoding = Array.isArray(contentEncoding) ? contentEncoding[0] : contentEncoding;
  try {
    switch (encoding) {
      case "gzip":
      case "x-gzip":
        return zlib.gunzipSync(rawBody).toString("utf8");
      case "deflate":
        return zlib.inflateSync(rawBody).toString("utf8");
      case "br":
        return zlib.brotliDecompressSync(rawBody).toString("utf8");
      default:
        return rawBody.toString("utf8");
    }
  } catch {
    return rawBody.toString("utf8");
  }
}
