import { execFileSync } from "node:child_process";
import * as https from "node:https";
import * as crypto from "node:crypto";
import * as os from "node:os";
import * as fs from "node:fs";
import * as path from "node:path";
import * as zlib from "node:zlib";

const LANDMARK = "SUPERSECRETLANDMARKVALUE0123456789ABCDEF";

function generateSelfSignedCert(): { key: string; cert: string } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "oas-breach-audit-cert-"));
  const keyPath = path.join(dir, "key.pem");
  const certPath = path.join(dir, "cert.pem");
  execFileSync("openssl", [
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-keyout",
    keyPath,
    "-out",
    certPath,
    "-days",
    "1",
    "-subj",
    "/CN=localhost",
  ]);
  const key = fs.readFileSync(keyPath, "utf8");
  const cert = fs.readFileSync(certPath, "utf8");
  fs.rmSync(dir, { recursive: true, force: true });
  return { key, cert };
}

function sendJson(
  res: import("node:http").ServerResponse,
  acceptEncoding: string,
  body: Record<string, unknown>,
  extraHeaders: Record<string, string> = {},
): void {
  const json = JSON.stringify(body);
  const wantsGzip = acceptEncoding.includes("gzip");
  const payload = wantsGzip ? zlib.gzipSync(json) : Buffer.from(json, "utf8");
  res.writeHead(200, {
    "content-type": "application/json",
    ...(wantsGzip ? { "content-encoding": "gzip" } : {}),
    ...extraHeaders,
  });
  res.end(payload);
}

export interface TestServer {
  baseUrl: string;
  close: () => Promise<void>;
}

/**
 * A minimal HTTPS server exposing a handful of endpoints that represent
 * distinct points on the BREACH-risk spectrum, used to exercise the scanner
 * end-to-end without hitting a real third-party service.
 *
 * Routes:
 *  - /safe                 not compressed -> risk should stay "info"
 *  - /reflect-no-secret    reflected + compressed, no secret -> "medium"
 *  - /vulnerable           reflected + compressed + varying CSRF token + oracle landmark -> "critical"
 *  - /vulnerable-static    reflected + compressed + static session cookie + oracle landmark -> "high"
 */
export async function startTestServer(): Promise<TestServer> {
  const { key, cert } = generateSelfSignedCert();

  const server = https.createServer({ key, cert }, (req, res) => {
    const url = new URL(req.url ?? "/", "https://localhost");
    const acceptEncoding = req.headers["accept-encoding"]?.toString() ?? "";
    const q = url.searchParams.get("q") ?? "";

    if (url.pathname === "/safe") {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("hello world");
      return;
    }

    if (url.pathname === "/reflect-no-secret") {
      sendJson(res, acceptEncoding, { q, status: "ok" });
      return;
    }

    if (url.pathname === "/vulnerable") {
      sendJson(res, acceptEncoding, {
        q,
        csrfToken: crypto.randomBytes(8).toString("hex"),
        landmark: LANDMARK,
      });
      return;
    }

    if (url.pathname === "/vulnerable-static") {
      sendJson(
        res,
        acceptEncoding,
        { q, landmark: LANDMARK },
        { "set-cookie": "sessionid=AAAABBBBCCCCDDDD; Path=/" },
      );
      return;
    }

    res.writeHead(404);
    res.end();
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Failed to bind test server");

  return {
    baseUrl: `https://127.0.0.1:${address.port}`,
    close: () => new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve()))),
  };
}
