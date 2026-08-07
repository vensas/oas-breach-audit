import { writeFile } from "node:fs/promises";
import { Command } from "commander";
import pc from "picocolors";
import { extractOperations, inferBaseUrl, loadSpec } from "./spec/loader.js";
import { scan } from "./scanner.js";
import { toConsole, toJson } from "./report/reporter.js";
import type { HttpMethod, Operation } from "./types.js";

const SAFE_METHODS: HttpMethod[] = ["get", "head"];

function parseHeader(value: string, previous: Record<string, string>): Record<string, string> {
  const separatorIndex = value.indexOf(":");
  if (separatorIndex === -1) {
    throw new Error(`Invalid --header value "${value}", expected "Name: Value".`);
  }
  const name = value.slice(0, separatorIndex).trim().toLowerCase();
  const val = value.slice(separatorIndex + 1).trim();
  return { ...previous, [name]: val };
}

function filterOperations(operations: Operation[], includeUnsafe: boolean, maxOperations?: number): Operation[] {
  const filtered = includeUnsafe ? operations : operations.filter((op) => SAFE_METHODS.includes(op.method));
  return maxOperations ? filtered.slice(0, maxOperations) : filtered;
}

const program = new Command();

program
  .name("oas-breach-audit")
  .description("Audit an OpenAPI-described HTTP service for BREACH compression-attack preconditions.")
  .version("0.1.0");

program
  .command("scan")
  .description("Scan every operation in an OpenAPI spec against a live base URL.")
  .requiredOption("--spec <pathOrUrl>", "path or URL to an OpenAPI 2.0/3.x document (JSON or YAML)")
  .option("--base-url <url>", "base URL of the running service (overrides the spec's declared servers)")
  .option("--header <name:value>", "extra header to send with every request (repeatable)", parseHeader, {})
  .option("--json <path>", "write the full report as JSON to this path")
  .option("--timeout <ms>", "per-request timeout in milliseconds", "10000")
  .option("--max-operations <n>", "cap the number of operations scanned", (v) => Number.parseInt(v, 10))
  .option(
    "--unsafe-methods",
    "also test non-idempotent methods (POST/PUT/DELETE/PATCH); off by default to avoid side effects on the target",
    false,
  )
  .option("--insecure", "do not verify TLS certificates (for self-signed staging environments)", false)
  .action(async (opts) => {
    const doc = await loadSpec(opts.spec, { insecure: opts.insecure });
    const baseUrl = opts.baseUrl ?? inferBaseUrl(doc);
    if (!baseUrl) {
      console.error(pc.red("No --base-url given and none could be inferred from the spec."));
      process.exitCode = 1;
      return;
    }

    const allOperations = extractOperations(doc);
    const operations = filterOperations(allOperations, opts.unsafeMethods, opts.maxOperations);
    if (operations.length === 0) {
      console.error(pc.red("No testable operations found (try --unsafe-methods if the spec only defines non-GET routes)."));
      process.exitCode = 1;
      return;
    }

    console.error(pc.dim(`Scanning ${operations.length} of ${allOperations.length} operation(s) at ${baseUrl}...`));

    const report = await scan({
      baseUrl,
      operations,
      extraHeaders: opts.header,
      timeoutMs: Number.parseInt(opts.timeout, 10),
      insecureTls: opts.insecure,
      onProgress: (done, total, operation) => {
        console.error(pc.dim(`  [${done}/${total}] ${operation.method.toUpperCase()} ${operation.path}`));
      },
    });

    console.log(toConsole(report));

    if (opts.json) {
      await writeFile(opts.json, toJson(report), "utf8");
      console.error(pc.dim(`Wrote JSON report to ${opts.json}`));
    }

    if (report.summary.critical > 0 || report.summary.high > 0) {
      process.exitCode = 2;
    }
  });

program.parseAsync(process.argv).catch((error) => {
  console.error(pc.red(error instanceof Error ? error.message : String(error)));
  process.exitCode = 1;
});
