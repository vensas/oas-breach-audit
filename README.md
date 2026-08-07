# oas-breach-audit

Audits an HTTP service described by an OpenAPI (2.0/3.x) spec for the
preconditions of a [BREACH](https://breachattack.com/) compression-oracle
attack, and — where those preconditions hold — runs a proof-of-concept
compression side-channel test to confirm the oracle is actually exploitable.

MIT licensed. No existing open-source tool does this OpenAPI-driven audit; the
handful of public BREACH tools ([rupture](https://github.com/decrypto-org/rupture),
[dimkarakostas/breach](https://github.com/dimkarakostas/breach)) are 2013-era
manual exploit PoCs that require you to already know which endpoint and
parameter to attack. This tool instead walks an entire API surface from its
spec and tells you which operations are even worth looking at.

## What it checks, per operation

BREACH requires four things to hold simultaneously. Each is checked, and each
missing one caps the reported risk:

1. **HTTPS** — BREACH is an attack on encrypted response sizes.
2. **Response compression** — `Content-Encoding: gzip|deflate|br` on the response.
3. **Reflection** — at least one query/header/path parameter's value is echoed
   back in the response body.
4. **A worthwhile secret** — a CSRF token, session cookie, JWT, or similarly
   named field in the response, ideally one that changes per request/session.

When 1–3 hold, the tool goes a step further and runs a **generic compression
oracle proof**: it finds a distinctive, static string already present in the
response and sends a series of requests where the reflected parameter shares
an increasing prefix with that string, measuring the raw (pre-decompression)
response byte count each time. A negative correlation between "characters
matched" and "bytes on the wire" is a direct demonstration of the same LZ77
back-reference effect BREACH exploits to recover secrets byte-by-byte — without
this tool ever trying to recover a real secret value itself.

| Condition                                   | Risk       |
| -------------------------------------------- | ---------- |
| Not HTTPS, or response not compressed        | `info`     |
| Compressed, nothing reflected                 | `low`      |
| Reflected, no secret-shaped value found       | `medium`   |
| Secret found but oracle didn't correlate      | `medium`   |
| Secret varies per request, no oracle run      | `high`     |
| Oracle correlates, secret doesn't vary        | `high`     |
| Oracle correlates **and** secret varies       | `critical` |

## CLI usage

```bash
pnpm install
pnpm build

node dist/cli.js scan \
  --spec ./openapi.yaml \
  --base-url https://staging.example.com \
  --header "Authorization: Bearer <token>" \
  --json report.json
```

Options:

- `--spec <pathOrUrl>` (required) — OpenAPI 2.0/3.x document, JSON or YAML, local path or URL.
- `--base-url <url>` — overrides the server URL inferred from the spec.
- `--header <name:value>` — extra header sent with every request (repeatable), e.g. auth.
- `--json <path>` — write the full machine-readable report to a file.
- `--timeout <ms>` — per-request timeout (default `10000`).
- `--max-operations <n>` — cap how many operations are scanned.
- `--unsafe-methods` — also probe non-idempotent methods (POST/PUT/DELETE/PATCH).
  **Off by default** — this tool sends live requests to the target, and mutating
  calls can have side effects. Only enable this against a disposable/staging
  environment.
- `--insecure` — skip TLS certificate verification, for self-signed staging setups.

Exit code is `2` if any `high` or `critical` findings were reported, so it can
gate CI.

## Library usage

```ts
import { loadSpec, extractOperations, scan, toConsole } from "@vensas-gmbh/oas-breach-audit";

const doc = await loadSpec("./openapi.yaml");
const report = await scan({
  baseUrl: "https://staging.example.com",
  operations: extractOperations(doc).filter((op) => op.method === "get"),
});
console.log(toConsole(report));
```

## Limitations (by design)

- This is a **precondition scanner and oracle-existence prover**, not a full
  secret-extraction tool. It deliberately stops short of brute-forcing real
  secret values byte-by-byte — that's a separate, much slower endeavor covered
  by tools like [rupture](https://github.com/decrypto-org/rupture) once you
  know an endpoint is worth attacking.
  - No redirect following.
  - Path/query parameters not under test are filled with a generic placeholder
    (or the spec's example value), which may not satisfy every API's validation
    rules — some operations may report fewer findings than expected if the
    server rejects the placeholder request outright.
  - Only one sample per oracle data point; noisy servers (e.g. those that
    inject per-request random padding) may need a higher/lower correlation
    threshold than the built-in one.

## Responsible use

Only run this against systems you own or are explicitly authorized to test.
`--unsafe-methods` sends live non-idempotent requests — never point it at
production without understanding the side effects of every mutating operation
in the spec.

## License

MIT — see [LICENSE](./LICENSE).
