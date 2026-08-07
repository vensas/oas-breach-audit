import pc from "picocolors";
import type { OperationFinding, RiskLevel, ScanReport } from "../types.js";

const RISK_COLOR: Record<RiskLevel, (s: string) => string> = {
  critical: pc.bgRed,
  high: pc.red,
  medium: pc.yellow,
  low: pc.cyan,
  info: pc.gray,
};

const RISK_ORDER: RiskLevel[] = ["critical", "high", "medium", "low", "info"];

export function toJson(report: ScanReport): string {
  return JSON.stringify(report, null, 2);
}

export function toConsole(report: ScanReport): string {
  const lines: string[] = [];
  lines.push(pc.bold(`BREACH audit for ${report.baseUrl}`));
  lines.push(`generated ${report.generatedAt}`);
  lines.push("");

  const sorted = [...report.findings].sort((a, b) => RISK_ORDER.indexOf(a.risk) - RISK_ORDER.indexOf(b.risk));

  for (const finding of sorted) {
    lines.push(formatFinding(finding));
  }

  lines.push(pc.bold("Summary"));
  for (const level of RISK_ORDER) {
    const count = report.summary[level];
    if (count === 0) continue;
    lines.push(`  ${RISK_COLOR[level](level.toUpperCase())}: ${count}`);
  }

  return lines.join("\n");
}

function formatFinding(finding: OperationFinding): string {
  const badge = RISK_COLOR[finding.risk](` ${finding.risk.toUpperCase()} `);
  const header = `${badge} ${finding.operation.method.toUpperCase()} ${finding.operation.path}`;
  const lines = [header, `  url: ${finding.url}`];

  if (finding.error) {
    lines.push(`  error: ${finding.error}`);
    return lines.join("\n");
  }

  for (const reason of finding.reasons) lines.push(`  - ${reason}`);
  return lines.join("\n");
}
