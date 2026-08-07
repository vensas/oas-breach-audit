export type HttpMethod = "get" | "put" | "post" | "delete" | "options" | "head" | "patch" | "trace";

export type ParamLocation = "query" | "header" | "path";

export interface TestableParam {
  name: string;
  location: ParamLocation;
  /** Example value taken from the spec, if any, used to seed a valid-looking request. */
  example?: string;
}

export interface Operation {
  operationId: string;
  method: HttpMethod;
  /** Path template as declared in the spec, e.g. /users/{id} */
  path: string;
  params: TestableParam[];
  /** Response content-types declared for 2xx responses. */
  responseContentTypes: string[];
}

export interface ScanTarget {
  baseUrl: string;
  operations: Operation[];
}

export interface CompressionCheck {
  supported: boolean;
  contentEncoding: string | null;
}

export interface TlsCheck {
  isHttps: boolean;
  protocol: string | null;
  tlsVersion: string | null;
}

export interface ReflectionResult {
  param: TestableParam;
  reflected: boolean;
}

export interface SecretMatch {
  kind: string;
  location: "header" | "body";
  sample: string;
  /** True when the same request repeated twice yields a different value (e.g. per-request CSRF token). */
  varies: boolean;
}

export interface OracleProofResult {
  attempted: boolean;
  landmarkFound: boolean;
  correlationObserved: boolean;
  detail: string;
}

export type RiskLevel = "info" | "low" | "medium" | "high" | "critical";

export interface OperationFinding {
  operation: Operation;
  url: string;
  tls: TlsCheck;
  compression: CompressionCheck;
  reflections: ReflectionResult[];
  secrets: SecretMatch[];
  oracle: OracleProofResult;
  risk: RiskLevel;
  reasons: string[];
  error?: string;
}

export interface ScanReport {
  baseUrl: string;
  generatedAt: string;
  findings: OperationFinding[];
  summary: Record<RiskLevel, number>;
}
