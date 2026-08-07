import type { SecretMatch } from "../types.js";

export type RawSecretMatch = Omit<SecretMatch, "varies">;

interface BodyPattern {
  kind: string;
  regex: RegExp;
}

const JWT_PATTERN: BodyPattern = {
  kind: "jwt",
  regex: /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g,
};

const JSON_TOKEN_PATTERN: BodyPattern = {
  kind: "token-field",
  regex: /"[a-z_]*(?:csrf|xsrf|token|session|secret|api[_-]?key)[a-z_]*"\s*:\s*"([A-Za-z0-9+/_=-]{8,})"/gi,
};

const HTML_TOKEN_PATTERN: BodyPattern = {
  kind: "token-field",
  regex: /name=["'][^"']*(?:csrf|xsrf|token)[^"']*["'][^>]*value=["']([A-Za-z0-9+/_=-]{8,})["']/gi,
};

const SESSION_COOKIE_NAMES = /^(?:sessionid|sid|phpsessid|jsessionid|connect\.sid|asp\.net_sessionid|_session)$/i;

/**
 * Scans a single response for values that would be worth stealing via a
 * BREACH-style oracle: session cookies, anti-CSRF tokens, JWTs, and generic
 * "token"/"secret"-ish JSON fields. This does not attempt to recover the
 * value byte-by-byte — it only flags that a target of that kind exists.
 */
export function detectSecrets(body: string, headers: Record<string, string | string[] | undefined>): RawSecretMatch[] {
  const matches: RawSecretMatch[] = [];

  for (const pattern of [JWT_PATTERN, JSON_TOKEN_PATTERN, HTML_TOKEN_PATTERN]) {
    for (const match of body.matchAll(pattern.regex)) {
      matches.push({ kind: pattern.kind, location: "body", sample: (match[1] ?? match[0]).slice(0, 12) });
    }
  }

  const setCookie = headers["set-cookie"];
  const cookies = Array.isArray(setCookie) ? setCookie : setCookie ? [setCookie] : [];
  for (const cookie of cookies) {
    const [pair] = cookie.split(";");
    const [name, value] = (pair ?? "").split("=");
    if (name && SESSION_COOKIE_NAMES.test(name.trim())) {
      matches.push({ kind: "session-cookie", location: "header", sample: (value ?? "").slice(0, 12) });
    }
  }

  return matches;
}

/**
 * Combines two independent samples of the same request into final findings,
 * flagging a secret as "varies" when its value differs between the two
 * samples — a strong signal it is a live, per-request/session token rather
 * than static page content (and therefore worth an attacker's effort).
 */
export function mergeSecretSamples(first: RawSecretMatch[], second: RawSecretMatch[]): SecretMatch[] {
  const bySecond = new Map<string, RawSecretMatch[]>();
  for (const s of second) {
    const key = `${s.kind}:${s.location}`;
    bySecond.set(key, [...(bySecond.get(key) ?? []), s]);
  }

  return first.map((match) => {
    const key = `${match.kind}:${match.location}`;
    const candidates = bySecond.get(key) ?? [];
    const identicalFound = candidates.some((c) => c.sample === match.sample);
    return { ...match, varies: candidates.length > 0 && !identicalFound };
  });
}
