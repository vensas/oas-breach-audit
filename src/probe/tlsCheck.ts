import type { TlsCheck } from "../types.js";
import type { ProbeResponse } from "./httpClient.js";

/**
 * BREACH is a TLS-observation attack: it needs an active network attacker
 * capable of measuring encrypted response sizes and injecting content into
 * requests the victim's browser sends (e.g. via CSRF), which is the standard
 * threat model for a service served over HTTPS.
 */
export function checkTls(response: ProbeResponse): TlsCheck {
  return response.tls;
}
