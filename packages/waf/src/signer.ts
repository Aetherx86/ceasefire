import { createHmac, timingSafeEqual } from "node:crypto";

export interface SignedEnvelope<T> {
  envelopeId: string;
  timestampIso: string;
  payload: T;
}

/**
 * Signs an outbound JSON payload using HMAC-SHA256.
 */
export function signEnvelope(payload: string, secret: string, timestampMs = Date.now()): { signatureHeader: string; timestampMs: number } {
  const hmac = createHmac("sha256", secret);
  hmac.update(`${timestampMs}.${payload}`);
  const digest = hmac.digest("hex");
  return {
    signatureHeader: `t=${timestampMs},v1=${digest}`,
    timestampMs,
  };
}

/**
 * Verifies an inbound signature header in constant time with replay window tolerance.
 */
export function verifySignature(
  payload: string,
  signatureHeader: string,
  secret: string,
  toleranceSec = 300,
  nowMs = Date.now()
): { valid: boolean; reason?: string } {
  const parts = signatureHeader.split(",");
  let tPart: string | undefined;
  let v1Part: string | undefined;

  for (const part of parts) {
    const [k, v] = part.trim().split("=");
    if (k === "t") tPart = v;
    if (k === "v1") v1Part = v;
  }

  if (!tPart || !v1Part) {
    return { valid: false, reason: "Malformed signature header format" };
  }

  const timestampMs = parseInt(tPart, 10);
  if (!Number.isFinite(timestampMs)) {
    return { valid: false, reason: "Invalid timestamp in signature header" };
  }

  if (Math.abs(nowMs - timestampMs) > toleranceSec * 1000) {
    return { valid: false, reason: "Signature timestamp outside replay tolerance window" };
  }

  const expectedHmac = createHmac("sha256", secret).update(`${timestampMs}.${payload}`).digest("hex");

  const expectedBuffer = Buffer.from(expectedHmac, "hex");
  const providedBuffer = Buffer.from(v1Part, "hex");

  if (expectedBuffer.length !== providedBuffer.length) {
    return { valid: false, reason: "Digest length mismatch" };
  }

  const matches = timingSafeEqual(expectedBuffer, providedBuffer);
  return {
    valid: matches,
    reason: matches ? undefined : "HMAC cryptographic signature mismatch",
  };
}
