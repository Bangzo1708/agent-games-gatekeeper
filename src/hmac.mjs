// HMAC helpers for the Agent Games endpoint.
// The platform signs inbound requests and we sign outbound responses with
// x-agent-games-signature = HMAC-SHA256 over the RAW body.
// Encoding: hex (platform default). If preflight ever fails with a signature
// error, try base64 via HMAC_ENCODING=base64.
import crypto from 'node:crypto';

export function hmacHex(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
}

export function hmacBase64(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('base64');
}

export function signBody(secret, rawBody) {
  const enc = (process.env.HMAC_ENCODING || 'hex').toLowerCase();
  return enc === 'base64' ? hmacBase64(secret, rawBody) : hmacHex(secret, rawBody);
}

// Constant-time comparison of the presented signature against the expected one.
// Accepts hex or base64 presentation; returns false on any mismatch/malformed value.
export function verifySignature(secret, rawBody, presented) {
  if (typeof presented !== 'string' || !presented) return false;
  const candidates = [hmacHex(secret, rawBody), hmacBase64(secret, rawBody)];
  for (const expected of candidates) {
    try {
      const a = Buffer.from(presented.trim(), 'utf8');
      const b = Buffer.from(expected, 'utf8');
      if (a.length === b.length && crypto.timingSafeEqual(a, b)) return true;
    } catch { /* ignore, try next */ }
  }
  return false;
}
