/**
 * DTLS authentication helpers.
 * Ported from go2rtc/pkg/tutk/dtls/auth.go
 */

import { createHash } from "node:crypto";

/** Calculate auth key from ENR + MAC. */
export function calculateAuthKey(enr: string, mac: string): Buffer {
  const data = enr + mac.toUpperCase();
  const hash = createHash("sha256").update(data).digest();
  let b64 = hash.subarray(0, 6).toString("base64");
  b64 = b64.replace(/\+/g, "Z").replace(/\//g, "9").replace(/=/g, "A");
  return Buffer.from(b64, "ascii");
}

/**
 * Derive DTLS PSK from ENR.
 * TUTK treats PSK as a NULL-terminated C string — truncated at first 0x00.
 */
export function derivePSK(enr: string): Buffer {
  const hash = createHash("sha256").update(enr).digest();
  let pskLen = 32;
  for (let i = 0; i < 32; i++) {
    if (hash[i] === 0x00) { pskLen = i; break; }
  }
  const psk = Buffer.alloc(32);
  hash.copy(psk, 0, 0, pskLen);
  return psk;
}
