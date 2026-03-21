/**
 * TUTK protocol helpers — ICAM/HL message builders and parsers.
 * Ported from go2rtc/pkg/tutk/helpers.go
 */

/** Generate session ID (8 bytes from nanosecond timestamp). */
export function genSessionId(): Buffer {
  const b = Buffer.alloc(8);
  const now = BigInt(Date.now()) * 1_000_000n; // ms → ns
  b.writeBigUInt64LE(now);
  return b;
}

/** Build an ICAM command packet. */
export function icam(cmd: number, ...args: number[]): Buffer {
  const n = args.length;
  const b = Buffer.alloc(23 + n);
  b.write("ICAM", 0, 4, "ascii");
  b.writeUInt32LE(cmd, 4);
  b[15] = n;
  for (let i = 0; i < n; i++) b[23 + i] = args[i]!;
  return b;
}

/**
 * Build an HL (Wyze auth protocol) command packet.
 *
 * Layout:
 *   0-1   "HL"       magic
 *   2     version    (5)
 *   4-5   cmdID      (uint16 LE)
 *   6-7   payloadLen (uint16 LE)
 *   16+   payload
 */
export function hl(cmdId: number, payload: Buffer): Buffer {
  const b = Buffer.alloc(16 + payload.length);
  b.write("HL", 0, 2, "ascii");
  b[2] = 5; // version
  b.writeUInt16LE(cmdId, 4);
  b.writeUInt16LE(payload.length, 6);
  payload.copy(b, 16);
  return b;
}

/**
 * Parse an HL packet.
 * @returns [cmdId, payload, ok]
 */
export function parseHL(data: Buffer): [cmdId: number, payload: Buffer, ok: boolean] {
  if (data.length < 16 || data[0] !== 0x48 || data[1] !== 0x4c) {
    return [0, Buffer.alloc(0), false];
  }
  const cmdId = data.readUInt16LE(4);
  const payloadLen = data.readUInt16LE(6);
  const end = Math.min(16 + payloadLen, data.length);
  return [cmdId, data.subarray(16, end), true];
}

/** Find HL magic bytes starting from offset. */
export function findHL(data: Buffer, offset: number): Buffer | null {
  for (let i = offset; i + 16 <= data.length; i++) {
    if (data[i] === 0x48 && data[i + 1] === 0x4c) {
      return data.subarray(i);
    }
  }
  return null;
}
