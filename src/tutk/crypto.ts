/**
 * TUTK crypto — TransCode and XXTEA encryption/decryption.
 *
 * Ported from go2rtc/pkg/tutk/crypto.go.
 * Used for Wyze P2P authentication and data encryption.
 */

const CHARLIE = Buffer.from("Charlie is the designer of P2P!!");
const DELTA = 0x9e3779b9;

// ─── Bit rotation helpers ───────────────────────────────────────

/** Rotate left for 32-bit unsigned integer. */
function rotl32(x: number, n: number): number {
  n = ((n % 32) + 32) % 32;
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

/** Rotate right for 32-bit unsigned integer. */
function rotr32(x: number, n: number): number {
  return rotl32(x, 32 - n);
}

/** Read uint32 LE from buffer at offset. */
function readU32(buf: Buffer, off: number): number {
  return buf.readUInt32LE(off);
}

/** Write uint32 LE to buffer at offset. */
function writeU32(buf: Buffer, off: number, val: number): void {
  buf.writeUInt32LE(val >>> 0, off);
}

// ─── Swap tables ────────────────────────────────────────────────

function swap(dst: Buffer, dOff: number, src: Buffer, sOff: number, n: number): void {
  if (n === 16) {
    dst[dOff + 0] = src[sOff + 11]!;
    dst[dOff + 1] = src[sOff + 9]!;
    dst[dOff + 2] = src[sOff + 8]!;
    dst[dOff + 3] = src[sOff + 15]!;
    dst[dOff + 4] = src[sOff + 13]!;
    dst[dOff + 5] = src[sOff + 10]!;
    dst[dOff + 6] = src[sOff + 12]!;
    dst[dOff + 7] = src[sOff + 14]!;
    dst[dOff + 8] = src[sOff + 2]!;
    dst[dOff + 9] = src[sOff + 1]!;
    dst[dOff + 10] = src[sOff + 5]!;
    dst[dOff + 11] = src[sOff + 0]!;
    dst[dOff + 12] = src[sOff + 6]!;
    dst[dOff + 13] = src[sOff + 4]!;
    dst[dOff + 14] = src[sOff + 7]!;
    dst[dOff + 15] = src[sOff + 3]!;
  } else if (n === 8) {
    dst[dOff + 0] = src[sOff + 7]!;
    dst[dOff + 1] = src[sOff + 4]!;
    dst[dOff + 2] = src[sOff + 3]!;
    dst[dOff + 3] = src[sOff + 2]!;
    dst[dOff + 4] = src[sOff + 1]!;
    dst[dOff + 5] = src[sOff + 6]!;
    dst[dOff + 6] = src[sOff + 5]!;
    dst[dOff + 7] = src[sOff + 0]!;
  } else if (n === 4) {
    dst[dOff + 0] = src[sOff + 2]!;
    dst[dOff + 1] = src[sOff + 3]!;
    dst[dOff + 2] = src[sOff + 0]!;
    dst[dOff + 3] = src[sOff + 1]!;
  } else if (n === 2) {
    dst[dOff + 0] = src[sOff + 1]!;
    dst[dOff + 1] = src[sOff + 0]!;
  } else {
    src.copy(dst, dOff, sOff, sOff + n);
  }
}

// ─── TransCode ──────────────────────────────────────────────────

/** Decrypt (reverse transcode) a partial block. */
export function reverseTransCodePartial(src: Buffer): Buffer {
  const n = src.length;
  const tmp = Buffer.alloc(n);
  const dst = Buffer.alloc(n);

  let sOff = 0, tOff = 0, dOff = 0;
  let remaining = n;

  while (remaining >= 16) {
    for (let i = 0; i < 16; i += 4) {
      const x = readU32(src, sOff + i);
      writeU32(tmp, tOff + i, rotl32(x, i + 3));
    }
    swap(dst, dOff, tmp, tOff, 16);
    for (let i = 0; i < 16; i++) {
      tmp[tOff + i] = dst[dOff + i]! ^ CHARLIE[i]!;
    }
    for (let i = 0; i < 16; i += 4) {
      const x = readU32(tmp, tOff + i);
      writeU32(dst, dOff + i, rotl32(x, i + 1));
    }
    sOff += 16; tOff += 16; dOff += 16;
    remaining -= 16;
  }

  swap(tmp, tOff, src, sOff, remaining);
  for (let i = 0; i < remaining; i++) {
    dst[dOff + i] = tmp[tOff + i]! ^ CHARLIE[i]!;
  }

  return dst;
}

/** Decrypt a full blob (header + body, with partial/full mode). */
export function reverseTransCodeBlob(src: Buffer): Buffer {
  if (src.length < 16) return reverseTransCodePartial(src);

  const dst = Buffer.alloc(src.length);
  const header = reverseTransCodePartial(src.subarray(0, 16));
  header.copy(dst, 0);

  if (src.length > 16) {
    if (header[3]! & 1) {
      // Partial encryption
      const remaining = src.length - 16;
      const decryptLen = Math.min(remaining, 48);
      if (decryptLen > 0) {
        const decrypted = reverseTransCodePartial(src.subarray(16, 16 + decryptLen));
        decrypted.copy(dst, 16);
      }
      if (remaining > 48) {
        src.copy(dst, 64, 64);
      }
    } else {
      // Full decryption
      const decrypted = reverseTransCodePartial(src.subarray(16));
      decrypted.copy(dst, 16);
    }
  }

  return dst;
}

/** Encrypt (transcode) a partial block. */
export function transCodePartial(src: Buffer): Buffer {
  const n = src.length;
  const tmp = Buffer.alloc(n);
  const dst = Buffer.alloc(n);

  let sOff = 0, tOff = 0, dOff = 0;
  let remaining = n;

  while (remaining >= 16) {
    for (let i = 0; i < 16; i += 4) {
      const x = readU32(src, sOff + i);
      writeU32(tmp, tOff + i, rotr32(x, i + 1));
    }
    for (let i = 0; i < 16; i++) {
      dst[dOff + i] = tmp[tOff + i]! ^ CHARLIE[i]!;
    }
    swap(tmp, tOff, dst, dOff, 16);
    for (let i = 0; i < 16; i += 4) {
      const x = readU32(tmp, tOff + i);
      writeU32(dst, dOff + i, rotr32(x, i + 3));
    }
    sOff += 16; tOff += 16; dOff += 16;
    remaining -= 16;
  }

  for (let i = 0; i < remaining; i++) {
    tmp[tOff + i] = src[sOff + i]! ^ CHARLIE[i]!;
  }
  swap(dst, dOff, tmp, tOff, remaining);

  return dst;
}

/** Encrypt a full blob. */
export function transCodeBlob(src: Buffer): Buffer {
  if (src.length < 16) return transCodePartial(src);

  const dst = Buffer.alloc(src.length);
  const header = transCodePartial(src.subarray(0, 16));
  header.copy(dst, 0);

  if (src.length > 16) {
    if (src[3]! & 1) {
      const remaining = src.length - 16;
      const encryptLen = Math.min(remaining, 48);
      if (encryptLen > 0) {
        const encrypted = transCodePartial(src.subarray(16, 16 + encryptLen));
        encrypted.copy(dst, 16);
      }
      if (remaining > 48) {
        src.copy(dst, 64, 64);
      }
    } else {
      const encrypted = transCodePartial(src.subarray(16));
      encrypted.copy(dst, 16);
    }
  }

  return dst;
}

// ─── XXTEA ──────────────────────────────────────────────────────

function xxteaMX(sum: number, y: number, z: number, p: number, e: number, k: number[]): number {
  return (
    (((z >>> 5) ^ (y << 2)) + ((y >>> 3) ^ (z << 4))) ^
    ((sum ^ y) + ((k[(p & 3) ^ e]!) ^ z))
  ) >>> 0;
}

/** XXTEA decrypt (fixed 16-byte blocks). */
export function xxteaDecrypt(src: Buffer, key: Buffer): Buffer {
  const n = 4;
  const w = new Array<number>(n);
  const k = new Array<number>(n);

  for (let i = 0; i < n; i++) {
    w[i] = readU32(src, i * 4);
    k[i] = readU32(key, i * 4);
  }

  let rounds = Math.floor(52 / n) + 6;
  let sum = (rounds * DELTA) >>> 0;

  while (rounds > 0) {
    const w0save = w[0]!;
    const i2 = (sum >>> 2) & 3;
    for (let i = n - 1; i >= 0; i--) {
      const wi = w[((i - 1) + n) % n]!;
      const ki = k[i ^ i2]!;
      const t1 = ((w0save ^ sum) + (wi ^ ki)) >>> 0;
      const t2 = ((wi >>> 5) ^ (w0save << 2)) >>> 0;
      const t3 = ((w0save >>> 3) ^ (wi << 4)) >>> 0;
      w[i] = (w[i]! - (t1 ^ (t2 + t3))) >>> 0;
    }
    sum = (sum - DELTA) >>> 0;
    rounds--;
  }

  const dst = Buffer.alloc(16);
  for (let i = 0; i < n; i++) {
    writeU32(dst, i * 4, w[i]!);
  }
  return dst;
}

/** XXTEA decrypt variable-length data. */
export function xxteaDecryptVar(data: Buffer, key: Buffer): Buffer {
  if (data.length < 8 || key.length < 16) return Buffer.alloc(0);

  const k = new Array<number>(4);
  for (let i = 0; i < 4; i++) {
    k[i] = readU32(key, i * 4);
  }

  const n = Math.max(Math.floor(data.length / 4), 2);
  const v = new Array<number>(n);
  for (let i = 0; i < Math.floor(data.length / 4); i++) {
    v[i] = readU32(data, i * 4);
  }
  // Fill remaining with 0 if data is short
  for (let i = Math.floor(data.length / 4); i < n; i++) {
    v[i] = 0;
  }

  let rounds = 6 + Math.floor(52 / n);
  let sum = (rounds * DELTA) >>> 0;
  let y = v[0]!;

  while (rounds > 0) {
    const e = (sum >>> 2) & 3;
    for (let p = n - 1; p > 0; p--) {
      const z = v[p - 1]!;
      v[p] = (v[p]! - xxteaMX(sum, y, z, p, e, k)) >>> 0;
      y = v[p]!;
    }
    const z = v[n - 1]!;
    v[0] = (v[0]! - xxteaMX(sum, y, z, 0, e, k)) >>> 0;
    y = v[0]!;
    sum = (sum - DELTA) >>> 0;
    rounds--;
  }

  const result = Buffer.alloc(n * 4);
  for (let i = 0; i < n; i++) {
    writeU32(result, i * 4, v[i]!);
  }

  return result.subarray(0, data.length);
}
