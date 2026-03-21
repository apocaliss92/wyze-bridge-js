/**
 * ChaCha20-Poly1305 cipher for TUTK DTLS.
 * Ported from go2rtc/pkg/tutk/dtls/cipher.go
 *
 * This implements the encryption/decryption primitives used by
 * the TUTK DTLS transport. The cipher suite is TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256
 * (custom ID 0xCCAC).
 *
 * Node.js crypto module supports chacha20-poly1305 natively.
 */

import { createCipheriv, createDecipheriv } from "node:crypto";

const TAG_LENGTH = 16;
const NONCE_LENGTH = 12;

export class ChaCha20Poly1305Cipher {
  private localKey: Buffer;
  private localIV: Buffer;
  private remoteKey: Buffer;
  private remoteIV: Buffer;

  constructor(localKey: Buffer, localIV: Buffer, remoteKey: Buffer, remoteIV: Buffer) {
    this.localKey = localKey;
    this.localIV = localIV;
    this.remoteKey = remoteKey;
    this.remoteIV = remoteIV;
  }

  /**
   * Encrypt a DTLS record payload.
   *
   * @param nonce - 12-byte nonce (computed from IV XOR sequence number)
   * @param plaintext - Data to encrypt
   * @param aad - Additional authenticated data (DTLS record header info)
   * @returns Ciphertext + 16-byte auth tag
   */
  encrypt(nonce: Buffer, plaintext: Buffer, aad: Buffer): Buffer {
    const xoredNonce = this.xorNonce(this.localIV, nonce);
    const cipher = createCipheriv("chacha20-poly1305", this.localKey, xoredNonce, {
      authTagLength: TAG_LENGTH,
    } as any);
    (cipher as any).setAAD(aad);
    const encrypted = Buffer.concat([cipher.update(plaintext), (cipher as any).final()]);
    const tag = (cipher as any).getAuthTag() as Buffer;
    return Buffer.concat([encrypted, tag]);
  }

  /**
   * Decrypt a DTLS record payload.
   *
   * @param nonce - 12-byte nonce
   * @param ciphertext - Data to decrypt (includes 16-byte auth tag at end)
   * @param aad - Additional authenticated data
   * @returns Decrypted plaintext
   * @throws If authentication fails
   */
  decrypt(nonce: Buffer, ciphertext: Buffer, aad: Buffer): Buffer {
    if (ciphertext.length < TAG_LENGTH) {
      throw new Error("Ciphertext too short");
    }

    const xoredNonce = this.xorNonce(this.remoteIV, nonce);
    const data = ciphertext.subarray(0, ciphertext.length - TAG_LENGTH);
    const tag = ciphertext.subarray(ciphertext.length - TAG_LENGTH);

    const decipher = createDecipheriv("chacha20-poly1305", this.remoteKey, xoredNonce, {
      authTagLength: TAG_LENGTH,
    } as any);
    (decipher as any).setAAD(aad);
    (decipher as any).setAuthTag(tag);
    return Buffer.concat([decipher.update(data), (decipher as any).final()]);
  }

  /** XOR a nonce with an IV. */
  private xorNonce(iv: Buffer, nonce: Buffer): Buffer {
    const result = Buffer.alloc(NONCE_LENGTH);
    for (let i = 0; i < NONCE_LENGTH; i++) {
      result[i] = (iv[i] ?? 0) ^ (nonce[i] ?? 0);
    }
    return result;
  }
}

/**
 * Compute a DTLS AEAD nonce from epoch and sequence number.
 */
export function computeNonce(epoch: number, sequenceNumber: bigint): Buffer {
  const nonce = Buffer.alloc(NONCE_LENGTH);
  // Write sequence number at offset 4 (big-endian)
  nonce.writeBigUInt64BE(sequenceNumber, 4);
  // Write epoch at offset 4 (big-endian, overwrites first 2 bytes of sequence)
  nonce.writeUInt16BE(epoch, 4);
  return nonce;
}

/**
 * Generate DTLS AEAD additional authenticated data.
 */
export function generateAAD(
  epoch: number,
  sequenceNumber: bigint,
  contentType: number,
  versionMajor: number,
  versionMinor: number,
  payloadLength: number,
): Buffer {
  const aad = Buffer.alloc(13);
  aad.writeBigUInt64BE(sequenceNumber, 0);
  aad.writeUInt16BE(epoch, 0);
  aad[8] = contentType;
  aad[9] = versionMajor;
  aad[10] = versionMinor;
  aad.writeUInt16BE(payloadLength, 11);
  return aad;
}
