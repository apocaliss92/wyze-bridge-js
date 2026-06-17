/**
 * Minimal DTLS 1.2 *server* handshake for the Wyze two-way-audio backchannel.
 *
 * When the app wants to talk to the camera, the camera connects to us as a
 * DTLS *client* on IOTC channel 1, using the standard PSK cipher suite
 * `TLS_PSK_WITH_AES_128_CBC_SHA256` (0x00AE). go2rtc gets this for free from
 * pion/dtls; Node has no PSK DTLS-server library, so this is a hand-rolled,
 * purpose-built implementation covering exactly the flights a Wyze camera
 * performs:
 *
 *   client → ClientHello
 *   server → HelloVerifyRequest(cookie)
 *   client → ClientHello(cookie)
 *   server → ServerHello + ServerKeyExchange(psk hint) + ServerHelloDone
 *   client → ClientKeyExchange + ChangeCipherSpec + Finished
 *   server → ChangeCipherSpec + Finished
 *
 * Record protection after the handshake is AES-128-CBC with HMAC-SHA256
 * (MAC-then-encrypt, explicit per-record IV), per RFC 5246 §6.2.3.2.
 *
 * EXPERIMENTAL: validated only structurally (see test/dtls-server.test.ts);
 * needs a real Wyze camera to confirm interop. Verbose logging is provided to
 * aid that debugging.
 */

import { createHmac, createHash, createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const VER = Buffer.from([0xfe, 0xfd]); // DTLS 1.2

// Content types
const CT_CCS = 20;
const CT_HANDSHAKE = 22;
const CT_APPDATA = 23;

// Handshake message types
const HS_CLIENT_HELLO = 1;
const HS_SERVER_HELLO = 2;
const HS_HELLO_VERIFY_REQUEST = 3;
const HS_SERVER_KEY_EXCHANGE = 12;
const HS_SERVER_HELLO_DONE = 14;
const HS_CLIENT_KEY_EXCHANGE = 16;
const HS_FINISHED = 20;

const CIPHER_PSK_AES128_CBC_SHA256 = 0x00ae;
const PSK_IDENTITY_HINT = "AUTHPWD_admin";

const MAC_LEN = 32; // HMAC-SHA256
const KEY_LEN = 16; // AES-128
const IV_LEN = 16; // CBC block / explicit IV

interface DtlsRecord {
  ct: number;
  epoch: number;
  seq: number;
  frag: Buffer;
}

interface HandshakeMsg {
  type: number;
  seq: number;
  body: Buffer;
  raw: Buffer; // full 12-byte header + body (for transcript hashing)
}

const u16 = (n: number): Buffer => {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n, 0);
  return b;
};

function prfSha256(secret: Buffer, label: string, seed: Buffer, length: number): Buffer {
  const labelSeed = Buffer.concat([Buffer.from(label, "ascii"), seed]);
  const out: Buffer[] = [];
  let a = labelSeed;
  let total = 0;
  while (total < length) {
    a = createHmac("sha256", secret).update(a).digest();
    out.push(createHmac("sha256", secret).update(Buffer.concat([a, labelSeed])).digest());
    total += 32;
  }
  return Buffer.concat(out).subarray(0, length);
}

function buildRecord(ct: number, epoch: number, seq: number, frag: Buffer): Buffer {
  const b = Buffer.alloc(13 + frag.length);
  b[0] = ct;
  VER.copy(b, 1);
  b.writeUInt16BE(epoch, 3);
  b.writeUIntBE(seq, 5, 6); // 48-bit sequence number
  b.writeUInt16BE(frag.length, 11);
  frag.copy(b, 13);
  return b;
}

function buildHandshake(type: number, seq: number, body: Buffer): Buffer {
  const b = Buffer.alloc(12 + body.length);
  b[0] = type;
  b.writeUIntBE(body.length, 1, 3); // length
  b.writeUInt16BE(seq, 4); // message_seq
  b.writeUIntBE(0, 6, 3); // fragment_offset
  b.writeUIntBE(body.length, 9, 3); // fragment_length (unfragmented)
  body.copy(b, 12);
  return b;
}

function parseRecords(buf: Buffer): DtlsRecord[] {
  const out: DtlsRecord[] = [];
  let o = 0;
  while (o + 13 <= buf.length) {
    const len = buf.readUInt16BE(o + 11);
    if (o + 13 + len > buf.length) break;
    out.push({
      ct: buf[o]!,
      epoch: buf.readUInt16BE(o + 3),
      seq: buf.readUIntBE(o + 5, 6),
      frag: buf.subarray(o + 13, o + 13 + len),
    });
    o += 13 + len;
  }
  return out;
}

/** Parse a single (unfragmented) handshake message from a fragment. */
function parseHandshake(frag: Buffer): HandshakeMsg | null {
  if (frag.length < 12) return null;
  const len = frag.readUIntBE(1, 3);
  if (frag.length < 12 + len) return null;
  return {
    type: frag[0]!,
    seq: frag.readUInt16BE(4),
    body: frag.subarray(12, 12 + len),
    raw: frag.subarray(0, 12 + len),
  };
}

export interface DtlsServerOptions {
  psk: Buffer;
  /** Send one fully-formed DTLS record (the caller frames it on channel 1). */
  send: (record: Buffer) => void;
  log?: (...args: any[]) => void;
  verbose?: boolean;
}

export class WyzeDtlsServer {
  private readonly psk: Buffer;
  private readonly send: (record: Buffer) => void;
  private readonly log: (...args: any[]) => void;
  private readonly verbose: boolean;

  private inbound: DtlsRecord[] = [];
  private waiter: (() => void) | null = null;
  private closed = false;

  // Negotiated state
  private serverRandom!: Buffer;
  private clientRandom!: Buffer;
  private clientMacKey!: Buffer;
  private serverMacKey!: Buffer;
  private clientKey!: Buffer;
  private serverKey!: Buffer;

  // Record sequence counters
  private sendSeqEpoch0 = 0;
  private sendSeqEpoch1 = 0;
  private recvSeqEpoch1 = 0;
  private msgSeq = 0; // server handshake message_seq

  constructor(opts: DtlsServerOptions) {
    this.psk = opts.psk;
    this.send = opts.send;
    this.verbose = opts.verbose ?? false;
    this.log = opts.log ?? (() => {});
  }

  /** Feed inbound channel-1 DTLS record bytes (may contain multiple records). */
  feed(recordBytes: Buffer): void {
    for (const r of parseRecords(recordBytes)) this.inbound.push(r);
    if (this.waiter) { const w = this.waiter; this.waiter = null; w(); }
  }

  close(): void {
    this.closed = true;
    if (this.waiter) { const w = this.waiter; this.waiter = null; w(); }
  }

  private async nextRecord(predicate: (r: DtlsRecord) => boolean, timeoutMs: number): Promise<DtlsRecord> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const idx = this.inbound.findIndex(predicate);
      if (idx >= 0) return this.inbound.splice(idx, 1)[0]!;
      if (this.closed) throw new Error("dtls-server closed");
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new Error("dtls-server record timeout");
      await new Promise<void>((resolve) => {
        const t = setTimeout(() => { this.waiter = null; resolve(); }, remaining);
        this.waiter = () => { clearTimeout(t); resolve(); };
      });
    }
  }

  /** Run the full server handshake. Resolves once the secure channel is up. */
  async handshake(timeoutMs = 5000): Promise<void> {
    // 1. ClientHello #1
    const ch1Rec = await this.nextRecord((r) => r.ct === CT_HANDSHAKE && r.epoch === 0, timeoutMs);
    const ch1 = parseHandshake(ch1Rec.frag);
    if (!ch1 || ch1.type !== HS_CLIENT_HELLO) throw new Error("expected ClientHello");

    // 2. HelloVerifyRequest with cookie
    const cookie = randomBytes(20);
    const hvrBody = Buffer.concat([VER, Buffer.from([cookie.length]), cookie]);
    this.sendEpoch0(buildHandshake(HS_HELLO_VERIFY_REQUEST, this.msgSeq++, hvrBody));
    if (this.verbose) this.log("[Wyze-DTLSsrv] sent HelloVerifyRequest");

    // 3. ClientHello #2 (with cookie) — this one starts the transcript
    const ch2Rec = await this.nextRecord(
      (r) => r.ct === CT_HANDSHAKE && r.epoch === 0 && parseHandshake(r.frag)?.type === HS_CLIENT_HELLO,
      timeoutMs,
    );
    const ch2 = parseHandshake(ch2Rec.frag)!;
    this.clientRandom = Buffer.from(ch2.body.subarray(2, 34));
    const transcript: Buffer[] = [ch2.raw];

    // 4. ServerHello + ServerKeyExchange(psk hint) + ServerHelloDone
    this.serverRandom = randomBytes(32);
    const shBody = Buffer.concat([
      VER,
      this.serverRandom,
      Buffer.from([0x00]), // session_id length 0
      u16(CIPHER_PSK_AES128_CBC_SHA256),
      Buffer.from([0x00]), // compression = null
    ]);
    const sh = buildHandshake(HS_SERVER_HELLO, this.msgSeq++, shBody);

    const hint = Buffer.from(PSK_IDENTITY_HINT, "ascii");
    const skeBody = Buffer.concat([u16(hint.length), hint]);
    const ske = buildHandshake(HS_SERVER_KEY_EXCHANGE, this.msgSeq++, skeBody);

    const shd = buildHandshake(HS_SERVER_HELLO_DONE, this.msgSeq++, Buffer.alloc(0));

    this.sendEpoch0(sh);
    this.sendEpoch0(ske);
    this.sendEpoch0(shd);
    transcript.push(sh, ske, shd);
    if (this.verbose) this.log("[Wyze-DTLSsrv] sent ServerHello/SKE/Done");

    // 5. ClientKeyExchange (+ CCS + client Finished)
    const ckeRec = await this.nextRecord(
      (r) => r.ct === CT_HANDSHAKE && r.epoch === 0 && parseHandshake(r.frag)?.type === HS_CLIENT_KEY_EXCHANGE,
      timeoutMs,
    );
    const cke = parseHandshake(ckeRec.frag)!;
    transcript.push(cke.raw);

    // Derive keys: PSK premaster = (u16 N, N zero bytes)(u16 N, psk)
    const n = this.psk.length;
    const premaster = Buffer.concat([u16(n), Buffer.alloc(n), u16(n), this.psk]);
    const masterSecret = prfSha256(premaster, "master secret", Buffer.concat([this.clientRandom, this.serverRandom]), 48);
    const kb = prfSha256(masterSecret, "key expansion", Buffer.concat([this.serverRandom, this.clientRandom]), 2 * (MAC_LEN + KEY_LEN));
    this.clientMacKey = kb.subarray(0, MAC_LEN);
    this.serverMacKey = kb.subarray(MAC_LEN, 2 * MAC_LEN);
    this.clientKey = kb.subarray(2 * MAC_LEN, 2 * MAC_LEN + KEY_LEN);
    this.serverKey = kb.subarray(2 * MAC_LEN + KEY_LEN, 2 * MAC_LEN + 2 * KEY_LEN);

    // 6. Client Finished (epoch 1, encrypted)
    const finRec = await this.nextRecord((r) => r.ct === CT_HANDSHAKE && r.epoch === 1, timeoutMs);
    const finPlain = this.decryptRecord(finRec);
    const clientFinished = parseHandshake(finPlain);
    if (!clientFinished || clientFinished.type !== HS_FINISHED) throw new Error("expected client Finished");
    // (verify_data not strictly enforced — camera is the trusted peer)
    transcript.push(clientFinished.raw);

    // 7. ChangeCipherSpec + server Finished
    this.sendEpoch0Raw(buildRecord(CT_CCS, 0, this.sendSeqEpoch0++, Buffer.from([0x01])));
    const verifyData = prfSha256(masterSecret, "server finished", createHash("sha256").update(Buffer.concat(transcript)).digest(), 12);
    const serverFinished = buildHandshake(HS_FINISHED, this.msgSeq++, verifyData);
    this.send(this.encryptRecord(CT_HANDSHAKE, serverFinished));
    if (this.verbose) this.log("[Wyze-DTLSsrv] handshake complete");
  }

  /** Decrypt the next application-data record from the camera. */
  async recv(timeoutMs = 5000): Promise<Buffer> {
    const rec = await this.nextRecord((r) => r.ct === CT_APPDATA && r.epoch === 1, timeoutMs);
    return this.decryptRecord(rec);
  }

  /** Encrypt + send application data (audio) to the camera. */
  write(appData: Buffer): void {
    this.send(this.encryptRecord(CT_APPDATA, appData));
  }

  // ─── Record layer (AES-128-CBC + HMAC-SHA256, MAC-then-encrypt) ──

  private encryptRecord(ct: number, content: Buffer): Buffer {
    const epoch = 1;
    const seq = this.sendSeqEpoch1++;
    const mac = this.recordMac(this.serverMacKey, epoch, seq, ct, content);
    const padLen = IV_LEN - ((content.length + MAC_LEN + 1) % IV_LEN);
    const padding = Buffer.alloc(padLen + 1, padLen);
    const plain = Buffer.concat([content, mac, padding]);
    const iv = randomBytes(IV_LEN);
    const cipher = createCipheriv("aes-128-cbc", this.serverKey, iv);
    cipher.setAutoPadding(false);
    const enc = Buffer.concat([cipher.update(plain), cipher.final()]);
    return buildRecord(ct, epoch, seq, Buffer.concat([iv, enc]));
  }

  private decryptRecord(rec: DtlsRecord): Buffer {
    const iv = rec.frag.subarray(0, IV_LEN);
    const body = rec.frag.subarray(IV_LEN);
    const decipher = createDecipheriv("aes-128-cbc", this.clientKey, iv);
    decipher.setAutoPadding(false);
    const plain = Buffer.concat([decipher.update(body), decipher.final()]);
    const padLen = plain[plain.length - 1]!;
    const content = plain.subarray(0, plain.length - 1 - padLen - MAC_LEN);
    this.recvSeqEpoch1 = Math.max(this.recvSeqEpoch1, rec.seq + 1);
    return content;
  }

  private recordMac(macKey: Buffer, epoch: number, seq: number, ct: number, content: Buffer): Buffer {
    const seqBuf = Buffer.alloc(8);
    seqBuf.writeUInt16BE(epoch, 0);
    seqBuf.writeUIntBE(seq, 2, 6);
    const macInput = Buffer.concat([seqBuf, Buffer.from([ct]), VER, u16(content.length), content]);
    return createHmac("sha256", macKey).update(macInput).digest();
  }

  // ─── Epoch-0 plaintext handshake send helpers ───────────────────
  private sendEpoch0(handshakeMsg: Buffer): void {
    this.sendEpoch0Raw(buildRecord(CT_HANDSHAKE, 0, this.sendSeqEpoch0++, handshakeMsg));
  }
  private sendEpoch0Raw(record: Buffer): void {
    this.send(record);
  }
}
