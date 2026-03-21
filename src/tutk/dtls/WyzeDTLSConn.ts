/**
 * WyzeDTLSConn — Full DTLS P2P connection to Wyze cameras.
 * Handles: IOTC discovery → DTLS handshake → encrypted channel.
 */

import * as dgram from "node:dgram";
import { createHmac, createHash, randomBytes, createCipheriv, createDecipheriv, generateKeyPairSync, diffieHellman, createPublicKey } from "node:crypto";
import { EventEmitter } from "node:events";
import { transCodeBlob, reverseTransCodeBlob, xxteaDecryptVar } from "../crypto.js";
import { genSessionId, parseHL, findHL } from "../helpers.js";
import { calculateAuthKey, derivePSK } from "./auth.js";
import { FrameHandler, type Packet, ChannelAudio, ChannelIVideo, ChannelPVideo } from "../frame.js";
import { isVideoCodec, isAudioCodec } from "../codec.js";

// ─── Types ──────────────────────────────────────────────────────

export interface WyzeDTLSConnOptions {
  host: string;
  port?: number;
  uid: string;
  enr: string;
  mac: string;
  model: string;
  verbose?: boolean;
}

interface DtlsRecord { contentType: number; epoch: number; seqNum: number; fragment: Buffer; totalLen: number; }
interface HandshakeMsg { type: number; msgSeq: number; body: Buffer; raw: Buffer; }

// ─── Helpers ────────────────────────────────────────────────────

function tlsPRF(secret: Buffer, label: string, seed: Buffer, length: number): Buffer {
  const fullSeed = Buffer.concat([Buffer.from(label, "ascii"), seed]);
  const result: Buffer[] = []; let a = fullSeed; let total = 0;
  while (total < length) { a = createHmac("sha256", secret).update(a).digest(); result.push(createHmac("sha256", secret).update(Buffer.concat([a, fullSeed])).digest()); total += 32; }
  return Buffer.concat(result).subarray(0, length);
}

function parseDtlsRecord(data: Buffer): DtlsRecord | null {
  if (data.length < 13) return null;
  const ct = data[0]!, ep = data.readUInt16BE(3), sh = data.readUInt16BE(5), sl = data.readUInt32BE(7), fl = data.readUInt16BE(11);
  if (data.length < 13 + fl) return null;
  return { contentType: ct, epoch: ep, seqNum: sh * 0x100000000 + sl, fragment: data.subarray(13, 13 + fl), totalLen: 13 + fl };
}

function* parseAllRecords(data: Buffer): Generator<DtlsRecord> {
  let o = 0; while (o < data.length) { const r = parseDtlsRecord(data.subarray(o)); if (!r) break; yield r; o += r.totalLen; }
}

function* parseHandshakeMsgs(frag: Buffer): Generator<HandshakeMsg> {
  let o = 0; while (o + 12 <= frag.length) {
    const t = frag[o]!, fl = (frag[o+9]! << 16) | (frag[o+10]! << 8) | frag[o+11]!;
    const ms = frag.readUInt16BE(o + 4);
    if (o + 12 + fl > frag.length) break;
    yield { type: t, msgSeq: ms, body: frag.subarray(o + 12, o + 12 + fl), raw: frag.subarray(o, o + 12 + fl) };
    o += 12 + fl;
  }
}

function buildDtlsRecord(ct: number, ep: number, seq: number, frag: Buffer): Buffer {
  const b = Buffer.alloc(13 + frag.length); b[0] = ct; b[1] = 0xfe; b[2] = 0xfd;
  b.writeUInt16BE(ep, 3); b.writeUInt16BE(0, 5); b.writeUInt32BE(seq, 7); b.writeUInt16BE(frag.length, 11); frag.copy(b, 13); return b;
}

function buildHandshake(type: number, msgSeq: number, body: Buffer): Buffer {
  const h = Buffer.alloc(12 + body.length); h[0] = type;
  h[1] = (body.length >> 16) & 0xff; h[2] = (body.length >> 8) & 0xff; h[3] = body.length & 0xff;
  h.writeUInt16BE(msgSeq, 4); h[9] = h[1]!; h[10] = h[2]!; h[11] = h[3]!; body.copy(h, 12); return h;
}

function computeNonce(iv: Buffer, epoch: number, seq: number): Buffer {
  const n = Buffer.alloc(12); n.writeUInt32BE(seq, 8); n.writeUInt16BE(epoch, 4);
  for (let i = 0; i < 12; i++) n[i] = (n[i]! ^ iv[i]!) & 0xff; return n;
}

function computeAAD(epoch: number, seq: number, ct: number, payloadLen: number): Buffer {
  const a = Buffer.alloc(13); a.writeUInt16BE(epoch, 0); a.writeUInt32BE(seq, 4);
  a[8] = ct; a[9] = 0xfe; a[10] = 0xfd; a.writeUInt16BE(payloadLen, 11); return a;
}

function chacha20Encrypt(key: Buffer, iv: Buffer, epoch: number, seq: number, ct: number, pt: Buffer): Buffer {
  const nonce = computeNonce(iv, epoch, seq), aad = computeAAD(epoch, seq, ct, pt.length);
  const c = createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 } as any);
  (c as any).setAAD(aad); const enc = Buffer.concat([c.update(pt), c.final()]); return Buffer.concat([enc, (c as any).getAuthTag()]);
}

function chacha20Decrypt(key: Buffer, iv: Buffer, epoch: number, seq: number, ct: number, ciphertext: Buffer): Buffer {
  const nonce = computeNonce(iv, epoch, seq);
  const data = ciphertext.subarray(0, ciphertext.length - 16), tag = ciphertext.subarray(ciphertext.length - 16);
  const aad = computeAAD(epoch, seq, ct, data.length);
  const d = createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 } as any);
  (d as any).setAAD(aad); (d as any).setAuthTag(tag); return Buffer.concat([d.update(data), d.final()]);
}

// ─── WyzeDTLSConn ───────────────────────────────────────────────

export class WyzeDTLSConn extends EventEmitter {
  private socket: dgram.Socket | null = null;
  private remotePort: number;
  private readonly host: string;
  private readonly uid: string;
  private readonly enr: string;
  private readonly mac: string;
  private readonly model: string;
  private readonly authKey: string;
  private readonly psk: Buffer;
  private readonly sid: Buffer;
  private readonly verbose: boolean;

  // DTLS keys
  private clientWriteKey!: Buffer;
  private serverWriteKey!: Buffer;
  private clientWriteIV!: Buffer;
  private serverWriteIV!: Buffer;
  private clientEpochSeq = 1;

  // IOCtrl state
  private avSeq = 0;
  private seqCmd = 0;
  private txSeq = 0;

  // Periodic ACK
  private ackFlags = 0;
  private ackAvSeq = 0;
  private rxSeqStart = 0xffff;
  private rxSeqEnd = 0xffff;
  private rxSeqInit = false;
  private ackTicker: ReturnType<typeof setInterval> | null = null;

  // Frame handling
  private frameHandler: FrameHandler;
  private closed = false;
  private messageListener: ((msg: Buffer, rinfo: dgram.RemoteInfo) => void) | null = null;

  constructor(opts: WyzeDTLSConnOptions) {
    super();
    this.host = opts.host;
    this.remotePort = opts.port ?? 32761;
    this.uid = opts.uid;
    this.enr = opts.enr;
    this.mac = opts.mac;
    this.model = opts.model;
    this.verbose = opts.verbose ?? false;
    this.authKey = calculateAuthKey(opts.enr, opts.mac).toString("ascii");
    this.psk = derivePSK(opts.enr);
    this.sid = genSessionId();
    this.frameHandler = new FrameHandler(this.verbose);
  }

  // ─── Public API ───────────────────────────────────────────────

  /**
   * Connect to camera: Discovery → DTLS → AV Login → K-Auth.
   * After this, call startVideo()/startAudio() to begin streaming.
   */
  async connect(): Promise<{ hasTwoWay: boolean; authInfo: any }> {
    this.socket = dgram.createSocket("udp4");
    await new Promise<void>(r => this.socket!.bind(0, r));
    if (this.verbose) console.log(`[Wyze] UDP bound :${this.socket.address().port}`);

    // 1. IOTC Discovery
    await this.writeAndWait(this.msgDisco(1), r => r.length >= 16 && r.readUInt16LE(8) === 0x0602);
    if (this.verbose) console.log("[Wyze] Discovery OK");

    // 2. Direct connect
    await this.udpSend(this.msgDisco(2));
    await this.sleep(200);

    // 3. Session
    await this.writeAndWait(this.msgSession(), r => r.length >= 16 && r.readUInt16LE(8) === 0x0404);
    if (this.verbose) console.log("[Wyze] Session OK");

    // 4. DTLS Handshake
    await this.doDTLSHandshake();
    if (this.verbose) console.log("[Wyze] DTLS OK");

    // 5. AV Login
    const hasTwoWay = await this.doAVLogin();
    if (this.verbose) console.log(`[Wyze] AV Login OK (twoWay=${hasTwoWay})`);

    // Start periodic ACK
    this.ackTicker = setInterval(() => this.sendPeriodicAck(), 100);

    // 6. K-Auth
    const authInfo = await this.doKAuth();
    if (this.verbose) console.log("[Wyze] K-Auth OK");

    // Start frame listener
    this.startFrameListener();

    return { hasTwoWay, authInfo };
  }

  /** Start video streaming. Returns when K10010 response is received. */
  async startVideo(frameSize = 0, bitrate = 0xF0): Promise<void> {
    // Set resolution
    const k10056 = this.buildHL(10056, Buffer.from([frameSize + 1, bitrate & 0xff, (bitrate >> 8) & 0xff, 0, 0]));
    await this.udpSend(this.msgTxData(this.dtlsWrite(23, this.msgIOCtrl(k10056)), 0));
    await this.sleep(200);
    // Start video channel
    const k10010 = this.buildK10010(1, true);
    await this.udpSend(this.msgTxData(this.dtlsWrite(23, this.msgIOCtrl(k10010)), 0));
  }

  /** Start audio streaming. */
  async startAudio(): Promise<void> {
    const k10010 = this.buildK10010(2, true);
    await this.udpSend(this.msgTxData(this.dtlsWrite(23, this.msgIOCtrl(k10010)), 0));
  }

  /** Set packet handler for decoded frames. */
  onPacket(handler: (pkt: Packet) => void): void {
    this.frameHandler.setHandler(handler);
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    if (this.ackTicker) clearInterval(this.ackTicker);
    if (this.messageListener && this.socket) this.socket.removeListener("message", this.messageListener);
    this.frameHandler.close();
    if (this.socket) { try { this.socket.close(); } catch {} this.socket = null; }
    this.emit("close");
  }

  // ─── DTLS Handshake ───────────────────────────────────────────

  private async doDTLSHandshake(): Promise<void> {
    const clientRandom = randomBytes(32);

    // Build ClientHello
    const ext1 = Buffer.alloc(8); ext1.writeUInt16BE(0x000a, 0); ext1.writeUInt16BE(4, 2); ext1.writeUInt16BE(2, 4); ext1.writeUInt16BE(0x001d, 6);
    const ext2 = Buffer.alloc(6); ext2.writeUInt16BE(0x000b, 0); ext2.writeUInt16BE(2, 2); ext2[4] = 1; ext2[5] = 0;
    const exts = Buffer.concat([ext1, ext2]); const extsL = Buffer.alloc(2 + exts.length); extsL.writeUInt16BE(exts.length, 0); exts.copy(extsL, 2);
    const cs = Buffer.alloc(4); cs.writeUInt16BE(2, 0); cs.writeUInt16BE(0xccac, 2);
    const chBody = Buffer.concat([Buffer.from([0xfe, 0xfd]), clientRandom, Buffer.from([0, 0]), cs, Buffer.from([0x01, 0x00]), extsL]);
    const clientHello = buildHandshake(1, 0, chBody);
    const chRec = buildDtlsRecord(22, 0, 0, clientHello);

    // Wait for server flight
    const srvHS = new Map<number, HandshakeMsg>();
    await new Promise<void>((res, rej) => {
      const t = setTimeout(() => { cl(); rej(new Error("DTLS timeout")); }, 8000);
      const rx = setInterval(() => this.udpSend(this.msgTxData(chRec, 0)).catch(() => {}), 1000);
      const onMsg = (msg: Buffer, ri: dgram.RemoteInfo) => {
        if (ri.address !== this.host) return; this.remotePort = ri.port;
        const d = reverseTransCodeBlob(msg); if (d.length < 16) return;
        if (d.readUInt16LE(8) === 0x0428 && d.length > 24) { this.udpSend(this.msgKeepaliveAck(d)).catch(() => {}); return; }
        if (d.readUInt16LE(8) === 0x0408 && d.length > 28 && d[14] === 0) {
          for (const r of parseAllRecords(d.subarray(28))) { if (r.contentType !== 22 || r.epoch !== 0) continue;
            for (const h of parseHandshakeMsgs(r.fragment)) { if (!srvHS.has(h.msgSeq)) { srvHS.set(h.msgSeq, h); if (h.type === 14) { cl(); res(); } } } }
        }
      };
      const cl = () => { clearTimeout(t); clearInterval(rx); this.socket!.removeListener("message", onMsg); };
      this.socket!.on("message", onMsg); this.udpSend(this.msgTxData(chRec, 0)).catch(() => {});
    });

    const sHello = srvHS.get(0)!, sKE = srvHS.get(1)!, sHD = srvHS.get(2)!;
    const serverRandom = Buffer.from(sHello.body.subarray(2, 34));

    // Parse ServerKeyExchange
    let o = 0; const hl = sKE.body.readUInt16BE(o); o += 2 + hl; o++;
    o += 2; // skip namedCurve
    const pl = sKE.body[o]!; o++; const sPub = Buffer.from(sKE.body.subarray(o, o + pl));

    // ECDHE x25519
    const { publicKey: myPubObj, privateKey: myPriv } = generateKeyPairSync("x25519");
    const myPubRaw = myPubObj.export({ type: "spki", format: "der" }).subarray(-32);
    const sKeyObj = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b656e032100", "hex"), sPub]), format: "der", type: "spki" });
    const shared = diffieHellman({ publicKey: sKeyObj, privateKey: myPriv });

    // Derive keys
    const pms = Buffer.alloc(2 + shared.length + 2 + this.psk.length);
    pms.writeUInt16BE(shared.length, 0); shared.copy(pms, 2); pms.writeUInt16BE(this.psk.length, 2 + shared.length); this.psk.copy(pms, 4 + shared.length);
    const ms = tlsPRF(pms, "master secret", Buffer.concat([clientRandom, serverRandom]), 48);
    const kb = tlsPRF(ms, "key expansion", Buffer.concat([serverRandom, clientRandom]), 88);
    this.clientWriteKey = kb.subarray(0, 32); this.serverWriteKey = kb.subarray(32, 64);
    this.clientWriteIV = kb.subarray(64, 76); this.serverWriteIV = kb.subarray(76, 88);

    // Client flight 2: CKE + CCS + Finished
    const pskId = Buffer.from("AUTHPWD_admin");
    const ckeB = Buffer.alloc(2 + pskId.length + 1 + myPubRaw.length);
    ckeB.writeUInt16BE(pskId.length, 0); pskId.copy(ckeB, 2); ckeB[2 + pskId.length] = myPubRaw.length; myPubRaw.copy(ckeB, 3 + pskId.length);
    const cke = buildHandshake(16, 1, ckeB);

    const hsHash = createHash("sha256").update(Buffer.concat([clientHello, sHello.raw, sKE.raw, sHD.raw, cke])).digest();
    const vd = tlsPRF(ms, "client finished", hsHash, 12);
    const fin = buildHandshake(20, 2, vd);
    const encFin = chacha20Encrypt(this.clientWriteKey, this.clientWriteIV, 1, 0, 22, fin);
    const flight2 = Buffer.concat([buildDtlsRecord(22, 0, 1, cke), buildDtlsRecord(20, 0, 2, Buffer.from([0x01])), buildDtlsRecord(22, 1, 0, encFin)]);

    // Wait for server CCS + Finished
    await new Promise<void>((res, rej) => {
      const t = setTimeout(() => { cl(); rej(new Error("Server Finished timeout")); }, 8000);
      const rx = setInterval(() => this.udpSend(this.msgTxData(flight2, 0)).catch(() => {}), 1500);
      const onMsg = (msg: Buffer, ri: dgram.RemoteInfo) => {
        if (ri.address !== this.host) return; this.remotePort = ri.port;
        const d = reverseTransCodeBlob(msg); if (d.length < 16) return;
        if (d.readUInt16LE(8) === 0x0428 && d.length > 24) { this.udpSend(this.msgKeepaliveAck(d)).catch(() => {}); return; }
        if (d.readUInt16LE(8) === 0x0408 && d.length > 28 && d[14] === 0) {
          for (const r of parseAllRecords(d.subarray(28))) {
            if (r.contentType === 22 && r.epoch === 1) { try { chacha20Decrypt(this.serverWriteKey, this.serverWriteIV, 1, r.seqNum, 22, r.fragment); cl(); res(); } catch {} }
          }
        }
      };
      const cl = () => { clearTimeout(t); clearInterval(rx); this.socket!.removeListener("message", onMsg); };
      this.socket!.on("message", onMsg); this.udpSend(this.msgTxData(flight2, 0)).catch(() => {});
    });
  }

  // ─── AV Login ─────────────────────────────────────────────────

  private async doAVLogin(): Promise<boolean> {
    const rid = genSessionId();
    const av1 = Buffer.alloc(570); av1.writeUInt16LE(0x0000, 0); av1.writeUInt16LE(0x000c, 2); av1.writeUInt16LE(546, 16); av1.writeUInt16LE(0x0001, 18);
    rid.copy(av1, 20, 0, 4); Buffer.from("admin").copy(av1, 24); Buffer.from(this.enr).copy(av1, 280); av1.writeUInt32LE(4, 540); av1.writeUInt32LE(0x001f07fb, 552);
    const av2 = Buffer.alloc(572); av2.writeUInt16LE(0x2000, 0); av2.writeUInt16LE(0x000c, 2); av2.writeUInt16LE(548, 16); av2.writeUInt16LE(0x0000, 18);
    rid.copy(av2, 20, 0, 4); av2[20] = (av2[20]! + 1) & 0xff; Buffer.from("admin").copy(av2, 24); Buffer.from(this.enr).copy(av2, 280); av2.writeUInt32LE(4, 540); av2.writeUInt32LE(0x001f07fb, 552);

    await this.udpSend(this.msgTxData(this.dtlsWrite(23, av1), 0));
    await this.sleep(50);
    await this.udpSend(this.msgTxData(this.dtlsWrite(23, av2), 0));

    return new Promise((res, rej) => {
      const t = setTimeout(() => { cl(); rej(new Error("AV Login timeout")); }, 8000);
      const onMsg = (msg: Buffer, ri: dgram.RemoteInfo) => {
        if (ri.address !== this.host) return; this.remotePort = ri.port;
        const d = reverseTransCodeBlob(msg); if (d.length < 16) return;
        if (d.readUInt16LE(8) === 0x0428 && d.length > 24) { this.udpSend(this.msgKeepaliveAck(d)).catch(() => {}); return; }
        if (d.readUInt16LE(8) === 0x0408 && d.length > 28 && d[14] === 0) {
          for (const r of parseAllRecords(d.subarray(28))) {
            if (r.contentType === 23 && r.epoch === 1) { try { const p = chacha20Decrypt(this.serverWriteKey, this.serverWriteIV, 1, r.seqNum, 23, r.fragment);
              if (p.readUInt16LE(0) === 0x2100) { const ack = Buffer.alloc(24); ack.writeUInt16LE(0x0009, 0); ack.writeUInt16LE(0x000c, 2);
                this.udpSend(this.msgTxData(this.dtlsWrite(23, ack), 0)).catch(() => {}); cl(); res(p.length >= 32 && p[31] === 1); }
            } catch {} }
          }
        }
      };
      const cl = () => { clearTimeout(t); this.socket!.removeListener("message", onMsg); };
      this.socket!.on("message", onMsg);
    });
  }

  // ─── K-Auth ───────────────────────────────────────────────────

  private async doKAuth(): Promise<any> {
    const k10000Json = Buffer.from('{"cameraInfo":{"audioEncoderList":[137,138,140]}}');
    const k10000 = Buffer.alloc(16 + k10000Json.length);
    k10000.write("HL", 0, 2, "ascii"); k10000[2] = 5; k10000.writeUInt16LE(10000, 4); k10000.writeUInt16LE(k10000Json.length, 6); k10000Json.copy(k10000, 16);

    // K10000 → K10001
    const k10001Payload = await this.sendIOCtrlWait(k10000, 10001);
    const status = k10001Payload[0]!;
    let challenge = Buffer.from(k10001Payload.subarray(1, 17));

    // Build challenge response
    let secretKey: Buffer;
    switch (status) {
      case 1: secretKey = Buffer.from("FFFFFFFFFFFFFFFF", "ascii"); break;
      case 3: secretKey = Buffer.alloc(16); Buffer.from(this.enr.slice(0, 16), "ascii").copy(secretKey); break;
      case 6: {
        const fk = Buffer.from(this.enr.slice(0, 16), "ascii"); challenge = Buffer.from(xxteaDecryptVar(challenge, fk));
        secretKey = Buffer.alloc(16);
        if (this.enr.length >= 32) Buffer.from(this.enr.slice(16, 32), "ascii").copy(secretKey);
        else if (this.enr.length > 16) Buffer.from(this.enr.slice(16), "ascii").copy(secretKey);
        else secretKey = Buffer.from("FFFFFFFFFFFFFFFF", "ascii"); break;
      }
      default: secretKey = Buffer.from("FFFFFFFFFFFFFFFF", "ascii");
    }
    const resp = xxteaDecryptVar(challenge, secretKey);
    const sessId = randomBytes(4);
    const k10002 = Buffer.alloc(38); k10002.write("HL", 0, 2, "ascii"); k10002[2] = 5; k10002.writeUInt16LE(10002, 4); k10002[6] = 22;
    resp.copy(k10002, 16, 0, 16); sessId.copy(k10002, 32); k10002[36] = 1; k10002[37] = 1;

    // K10002 → K10003
    const k10003Payload = await this.sendIOCtrlWait(k10002, 10003);
    try {
      const jsonStr = k10003Payload.toString().replace(/[\x00-\x1f]/g, "");
      const start = jsonStr.indexOf("{");
      if (start >= 0) return JSON.parse(jsonStr.slice(start));
    } catch {}
    return {};
  }

  private sendIOCtrlWait(payload: Buffer, expectCmd: number, timeoutMs = 8000): Promise<Buffer> {
    const frame = this.msgIOCtrl(payload);
    return new Promise((res, rej) => {
      const t = setTimeout(() => { cl(); rej(new Error(`HL ${expectCmd} timeout`)); }, timeoutMs);
      const rx = setInterval(() => this.udpSend(this.msgTxData(this.dtlsWrite(23, frame), 0)).catch(() => {}), 1000);
      const onMsg = (msg: Buffer, ri: dgram.RemoteInfo) => {
        if (ri.address !== this.host) return; this.remotePort = ri.port;
        const d = reverseTransCodeBlob(msg); if (d.length < 16) return;
        if (d.readUInt16LE(8) === 0x0428 && d.length > 24) { this.udpSend(this.msgKeepaliveAck(d)).catch(() => {}); return; }
        if (d.readUInt16LE(8) === 0x0408 && d.length > 28 && d[14] === 0) {
          for (const r of parseAllRecords(d.subarray(28))) { if (r.contentType === 23 && r.epoch === 1) {
            try { const p = chacha20Decrypt(this.serverWriteKey, this.serverWriteIV, 1, r.seqNum, 23, r.fragment); this.trackSeq(p);
              const hl = findHL(p, 32) ?? findHL(p, 36) ?? findHL(p, 0);
              if (hl) { const [cid, pl, ok] = parseHL(hl); if (ok && cid === expectCmd) { cl(); res(pl); } }
            } catch {} } }
        }
      };
      const cl = () => { clearTimeout(t); clearInterval(rx); this.socket!.removeListener("message", onMsg); };
      this.socket!.on("message", onMsg); this.udpSend(this.msgTxData(this.dtlsWrite(23, frame), 0)).catch(() => {});
    });
  }

  // ─── Frame listener (after auth) ─────────────────────────────

  private startFrameListener(): void {
    this.messageListener = (msg: Buffer, ri: dgram.RemoteInfo) => {
      if (ri.address !== this.host || this.closed) return;
      this.remotePort = ri.port;
      const decoded = reverseTransCodeBlob(msg);
      if (decoded.length < 16) return;
      const cmd = decoded.readUInt16LE(8);

      if (cmd === 0x0428 && decoded.length > 24) { this.udpSend(this.msgKeepaliveAck(decoded)).catch(() => {}); return; }

      if (cmd === 0x0408 && decoded.length > 28 && decoded[14] === 0) {
        for (const r of parseAllRecords(decoded.subarray(28))) {
          if (r.contentType === 23 && r.epoch === 1) {
            try {
              const plain = chacha20Decrypt(this.serverWriteKey, this.serverWriteIV, 1, r.seqNum, 23, r.fragment);
              this.trackSeq(plain);
              const ch = plain[0]!;
              if (ch === ChannelIVideo || ch === ChannelPVideo || ch === ChannelAudio) {
                this.frameHandler.handle(plain);
              }
            } catch {}
          }
        }
      }
    };
    this.socket!.on("message", this.messageListener);
  }

  // ─── Message builders ─────────────────────────────────────────

  private dtlsWrite(ct: number, pt: Buffer): Buffer {
    const enc = chacha20Encrypt(this.clientWriteKey, this.clientWriteIV, 1, this.clientEpochSeq, ct, pt);
    const rec = buildDtlsRecord(ct, 1, this.clientEpochSeq, enc); this.clientEpochSeq++; return rec;
  }

  private msgIOCtrl(payload: Buffer): Buffer {
    const b = Buffer.alloc(40 + payload.length); b.writeUInt16LE(0x000c, 0); b.writeUInt16LE(0x000c, 2); b.writeUInt32LE(this.avSeq, 4); this.avSeq++;
    b.writeUInt16LE(0x7000, 16); b.writeUInt16LE(this.seqCmd, 18); b.writeUInt32LE(1, 20); b.writeUInt32LE(payload.length + 4, 24);
    b.writeUInt32LE(this.seqCmd, 28); b[37] = 0x01; payload.copy(b, 40); this.seqCmd++; return b;
  }

  private buildK10010(mediaType: number, enabled: boolean): Buffer {
    const b = Buffer.alloc(18); b.write("HL", 0, 2, "ascii"); b[2] = 5; b.writeUInt16LE(10010, 4); b.writeUInt16LE(2, 6);
    b[16] = mediaType; b[17] = enabled ? 1 : 2; return b;
  }

  private buildHL(cmdId: number, payload: Buffer): Buffer {
    const b = Buffer.alloc(16 + payload.length); b.write("HL", 0, 2, "ascii"); b[2] = 5; b.writeUInt16LE(cmdId, 4); b.writeUInt16LE(payload.length, 6); payload.copy(b, 16); return b;
  }

  private msgDisco(stage: number): Buffer {
    const b = Buffer.alloc(88); b[0] = 0x04; b[1] = 0x02; b[2] = 0x1a; b[3] = 0x02;
    b.writeUInt16LE(72, 4); b.writeUInt16LE(0x0601, 8); b.writeUInt16LE(0x0021, 10);
    Buffer.from(this.uid).copy(b, 16); Buffer.from([0x01, 0x01, 0x02, 0x04]).copy(b, 52); this.sid.copy(b, 56); b[64] = stage;
    if (stage === 1) Buffer.from(this.authKey).copy(b, 74); return b;
  }

  private msgSession(): Buffer {
    const b = Buffer.alloc(52); b[0] = 0x04; b[1] = 0x02; b[2] = 0x1a; b[3] = 0x02;
    b.writeUInt16LE(36, 4); b.writeUInt16LE(0x0402, 8); b.writeUInt16LE(0x0033, 10);
    Buffer.from(this.uid).copy(b, 16); this.sid.copy(b, 36); b.writeUInt32LE(Math.floor(Date.now() / 1000), 48); return b;
  }

  private msgTxData(payload: Buffer, ch: number): Buffer {
    const bs = 12 + payload.length; const b = Buffer.alloc(16 + bs);
    b[0] = 0x04; b[1] = 0x02; b[2] = 0x1a; b[3] = 0x0b;
    b.writeUInt16LE(bs, 4); b.writeUInt16LE(this.txSeq, 6); this.txSeq++;
    b.writeUInt16LE(0x0407, 8); b.writeUInt16LE(0x0021, 10);
    this.sid.copy(b, 12, 0, 2); b[14] = ch; b[15] = 0x01;
    b.writeUInt32LE(0x0c, 16); this.sid.copy(b, 20, 0, 8); payload.copy(b, 28); return b;
  }

  private msgKeepaliveAck(inc: Buffer): Buffer {
    const b = Buffer.alloc(24); b[0] = 0x04; b[1] = 0x02; b[2] = 0x1a; b[3] = 0x0a;
    b.writeUInt16LE(8, 4); b.writeUInt16LE(0x0427, 8); b.writeUInt16LE(0x0021, 10);
    if (inc.length > 24) inc.copy(b, 16, 16, 24); return b;
  }

  // ─── Low-level helpers ────────────────────────────────────────

  private udpSend(data: Buffer): Promise<void> {
    return new Promise((r, j) => { this.socket!.send(transCodeBlob(data), this.remotePort, this.host, e => e ? j(e) : r()); });
  }

  private writeAndWait(data: Buffer, matchFn: (d: Buffer) => boolean, ms = 5000): Promise<Buffer> {
    return new Promise((res, rej) => {
      const dl = Date.now() + ms; const iv = setInterval(() => { if (Date.now() > dl) { cl(); rej(new Error("Timeout")); } this.udpSend(data).catch(() => {}); }, 1000);
      const onMsg = (msg: Buffer, ri: dgram.RemoteInfo) => { if (ri.address !== this.host) return; this.remotePort = ri.port;
        const d = reverseTransCodeBlob(msg); if (matchFn(d)) { cl(); res(d); } };
      const cl = () => { clearInterval(iv); this.socket!.removeListener("message", onMsg); };
      this.socket!.on("message", onMsg); this.udpSend(data).catch(() => {});
    });
  }

  private sendPeriodicAck(): void {
    this.ackFlags++;
    const ack = Buffer.alloc(24); ack.writeUInt16LE(0x0009, 0); ack.writeUInt16LE(0x000c, 2);
    ack.writeUInt32LE(this.ackAvSeq, 4); this.ackAvSeq++;
    ack.writeUInt16LE(this.rxSeqStart, 8); ack.writeUInt16LE(this.rxSeqEnd, 10);
    if (this.rxSeqInit) this.rxSeqStart = this.rxSeqEnd;
    ack.writeUInt16LE(this.ackFlags, 12); ack.writeUInt32LE(this.ackFlags << 16, 16); ack.writeUInt16LE(Date.now() & 0xffff, 20);
    this.udpSend(this.msgTxData(this.dtlsWrite(23, ack), 0)).catch(() => {});
  }

  private trackSeq(plain: Buffer): void {
    if (plain.readUInt16LE(0) === 0x000c && plain.length >= 8) {
      const s = plain.readUInt16LE(4); if (!this.rxSeqInit) this.rxSeqInit = true;
      if (s > this.rxSeqEnd || this.rxSeqEnd === 0xffff) this.rxSeqEnd = s;
    }
  }

  private sleep(ms: number): Promise<void> { return new Promise(r => setTimeout(r, ms)); }
}
