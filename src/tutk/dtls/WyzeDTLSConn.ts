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
import { FrameHandler, type Packet, ChannelAudio, ChannelIVideo, ChannelPVideo, FrameTypeStartAlt, FrameTypeEndSingle } from "../frame.js";
import { isVideoCodec, isAudioCodec, getSampleRateIndex, getSamplesPerFrame } from "../codec.js";
import { WyzeDtlsServer } from "./dtlsServer.js";

// ─── CC51 transport variant ─────────────────────────────────────
// Some Wyze firmwares answer discovery with the "CC51" protocol instead of
// the IOTC "Basis" protocol. CC51 frames are sent raw (no TransCode blob),
// carry a per-session HMAC trailer, and wrap the same DTLS records.
// Ported from go2rtc pkg/tutk/dtls/conn_dtls.go.
const MAGIC_CC51 = "\x51\xcc";
const SDK_VERSION_43 = Buffer.from([0x00, 0x08, 0x03, 0x04]); // 4.3.8.0
const CMD_DISCO_CC51 = 0x1002;
const CMD_KEEPALIVE_CC51 = 0x1202;
const CMD_DTLS_CC51 = 0x1502;
const PAYLOAD_SIZE_CC51 = 0x0028;
const PACKET_SIZE_CC51 = 52;
const HEADER_SIZE_CC51 = 28;
const AUTH_SIZE_CC51 = 20;
const KEEPALIVE_SIZE_CC51 = 48;

// ─── Types ──────────────────────────────────────────────────────

export interface WyzeDTLSConnOptions {
  host: string;
  port?: number;
  uid: string;
  enr: string;
  mac: string;
  model: string;
  verbose?: boolean;
  /** Optional logger — defaults to global console. Pass Scrypted's console to see logs in the plugin UI. */
  logger?: { log: (...args: any[]) => void; error?: (...args: any[]) => void };
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
  private readonly log: (...args: any[]) => void;

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

  // CC51 transport state (set during discovery)
  private isCC51 = false;
  private ticket = 0;
  private kaSeq = 0;

  // Two-way audio (backchannel) state
  private serverConn: WyzeDtlsServer | null = null;
  private audioSeq = 0;
  private audioFrameNo = 0;
  private audioCodecId = 0;
  private audioSampleRate = 0;
  private audioChannels = 0;
  private hasTwoWay = false;

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
    this.log = opts.logger?.log?.bind(opts.logger) ?? console.log;
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
    const localPort = this.socket.address().port;
    // Unconditional handshake tracing (not gated by `verbose`) so plugin logs
    // pinpoint exactly which P2P stage stalls. Each stage is numbered /6.
    this.log(`[Wyze] connect → ${this.host}:${this.remotePort} udp:${localPort} model=${this.model} uid=${this.uid}`);

    // 1-3. Discovery — dual-probe IOTC + CC51, adopt whichever the camera
    // answers. CC51 cameras never reply to the IOTC probe alone, which stalled
    // here before (issue #4).
    this.log("[Wyze] 1/6 discovery…");
    await this.discover();
    this.log(`[Wyze] 1/6 discovery OK (protocol=${this.isCC51 ? "CC51" : "IOTC"})`);

    // 4. DTLS Handshake
    this.log("[Wyze] 4/6 dtls handshake…");
    await this.doDTLSHandshake();
    this.log("[Wyze] 4/6 dtls OK");

    // 5. AV Login
    this.log("[Wyze] 5/6 av login…");
    const hasTwoWay = await this.doAVLogin();
    this.hasTwoWay = hasTwoWay;
    this.log(`[Wyze] 5/6 av login OK (twoWay=${hasTwoWay})`);

    // Start periodic ACK
    this.ackTicker = setInterval(() => this.sendPeriodicAck(), 100);

    // 6. K-Auth
    this.log("[Wyze] 6/6 k-auth…");
    const authInfo = await this.doKAuth();
    this.log("[Wyze] 6/6 k-auth OK — handshake complete");

    // Start frame listener
    this.startFrameListener();

    return { hasTwoWay, authInfo };
  }

  /**
   * Discovery with dual-probe: send the IOTC and the CC51 disco packets and
   * adopt whichever protocol the camera answers (ported from go2rtc
   * conn_dtls.go `discovery()`).
   */
  private async discover(): Promise<void> {
    const pktIOTC = transCodeBlob(this.msgDisco(1));
    const pktCC51 = this.msgDiscoCC51(0, 0, false);
    let rxFromCamera = 0;
    let unmatched = 0;

    await new Promise<void>((resolve, reject) => {
      const dl = Date.now() + 5000;
      const tick = () => {
        if (Date.now() > dl) {
          cl();
          reject(new Error(`discovery timeout after 5000ms — rxFromCamera=${rxFromCamera} unmatched=${unmatched} (target=${this.host}:${this.remotePort})`));
          return;
        }
        this.udpSendRaw(pktIOTC).catch(() => {});
        this.udpSendRaw(pktCC51).catch(() => {});
      };
      const onMsg = (msg: Buffer, ri: dgram.RemoteInfo) => {
        if (ri.address !== this.host) return;
        rxFromCamera++;
        // CC51 reply?
        if (
          msg.length >= PACKET_SIZE_CC51 &&
          msg.subarray(0, 2).toString("binary") === MAGIC_CC51 &&
          msg.readUInt16LE(4) === CMD_DISCO_CC51
        ) {
          this.remotePort = ri.port;
          this.isCC51 = true;
          this.ticket = msg.readUInt16LE(14);
          if (msg.length >= 24) msg.copy(this.sid, 0, 16, 24);
          cl();
          this.log(`[Wyze] discovery: CC51 protocol (ticket=${this.ticket})`);
          this.discoDoneCC51().then(resolve).catch(reject);
          return;
        }
        // IOTC reply?
        const d = reverseTransCodeBlob(msg);
        if (d.length >= 16 && d.readUInt16LE(8) === 0x0602) {
          this.remotePort = ri.port;
          this.isCC51 = false;
          cl();
          this.log("[Wyze] discovery: IOTC protocol");
          this.discoDoneIOTC().then(resolve).catch(reject);
          return;
        }
        unmatched++;
      };
      const iv = setInterval(tick, 1000);
      const cl = () => { clearInterval(iv); this.socket!.removeListener("message", onMsg); };
      this.socket!.on("message", onMsg);
      tick();
    });
  }

  /** IOTC discovery stage 2 + session negotiation. */
  private async discoDoneIOTC(): Promise<void> {
    await this.udpSend(this.msgDisco(2));
    await this.sleep(200);
    this.log("[Wyze] 3/6 session…");
    await this.writeAndWait(this.msgSession(), r => r.length >= 16 && r.readUInt16LE(8) === 0x0404, 5000, "session");
    this.log("[Wyze] 3/6 session OK");
  }

  /** CC51 discovery stage 2 (no IOTC session step). */
  private async discoDoneCC51(): Promise<void> {
    const req = this.msgDiscoCC51(2, this.ticket, false);
    await new Promise<void>((resolve, reject) => {
      const dl = Date.now() + 5000;
      const tick = () => {
        if (Date.now() > dl) { cl(); reject(new Error("CC51 disco stage-2 timeout")); return; }
        this.udpSendRaw(req).catch(() => {});
      };
      const onMsg = (msg: Buffer, ri: dgram.RemoteInfo) => {
        if (ri.address !== this.host) return;
        if (msg.length < PACKET_SIZE_CC51 || msg.subarray(0, 2).toString("binary") !== MAGIC_CC51) return;
        if (msg.readUInt16LE(4) === CMD_DISCO_CC51 && msg.readUInt16LE(8) === 0xffff && msg.readUInt16LE(12) === 3) {
          this.remotePort = ri.port;
          cl();
          resolve();
        }
      };
      const iv = setInterval(tick, 1000);
      const cl = () => { clearInterval(iv); this.socket!.removeListener("message", onMsg); };
      this.socket!.on("message", onMsg);
      tick();
    });
  }

  /** Start video streaming. Returns when K10010 response is received. */
  async startVideo(frameSize = 0, bitrate = 0xF0): Promise<void> {
    // Set resolution — doorbell-class models use K10052, others K10056
    // (ported from go2rtc Client.SetResolution / useDoorbellResolution).
    const resHL = this.useDoorbellResolution()
      ? this.buildHL(10052, Buffer.from([bitrate & 0xff, (bitrate >> 8) & 0xff, frameSize + 1, 0, 0, 0]))
      : this.buildHL(10056, Buffer.from([frameSize + 1, bitrate & 0xff, (bitrate >> 8) & 0xff, 0, 0]));
    await this.udpSend(this.msgTxData(this.dtlsWrite(23, this.msgIOCtrl(resHL)), 0));
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

  // ─── Two-way audio (backchannel) — ported from go2rtc ─────────────

  /**
   * Enable the return-audio channel and bring up the backchannel DTLS server.
   * EXPERIMENTAL: the DTLS server handshake is hand-rolled (see dtlsServer.ts)
   * and needs validation on real hardware.
   */
  async startIntercom(): Promise<void> {
    if (this.serverConn) return;
    // Enable return-audio media channel (K10010, mediaType 3).
    const k10010 = this.buildK10010(3, true);
    await this.udpSend(this.msgTxData(this.dtlsWrite(23, this.msgIOCtrl(k10010)), 0));

    const server = new WyzeDtlsServer({
      psk: this.psk,
      send: (record) => { this.udpSend(this.msgTxData(record, 1)).catch(() => {}); },
      log: this.log,
      verbose: this.verbose,
    });
    this.serverConn = server;

    this.log("[Wyze] intercom: DTLS server handshake…");
    await server.handshake(5000);

    // Camera sends its AV login over the backchannel; echo the checksum back.
    const login = await server.recv(5000);
    if (login.length >= 24) {
      const checksum = login.readUInt32LE(20);
      server.write(this.msgAVLoginResponse(checksum));
      try {
        const resend = await server.recv(500);
        if (resend.length >= 24) server.write(this.msgAVLoginResponse(resend.readUInt32LE(20)));
      } catch { /* no resend — fine */ }
    }
    this.log("[Wyze] intercom: ready for two-way audio");
  }

  /** Send one encoded audio frame to the camera (codec must match getBackchannelCodec). */
  writeAudio(codec: number, payload: Buffer, timestampUS: number, sampleRate: number, channels: number): void {
    if (!this.serverConn) throw new Error("intercom not started");
    this.serverConn.write(this.msgAudioFrame(payload, timestampUS, codec, sampleRate, channels));
  }

  /** Tear down the backchannel and disable the return-audio channel. */
  stopIntercom(): void {
    if (this.serverConn) { this.serverConn.close(); this.serverConn = null; }
    this.audioSeq = 0;
    this.audioFrameNo = 0;
    if (!this.closed) {
      this.udpSend(this.msgTxData(this.dtlsWrite(23, this.msgIOCtrl(this.buildK10010(3, false))), 0)).catch(() => {});
    }
  }

  /** True once the backchannel DTLS server is up. */
  get isBackchannelReady(): boolean { return this.serverConn !== null; }

  private msgAVLoginResponse(checksum: number): Buffer {
    const b = Buffer.alloc(60);
    b.writeUInt16LE(0x2100, 0); b.writeUInt16LE(0x000c, 2); b[4] = 0x10;
    b.writeUInt32LE(0x24, 16); b.writeUInt32LE(checksum >>> 0, 20);
    b[29] = 0x01; b[31] = 0x01;
    b.writeUInt32LE(0x04, 36); b.writeUInt32LE(0x001f07fb, 40);
    b.writeUInt16LE(0x0003, 54); b.writeUInt16LE(0x0002, 56);
    return b;
  }

  private msgAudioFrame(payload: Buffer, timestampUS: number, codec: number, sampleRate: number, channels: number): Buffer {
    this.audioSeq++;
    this.audioFrameNo++;
    const prevFrame = this.audioFrameNo > 1 ? this.audioFrameNo - 1 : 0;
    const totalPayload = payload.length + 16;
    const b = Buffer.alloc(36 + totalPayload);
    // Outer header
    b[0] = ChannelAudio; b[1] = FrameTypeStartAlt;
    b.writeUInt16LE(0x000c, 2);
    b.writeUInt32LE(this.audioSeq >>> 0, 4);
    b.writeUInt32LE(timestampUS >>> 0, 8);
    b.writeUInt32LE(this.audioFrameNo === 1 ? 0x00000001 : 0x00100001, 12);
    // Inner header
    b[16] = ChannelAudio; b[17] = FrameTypeEndSingle;
    b.writeUInt16LE(prevFrame & 0xffff, 18);
    b.writeUInt16LE(0x0001, 20);
    b.writeUInt16LE(0x0010, 22);
    b.writeUInt32LE(totalPayload >>> 0, 24);
    b.writeUInt32LE(prevFrame >>> 0, 28);
    b.writeUInt32LE(this.audioFrameNo >>> 0, 32);
    payload.copy(b, 36);
    // FrameInfo trailer (16 bytes)
    const fi = b.subarray(36 + payload.length);
    fi[0] = codec; fi[1] = 0;
    const srIdx = getSampleRateIndex(sampleRate);
    fi[2] = (srIdx << 2) | 0x02; // 16-bit always set
    if (channels === 2) fi[2] |= 0x01;
    fi[4] = 1; // online
    const spf = getSamplesPerFrame(codec) || 1;
    fi.writeUInt32LE(Math.floor((this.audioFrameNo - 1) * spf * 1000 / (sampleRate || 1)) >>> 0, 12);
    return b;
  }

  /** Set packet handler for decoded frames. */
  onPacket(handler: (pkt: Packet) => void): void {
    this.frameHandler.setHandler((pkt: Packet) => {
      // Capture the camera's audio codec — it is also what the camera accepts
      // for the return-audio (backchannel) stream.
      if (isAudioCodec(pkt.codec)) {
        this.audioCodecId = pkt.codec;
        this.audioSampleRate = pkt.sampleRate || 8000;
        this.audioChannels = pkt.channels || 1;
      }
      handler(pkt);
    });
  }

  /** True if the camera advertised two-way streaming during AV login. */
  get hasTwoWayStreaming(): boolean { return this.hasTwoWay; }

  /** Audio codec the camera sent (= what it accepts back). 0 until first audio. */
  getBackchannelCodec(): { codec: number; sampleRate: number; channels: number } {
    return { codec: this.audioCodecId, sampleRate: this.audioSampleRate, channels: this.audioChannels };
  }

  // ─── Camera Commands (K10xxx via HL protocol) ─────────────────

  /**
   * Send a raw HL command and optionally wait for a response.
   * @returns The response payload, or null if no response expected.
   */
  async sendHLCommand(cmdId: number, payload: Buffer = Buffer.alloc(0), expectResponseCmd?: number): Promise<Buffer | null> {
    this.log(`[Wyze-HL] K${cmdId} → payload=[${[...payload].map(b => "0x" + b.toString(16)).join(",")}]${expectResponseCmd ? ` waitFor=K${expectResponseCmd}` : " (fire-and-forget)"}`);
    const hlMsg = this.buildHL(cmdId, payload);
    if (expectResponseCmd !== undefined) {
      try {
        const resp = await this.sendIOCtrlWait(hlMsg, expectResponseCmd);
        this.log(`[Wyze-HL] K${cmdId} → K${expectResponseCmd} OK resp=[${[...resp].map(b => "0x" + b.toString(16)).join(",")}] (${resp.length}B)`);
        return resp;
      } catch (e: any) {
        this.log(`[Wyze-HL] K${cmdId} → K${expectResponseCmd} FAILED: ${e?.message}`);
        throw e;
      }
    }
    // Fire and forget
    const frame = this.msgIOCtrl(hlMsg);
    await this.udpSend(this.msgTxData(this.dtlsWrite(23, frame), 0));
    this.log(`[Wyze-HL] K${cmdId} sent (no response expected)`);
    return null;
  }

  /** Get night vision status. Returns 1=on, 2=off, 3=auto */
  async getNightVision(): Promise<number> {
    const resp = await this.sendHLCommand(10040, Buffer.alloc(0), 10041);
    return resp?.[0] ?? 0;
  }

  /** Set night vision. 1=on, 2=off, 3=auto */
  async setNightVision(mode: 1 | 2 | 3): Promise<void> {
    await this.sendHLCommand(10042, Buffer.from([mode]), 10043);
  }

  /** Get motion alarm status. Returns: { enabled: boolean, sensitivity: number } */
  async getMotionAlarm(): Promise<{ enabled: boolean; sensitivity: number }> {
    const resp = await this.sendHLCommand(10200, Buffer.alloc(0), 10201);
    if (!resp || resp.length < 2) return { enabled: false, sensitivity: 0 };
    return { enabled: resp[0] === 1, sensitivity: resp[1]! };
  }

  /** Set motion alarm. sensitivity: 1=low, 2=medium, 3=high */
  async setMotionAlarm(enabled: boolean, sensitivity: 1 | 2 | 3 = 2): Promise<void> {
    await this.sendHLCommand(10202, Buffer.from([enabled ? 1 : 2, sensitivity]), 10203);
  }

  /** Get status LED (network light). Returns true if on. */
  async getStatusLight(): Promise<boolean> {
    const resp = await this.sendHLCommand(10030, Buffer.alloc(0), 10031);
    return resp?.[0] === 1;
  }

  /** Set status LED on/off. */
  async setStatusLight(on: boolean): Promise<void> {
    await this.sendHLCommand(10032, Buffer.from([on ? 1 : 2]), 10033);
  }

  /** Take a photo on the camera (saved to SD card). */
  async takePhoto(): Promise<void> {
    await this.sendHLCommand(10058, Buffer.from([1]));
  }

  /** Start the camera's built-in boa web server (for accessing photos on SD). */
  async startBoaServer(): Promise<void> {
    await this.sendHLCommand(10148, Buffer.from([0, 1, 0, 0, 0]));
  }

  /** Get IR LED status. Returns true if on. */
  async getIRLED(): Promise<boolean> {
    const resp = await this.sendHLCommand(10044, Buffer.alloc(0), 10045);
    return resp?.[0] === 1;
  }

  /** Set IR LED on/off. */
  async setIRLED(on: boolean): Promise<void> {
    await this.sendHLCommand(10046, Buffer.from([on ? 1 : 2]), 10047);
  }

  /** Get motion tagging (green box) status. */
  async getMotionTagging(): Promise<boolean> {
    const resp = await this.sendHLCommand(10290, Buffer.alloc(0), 10291);
    return resp?.[0] === 1;
  }

  /** Set motion tagging (green box) on/off. */
  async setMotionTagging(on: boolean): Promise<void> {
    await this.sendHLCommand(10292, Buffer.from([on ? 1 : 2]), 10293);
  }

  /** Get camera time. */
  async getCameraTime(): Promise<number> {
    const resp = await this.sendHLCommand(10090, Buffer.alloc(0), 10091);
    if (!resp || resp.length < 4) return 0;
    return resp.readUInt32LE(0);
  }

  /** Get spotlight/floodlight status. Returns true if on. */
  async getSpotlight(): Promise<boolean> {
    const resp = await this.sendHLCommand(10640, Buffer.alloc(0), 10641);
    return resp?.[0] === 1;
  }

  /** Set spotlight/floodlight on/off. */
  async setSpotlight(on: boolean): Promise<void> {
    await this.sendHLCommand(10646, Buffer.from([on ? 1 : 2]), 10647);
  }

  /** Get alarm flashing status (siren + flash). */
  async getAlarmFlashing(): Promise<boolean> {
    const resp = await this.sendHLCommand(10632, Buffer.alloc(0), 10633);
    return resp?.[0] === 1;
  }

  /** Set alarm flashing (siren + flash) on/off. K10630: value 1=on, 2=off. */
  async setAlarmFlashing(on: boolean): Promise<void> {
    const v = on ? 1 : 2;
    await this.sendHLCommand(10630, Buffer.from([v, v]), 10631);
  }

  /** Trigger siren + flash alarm (turn on). */
  async triggerAlarm(): Promise<void> { return this.setAlarmFlashing(true); }

  /** Stop siren + flash alarm (turn off). */
  async stopAlarm(): Promise<void> { return this.setAlarmFlashing(false); }

  /** Set floodlight switch (for integrated floodlight cameras). K12060. */
  async setFloodlight(on: boolean): Promise<void> {
    await this.sendHLCommand(12060, Buffer.from([on ? 1 : 2]));
  }

  /**
   * Query camera capabilities by probing commands.
   * Returns which accessories/features are available.
   */
  async probeCapabilities(): Promise<{
    hasSpotlight: boolean;
    hasSiren: boolean;
    hasFloodlight: boolean;
    hasAccessories: boolean;
    hasRtsp: boolean;
    hasBattery: boolean;
  }> {
    const probe = async (cmdId: number, respCmdId: number): Promise<boolean> => {
      try { const r = await this.sendHLCommand(cmdId, Buffer.alloc(0), respCmdId); return r !== null && r.length > 0; }
      catch { return false; }
    };

    const [hasSpotlight, hasSiren, hasFloodlight, hasAccessories, hasRtsp, hasBattery] = await Promise.all([
      probe(10640, 10641), // spotlight
      probe(10632, 10633), // alarm/siren
      probe(10788, 10789), // integrated floodlight
      probe(10720, 10721), // accessories
      probe(10604, 10605), // rtsp
      probe(10448, 10449), // battery
    ]);

    return { hasSpotlight, hasSiren, hasFloodlight, hasAccessories, hasRtsp, hasBattery };
  }

  /**
   * Waits for the next keyframe and returns the raw H264 Annex-B data.
   * Use ffmpeg to decode: `ffmpeg -f h264 -i pipe:0 -frames:v 1 -f image2 snapshot.jpg`
   */
  grabKeyframe(timeoutMs = 10000): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { cleanup(); reject(new Error("Keyframe timeout")); }, timeoutMs);
      const origHandler = (this.frameHandler as any).onPacket;

      const handler = (pkt: Packet) => {
        origHandler?.(pkt);
        if (isVideoCodec(pkt.codec) && pkt.isKeyframe) {
          cleanup();
          resolve(pkt.payload);
        }
      };

      const cleanup = () => {
        clearTimeout(timer);
        this.frameHandler.setHandler(origHandler ?? (() => {}));
      };

      this.frameHandler.setHandler(handler);
    });
  }

  // ─── Diagnostics ──────────────────────────────────────────────

  /**
   * Run full diagnostics: query every known camera parameter/flag and
   * return a JSON-serialisable object. Useful for debugging and
   * understanding a camera's capabilities.
   *
   * Commands that the camera does not support will return `null` with
   * an error message. The function never throws.
   */

  // ─── Boa SD Card Polling (local motion detection) ─────────────

  /**
   * Check if the camera's built-in HTTP server (boa) is reachable.
   * Boa serves files from the SD card — requires SD card inserted.
   */
  async isBoaAlive(): Promise<boolean> {
    return new Promise((resolve) => {
      const s = new (require("node:net").Socket)();
      s.setTimeout(2000);
      s.connect(80, this.host, () => { s.destroy(); resolve(true); });
      s.on("error", () => resolve(false));
      s.on("timeout", () => { s.destroy(); resolve(false); });
    });
  }

  /**
   * Start boa and begin polling for alarm images (local motion detection).
   * Emits "motion" events when new alarm images appear on the SD card.
   *
   * @param intervalMs - Polling interval in ms (default: 3000)
   * @returns A stop function, or null if boa is not available
   */
  async startBoaMotionPolling(intervalMs = 3000): Promise<{ stop: () => void } | null> {
    // Try to start boa
    await this.startBoaServer();
    await new Promise(r => setTimeout(r, 3000));

    if (!(await this.isBoaAlive())) {
      return null; // No boa (no SD card, unsupported firmware, etc.)
    }

    let lastAlarmFile: string | null = null;
    let stopped = false;

    const poll = async () => {
      if (stopped) return;
      try {
        const result = await this.pollBoaAlarm();
        if (result && result.fileName !== lastAlarmFile) {
          lastAlarmFile = result.fileName;
          this.emit("motion", {
            timestamp: Date.now(),
            fileName: result.fileName,
            imageUrl: result.imageUrl,
            image: result.image, // JPEG Buffer or null
          });
        }
      } catch {}
    };

    const timer = setInterval(poll, intervalMs);
    poll(); // Initial check

    return {
      stop: () => { stopped = true; clearInterval(timer); },
    };
  }

  /**
   * Poll the boa web server for the latest alarm image.
   * Returns null if no alarm images found or boa not available.
   */
  async pollBoaAlarm(): Promise<{ fileName: string; imageUrl: string; image: Buffer | null } | null> {
    try {
      const base = `http://${this.host}/cgi-bin/hello.cgi?name=/alarm/`;
      const dateResp = await fetch(base, { signal: AbortSignal.timeout(3000) });
      const dateHtml = await dateResp.text();

      // Parse date folders: <h2>20260321</h2>
      const dates = [...dateHtml.matchAll(/<h2>(\d+)<\/h2>/g)].map(m => m[1]!);
      if (dates.length === 0) return null;
      const latestDate = dates.sort().pop()!;

      // Get files in latest date folder
      const fileResp = await fetch(`${base}${latestDate}`, { signal: AbortSignal.timeout(3000) });
      const fileHtml = await fileResp.text();

      // Parse file names: <h1>20260321_12_30_45.jpg</h1>
      const files = [...fileHtml.matchAll(/<h1>(\w+\.jpg)<\/h1>/g)].map(m => m[1]!);
      if (files.length === 0) return null;
      const latestFile = files.sort().pop()!;

      const imageUrl = `http://${this.host}/SDPath/alarm/${latestDate}/${latestFile}`;

      // Download the image
      let image: Buffer | null = null;
      try {
        const imgResp = await fetch(imageUrl, { signal: AbortSignal.timeout(5000) });
        if (imgResp.ok) {
          image = Buffer.from(await imgResp.arrayBuffer());
        }
      } catch {}

      return { fileName: latestFile, imageUrl, image };
    } catch {
      return null;
    }
  }
  async runDiagnostics(): Promise<Record<string, unknown>> {
    const diag: Record<string, unknown> = {
      _timestamp: new Date().toISOString(),
      _host: this.host,
      _model: this.model,
      _uid: this.uid,
      _mac: this.mac,
    };

    const safeQuery = async (
      label: string,
      cmdId: number,
      responseCmdId: number,
      payload: Buffer = Buffer.alloc(0),
      parser?: (buf: Buffer) => unknown,
    ) => {
      try {
        const resp = await this.sendHLCommand(cmdId, payload, responseCmdId);
        if (!resp || resp.length === 0) { diag[label] = null; return; }
        if (parser) { diag[label] = parser(resp); return; }
        // Default: try JSON first, then hex dump
        const str = resp.toString().replace(/[\x00-\x1f]/g, "").trim();
        const jsonStart = str.indexOf("{");
        if (jsonStart >= 0) {
          try { diag[label] = JSON.parse(str.slice(jsonStart)); return; } catch {}
        }
        diag[label] = { raw: resp.toString("hex"), length: resp.length };
      } catch (e: any) {
        diag[label] = { error: e?.message ?? String(e) };
      }
    };

    const parseBool = (b: Buffer) => b[0] === 1;
    const parseOnOff = (b: Buffer) => ({ value: b[0], label: b[0] === 1 ? "on" : b[0] === 2 ? "off" : b[0] === 3 ? "auto" : `unknown(${b[0]})` });

    // K10020 — Camera Info (JSON) — the big one
    // Sends param count + param IDs 1..60
    const paramCount = 60;
    const k10020Payload = Buffer.alloc(1 + paramCount);
    k10020Payload[0] = paramCount;
    for (let i = 0; i < paramCount; i++) k10020Payload[i + 1] = i + 1;
    await safeQuery("cameraInfo", 10020, 10021, k10020Payload);

    // K10030 — Network/Status LED
    await safeQuery("statusLight", 10030, 10031, Buffer.alloc(0), parseOnOff);

    // K10040 — Night Vision
    await safeQuery("nightVision", 10040, 10041, Buffer.alloc(0), parseOnOff);

    // K10044 — IR LED
    await safeQuery("irLed", 10044, 10045, Buffer.alloc(0), parseOnOff);

    // K10050 — Video Parameters (bitrate, resolution, fps, flip)
    await safeQuery("videoParams", 10050, 10051, Buffer.alloc(0), (b) => {
      if (b.length < 5) return { raw: b.toString("hex") };
      return {
        bitrate: b.readUInt16LE(0),
        resolution: b[2],
        fps: b[3],
        horizontalFlip: b[4] === 1,
        verticalFlip: b.length > 5 ? b[5] === 1 : undefined,
      };
    });

    // K10070 — OSD (On-Screen Display / timestamp)
    await safeQuery("osd", 10070, 10071, Buffer.alloc(0), parseOnOff);

    // K10074 — OSD Logo
    await safeQuery("osdLogo", 10074, 10075, Buffer.alloc(0), parseOnOff);

    // K10090 — Camera Time
    await safeQuery("cameraTime", 10090, 10091, Buffer.alloc(0), (b) => {
      if (b.length < 4) return null;
      const ts = b.readUInt32LE(0);
      return { unixTimestamp: ts, date: new Date(ts * 1000).toISOString() };
    });

    // K10200 — Motion Alarm
    await safeQuery("motionAlarm", 10200, 10201, Buffer.alloc(0), (b) => {
      if (b.length < 1) return null;
      return {
        enabled: b[0] === 1,
        sensitivity: b.length >= 2 ? b[1] : undefined,
        sensitivityLabel: b.length >= 2 ? (b[1] === 1 ? "low" : b[1] === 2 ? "medium" : b[1] === 3 ? "high" : `unknown(${b[1]})`) : undefined,
      };
    });

    // K10290 — Motion Tagging (green box)
    await safeQuery("motionTagging", 10290, 10291, Buffer.alloc(0), parseBool);

    // K10446 — Connection Status (JSON, outdoor cams)
    await safeQuery("connectionStatus", 10446, 10447);

    // K10448 — Battery Usage (outdoor cams, JSON)
    await safeQuery("batteryUsage", 10448, 10449);

    // K10604 — RTSP Parameters
    await safeQuery("rtspParams", 10604, 10605);

    // K10620 — Night check
    await safeQuery("nightCheck", 10620, 10621);

    // K10624 — Auto Switch Night Type
    await safeQuery("autoSwitchNightType", 10624, 10625, Buffer.alloc(0), parseOnOff);

    // K10632 — Alarm Flashing
    await safeQuery("alarmFlashing", 10632, 10633, Buffer.alloc(0), parseOnOff);

    // K10640 — Spotlight
    await safeQuery("spotlight", 10640, 10641, Buffer.alloc(0), parseOnOff);

    // K10720 — Accessories Info (JSON)
    await safeQuery("accessoriesInfo", 10720, 10721);

    // K10788 — Integrated Floodlight Info
    await safeQuery("integratedFloodlightInfo", 10788, 10789);

    // K10820 — White Light Info
    await safeQuery("whiteLightInfo", 10820, 10821);

    return diag;
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    if (this.serverConn) { this.serverConn.close(); this.serverConn = null; }
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
        const dec = this.decodeInbound(msg); if (!dec || dec.channel !== 0) return; const recs = dec.records;
        {
          for (const r of parseAllRecords(recs)) { if (r.contentType !== 22 || r.epoch !== 0) continue;
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
        const dec = this.decodeInbound(msg); if (!dec || dec.channel !== 0) return; const recs = dec.records;
        {
          for (const r of parseAllRecords(recs)) {
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
        const dec = this.decodeInbound(msg); if (!dec || dec.channel !== 0) return; const recs = dec.records;
        {
          for (const r of parseAllRecords(recs)) {
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
        const dec = this.decodeInbound(msg); if (!dec || dec.channel !== 0) return; const recs = dec.records;
        {
          for (const r of parseAllRecords(recs)) { if (r.contentType === 23 && r.epoch === 1) {
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
    let udpPackets = 0;
    let dtlsRecords = 0;
    let decryptErrors = 0;
    let frameData = 0;
    let keepalives = 0;
    const startedAt = Date.now();

    // Periodic stats log (every 30s)
    const statsTimer = setInterval(() => {
      if (this.closed) { clearInterval(statsTimer); return; }
      const elapsed = ((Date.now() - startedAt) / 1000).toFixed(0);
      this.log(
        `[Wyze-P2P] stats: ${elapsed}s elapsed  udp=${udpPackets} dtls=${dtlsRecords} ` +
        `frames=${frameData} keepalives=${keepalives} decryptErr=${decryptErrors}`,
      );
    }, 30_000);

    this.messageListener = (msg: Buffer, ri: dgram.RemoteInfo) => {
      if (ri.address !== this.host || this.closed) return;
      this.remotePort = ri.port;
      udpPackets++;
      const dec = this.decodeInbound(msg);
      if (!dec) { keepalives++; return; }
      // Channel 1 = backchannel DTLS (two-way audio) — feed the DTLS server.
      if (dec.channel === 1) { this.serverConn?.feed(dec.records); return; }
      const recs = dec.records;
      for (const r of parseAllRecords(recs)) {
        if (r.contentType === 23 && r.epoch === 1) {
          dtlsRecords++;
          try {
            const plain = chacha20Decrypt(this.serverWriteKey, this.serverWriteIV, 1, r.seqNum, 23, r.fragment);
            this.trackSeq(plain);
            const ch = plain[0]!;
            if (ch === ChannelIVideo || ch === ChannelPVideo || ch === ChannelAudio) {
              frameData++;
              this.frameHandler.handle(plain);
            }
          } catch {
            decryptErrors++;
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
    // CC51 transport wraps the DTLS record differently (raw + HMAC trailer).
    if (this.isCC51) return this.msgTxDataCC51(payload, ch);
    const bs = 12 + payload.length; const b = Buffer.alloc(16 + bs);
    b[0] = 0x04; b[1] = 0x02; b[2] = 0x1a; b[3] = 0x0b;
    b.writeUInt16LE(bs, 4); b.writeUInt16LE(this.txSeq, 6); this.txSeq++;
    b.writeUInt16LE(0x0407, 8); b.writeUInt16LE(0x0021, 10);
    this.sid.copy(b, 12, 0, 2); b[14] = ch; b[15] = 0x01;
    b.writeUInt32LE(0x0c, 16); this.sid.copy(b, 20, 0, 8); payload.copy(b, 28); return b;
  }

  // ─── CC51 message builders (ported from go2rtc conn_dtls.go) ──────
  private msgDiscoCC51(seq: number, ticket: number, isResponse: boolean): Buffer {
    const b = Buffer.alloc(PACKET_SIZE_CC51);
    b[0] = 0x51; b[1] = 0xcc;
    b.writeUInt16LE(CMD_DISCO_CC51, 4);
    b.writeUInt16LE(PAYLOAD_SIZE_CC51, 6);
    if (isResponse) b.writeUInt16LE(0xffff, 8);
    b.writeUInt16LE(seq, 12);
    b.writeUInt16LE(ticket, 14);
    this.sid.copy(b, 16, 0, 8);
    SDK_VERSION_43.copy(b, 24);
    b[28] = 0x1d;
    const key = Buffer.concat([Buffer.from(this.uid, "ascii"), Buffer.from(this.authKey, "ascii")]);
    createHmac("sha1", key).update(b.subarray(0, 32)).digest().copy(b, 32);
    return b;
  }

  private msgKeepaliveCC51(): Buffer {
    this.kaSeq += 2;
    const b = Buffer.alloc(KEEPALIVE_SIZE_CC51);
    b[0] = 0x51; b[1] = 0xcc;
    b.writeUInt16LE(CMD_KEEPALIVE_CC51, 4);
    b.writeUInt16LE(0x0024, 6);
    b.writeUInt32LE(this.kaSeq, 16);
    this.sid.copy(b, 20, 0, 8);
    const key = Buffer.concat([Buffer.from(this.uid, "ascii"), Buffer.from(this.authKey, "ascii")]);
    createHmac("sha1", key).update(b.subarray(0, 28)).digest().copy(b, 28);
    return b;
  }

  private msgTxDataCC51(payload: Buffer, channel: number): Buffer {
    const payloadSize = 16 + payload.length + AUTH_SIZE_CC51;
    const b = Buffer.alloc(HEADER_SIZE_CC51 + payload.length + AUTH_SIZE_CC51);
    b[0] = 0x51; b[1] = 0xcc;
    b.writeUInt16LE(CMD_DTLS_CC51, 4);
    b.writeUInt16LE(payloadSize, 6);
    b.writeUInt16LE(0x0010 | (channel << 8), 12);
    b.writeUInt16LE(this.ticket, 14);
    this.sid.copy(b, 16, 0, 8);
    b.writeUInt32LE(1, 24);
    payload.copy(b, HEADER_SIZE_CC51);
    const key = Buffer.concat([Buffer.from(this.uid, "ascii"), Buffer.from(this.authKey, "ascii")]);
    createHmac("sha1", key).update(b.subarray(0, HEADER_SIZE_CC51)).digest().copy(b, HEADER_SIZE_CC51 + payload.length);
    return b;
  }

  private useDoorbellResolution(): boolean {
    switch (this.model) {
      case "WYZEDB3": case "WVOD1": case "HL_WCO2": case "WYZEC1": return true;
    }
    return false;
  }

  /**
   * Decode an inbound UDP datagram into its DTLS-record bytes, transparently
   * across IOTC and CC51 transports, auto-replying to keepalives. Returns null
   * for keepalives / non-data / wrong-channel packets.
   */
  private decodeInbound(msg: Buffer): { channel: number; records: Buffer } | null {
    if (this.isCC51) {
      if (msg.length < 12 || msg.subarray(0, 2).toString("binary") !== MAGIC_CC51) return null;
      const cmd = msg.readUInt16LE(4);
      if (cmd === CMD_KEEPALIVE_CC51) {
        if (msg.length >= KEEPALIVE_SIZE_CC51) this.udpSendRaw(this.msgKeepaliveCC51()).catch(() => {});
        return null;
      }
      if (cmd === CMD_DTLS_CC51 && msg.length >= HEADER_SIZE_CC51 + AUTH_SIZE_CC51) {
        const ch = msg.readUInt16LE(12) >> 8;
        return { channel: ch, records: msg.subarray(HEADER_SIZE_CC51, msg.length - AUTH_SIZE_CC51) };
      }
      return null;
    }
    const d = reverseTransCodeBlob(msg);
    if (d.length < 16) return null;
    const cmd = d.readUInt16LE(8);
    if (cmd === 0x0428 && d.length > 24) { this.udpSend(this.msgKeepaliveAck(d)).catch(() => {}); return null; }
    if (cmd === 0x0408 && d.length > 28) return { channel: d[14]!, records: d.subarray(28) };
    return null;
  }

  private msgKeepaliveAck(inc: Buffer): Buffer {
    const b = Buffer.alloc(24); b[0] = 0x04; b[1] = 0x02; b[2] = 0x1a; b[3] = 0x0a;
    b.writeUInt16LE(8, 4); b.writeUInt16LE(0x0427, 8); b.writeUInt16LE(0x0021, 10);
    if (inc.length > 24) inc.copy(b, 16, 16, 24); return b;
  }

  // ─── Low-level helpers ────────────────────────────────────────

  private udpSend(data: Buffer): Promise<void> {
    // IOTC frames are TransCode-obfuscated; CC51 frames go raw on the wire.
    return this.isCC51 ? this.udpSendRaw(data) : this.udpSendRaw(transCodeBlob(data));
  }

  private udpSendRaw(data: Buffer): Promise<void> {
    return new Promise((r, j) => { this.socket!.send(data, this.remotePort, this.host, e => e ? j(e) : r()); });
  }

  private writeAndWait(data: Buffer, matchFn: (d: Buffer) => boolean, ms = 5000, label = "handshake"): Promise<Buffer> {
    return new Promise((res, rej) => {
      // rxFromHost: any UDP seen from the camera IP (reachability signal).
      // rxUnmatched: packets that arrived but did not match the expected
      // reply (protocol/firmware signal). These two counters let a single
      // failed log distinguish "camera never answered" from "answered but
      // the reply shape was unexpected".
      let rxFromHost = 0; let rxUnmatched = 0; let firstReplyLogged = false;
      const dl = Date.now() + ms;
      const iv = setInterval(() => {
        if (Date.now() > dl) {
          cl();
          rej(new Error(`${label} timeout after ${ms}ms — rxFromCamera=${rxFromHost} unmatched=${rxUnmatched} (target=${this.host}:${this.remotePort})`));
          return;
        }
        this.udpSend(data).catch(() => {});
      }, 1000);
      const onMsg = (msg: Buffer, ri: dgram.RemoteInfo) => {
        if (ri.address !== this.host) return;
        this.remotePort = ri.port;
        rxFromHost++;
        if (!firstReplyLogged) { firstReplyLogged = true; this.log(`[Wyze] ${label}: first UDP reply from ${ri.address}:${ri.port} (${msg.length}B)`); }
        const d = reverseTransCodeBlob(msg);
        if (matchFn(d)) { cl(); res(d); } else { rxUnmatched++; }
      };
      const cl = () => { clearInterval(iv); this.socket!.removeListener("message", onMsg); };
      this.socket!.on("message", onMsg); this.udpSend(data).catch(() => {});
    });
  }

  private sendPeriodicAck(): void {
    this.ackFlags = (this.ackFlags + 1) & 0xFFFF;
    const ack = Buffer.alloc(24); ack.writeUInt16LE(0x0009, 0); ack.writeUInt16LE(0x000c, 2);
    ack.writeUInt32LE(this.ackAvSeq, 4); this.ackAvSeq = (this.ackAvSeq + 1) >>> 0;
    ack.writeUInt16LE(this.rxSeqStart, 8); ack.writeUInt16LE(this.rxSeqEnd, 10);
    if (this.rxSeqInit) this.rxSeqStart = this.rxSeqEnd;
    ack.writeUInt16LE(this.ackFlags, 12); ack.writeUInt32LE((this.ackFlags << 16) >>> 0, 16); ack.writeUInt16LE(Date.now() & 0xffff, 20);
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
