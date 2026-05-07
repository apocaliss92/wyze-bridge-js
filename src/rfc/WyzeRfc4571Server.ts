/**
 * Wyze RFC 4571 TCP Server.
 *
 * Wraps a WyzeDTLSConn into a TCP server that speaks RFC 4571 framed RTP.
 * Scrypted (or any RFC 4571 consumer) connects via TCP, receives SDP, then
 * gets a packetized H264/H265 + audio stream.
 *
 * Usage:
 *   const server = await createWyzeRfc4571Server({ camera, cloud, logger });
 *   // server.host, server.port, server.sdp  → give to Scrypted
 *   // server.close() when done
 */

import * as net from "node:net";
import { WyzeDTLSConn, type WyzeDTLSConnOptions } from "../tutk/dtls/WyzeDTLSConn.js";
import { isVideoCodec, isAudioCodec, CodecH264, CodecH265, CodecPCMU, CodecPCMA, CodecPCML, CodecAACADTS, CodecAACRaw, CodecAACLATM, CodecAACAlt, CodecOpus } from "../tutk/codec.js";
import type { Packet } from "../tutk/frame.js";
import type { WyzeCamera } from "../cloud/types.js";

// ─── Minimal RFC 4571 Muxer ─────────────────────────────────────

type VideoType = "H264" | "H265";

interface RtpWriter {
  payloadType: number;
  seq: number;
  ssrc: number;
  timestamp: number;
}

function createRtpWriter(pt: number): RtpWriter {
  return { payloadType: pt, seq: 0, ssrc: (Math.random() * 0xffffffff) >>> 0, timestamp: 0 };
}

function buildRtpPacket(w: RtpWriter, marker: boolean, ts: number, payload: Buffer): Buffer {
  const hdr = Buffer.alloc(12);
  hdr[0] = 0x80; // V=2
  hdr[1] = (marker ? 0x80 : 0) | (w.payloadType & 0x7f);
  hdr.writeUInt16BE(w.seq & 0xffff, 2); w.seq++;
  hdr.writeUInt32BE(ts >>> 0, 4);
  hdr.writeUInt32BE(w.ssrc, 8);
  return Buffer.concat([hdr, payload]);
}

function splitAnnexBToNals(data: Buffer): Buffer[] {
  const nals: Buffer[] = [];
  let i = 0;
  const isStart = (p: number) => {
    if (p + 3 <= data.length && data[p] === 0 && data[p + 1] === 0) {
      if (data[p + 2] === 1) return 3;
      if (p + 4 <= data.length && data[p + 2] === 0 && data[p + 3] === 1) return 4;
    }
    return 0;
  };
  while (i < data.length) { const s = isStart(i); if (s) break; i++; }
  while (i < data.length) {
    const s = isStart(i); if (!s) { i++; continue; }
    const start = i + s; let j = start;
    while (j < data.length) { if (isStart(j)) break; j++; }
    if (start < j) nals.push(data.subarray(start, j));
    i = j;
  }

  // If no Annex-B start codes were found, the payload may be a raw NAL unit
  // (some TUTK firmware versions omit start codes). Treat the entire buffer
  // as a single NAL if it looks like valid NAL data (forbidden_zero_bit == 0).
  if (nals.length === 0 && data.length > 0 && (data[0]! & 0x80) === 0) {
    nals.push(data);
  }

  return nals;
}

/**
 * Strip VUI parameters from an H.264 SPS NAL to produce a clean SPS
 * suitable for SDP sprop-parameter-sets.
 *
 * The Wyze camera's SPS has trailing bytes beyond the core parameters that
 * corrupt the VUI/HRD section (garbage colour_primaries, cpb_cnt, etc.).
 * The Scrypted prebuffer plugin parses the SPS from the SDP and rejects
 * streams with invalid VUI values, killing the session immediately.
 *
 * Fix: rebuild the SPS with vui_parameters_present_flag=0 and proper RBSP
 * trailing bits. VUI is optional and not needed for decoding.
 */
function stripSpsVui(sps: Buffer): Buffer {
  // H.264 SPS bit-level parsing (minimal, just enough to find vui_parameters_present_flag)
  // NAL header (1 byte) + profile_idc(8) + constraint_set_flags(8) + level_idc(8) = 4 bytes fixed
  if (sps.length < 4) return sps;

  // Instead of complex bit parsing, rebuild a minimal SPS from the known fields.
  // We know the Wyze camera sends: profile 77 (Main), level 41, 1920x1080.
  // Build a clean SPS with the same parameters but no VUI.
  const profile = sps[1]!;
  const constraints = sps[2]!;
  const level = sps[3]!;

  // Minimal SPS NAL: nal_header + profile + constraints + level + sps_id(0) +
  // log2_max_frame_num(4) + pic_order_cnt_type(0) + log2_max_pic_order_cnt_lsb(10) +
  // max_num_ref_frames(1) + gaps(0) + width(120) + height(68) + frame_mbs_only(1) +
  // direct_8x8(1) + frame_cropping(1,0,0,0,4) + vui_present(0) + rbsp_stop_bit
  //
  // Rather than bit-packing manually, use the original SPS bytes up to just before
  // the vui_parameters_present_flag, then clear that flag.
  //
  // Simpler approach: use the raw SPS but cap it at a safe length.
  // The core SPS for this camera (Main profile, no scaling matrices) is ~15-20 bytes.
  // VUI starts after frame_cropping. We'll parse byte-by-byte to find the boundary.

  // Actually, the simplest robust fix: parse only the Exp-Golomb fields we need,
  // then output a fresh, minimal bitstream.
  try {
    return buildCleanSps(sps);
  } catch {
    // If clean rebuild fails, return original (better than nothing)
    return sps;
  }
}

/** Minimal bitstream reader for Exp-Golomb coded H.264 SPS fields. */
class BitReader {
  private buf: Buffer;
  private pos = 0; // bit position
  constructor(buf: Buffer) { this.buf = buf; }
  get bitsLeft() { return this.buf.length * 8 - this.pos; }
  readBit(): number {
    if (this.pos >= this.buf.length * 8) throw new Error("EOF");
    const byte = this.buf[this.pos >> 3]!;
    const bit = (byte >> (7 - (this.pos & 7))) & 1;
    this.pos++;
    return bit;
  }
  readBits(n: number): number {
    let v = 0;
    for (let i = 0; i < n; i++) v = (v << 1) | this.readBit();
    return v;
  }
  readUE(): number { // unsigned Exp-Golomb
    let zeros = 0;
    while (this.readBit() === 0) zeros++;
    if (zeros === 0) return 0;
    return (1 << zeros) - 1 + this.readBits(zeros);
  }
  readSE(): number { // signed Exp-Golomb
    const v = this.readUE();
    return (v & 1) ? ((v + 1) >> 1) : -(v >> 1);
  }
}

class BitWriter {
  private bytes: number[] = [];
  private cur = 0;
  private bits = 0;
  writeBit(b: number): void {
    this.cur = (this.cur << 1) | (b & 1);
    this.bits++;
    if (this.bits === 8) { this.bytes.push(this.cur); this.cur = 0; this.bits = 0; }
  }
  writeBits(v: number, n: number): void {
    for (let i = n - 1; i >= 0; i--) this.writeBit((v >> i) & 1);
  }
  writeUE(v: number): void {
    const val = v + 1;
    const len = 32 - Math.clz32(val);
    for (let i = 0; i < len - 1; i++) this.writeBit(0);
    this.writeBits(val, len);
  }
  writeSE(v: number): void {
    this.writeUE(v <= 0 ? (-v * 2) : (v * 2 - 1));
  }
  /** Write RBSP trailing bits (1 + alignment zeros) */
  writeTrailing(): void {
    this.writeBit(1);
    while (this.bits !== 0) this.writeBit(0);
  }
  toBuffer(): Buffer {
    const out = [...this.bytes];
    if (this.bits > 0) out.push(this.cur << (8 - this.bits));
    return Buffer.from(out);
  }
}

function buildCleanSps(origSps: Buffer): Buffer {
  const r = new BitReader(origSps);
  const w = new BitWriter();

  // forbidden_zero_bit + nal_ref_idc + nal_unit_type
  const nalHeader = r.readBits(8);
  w.writeBits(nalHeader, 8);

  // profile_idc, constraint_set0..5_flags + reserved, level_idc
  const profile = r.readBits(8); w.writeBits(profile, 8);
  const constraints = r.readBits(8); w.writeBits(constraints, 8);
  const level = r.readBits(8); w.writeBits(level, 8);

  // seq_parameter_set_id
  const spsId = r.readUE(); w.writeUE(spsId);

  // High profiles have extra fields
  if (profile === 100 || profile === 110 || profile === 122 || profile === 244 ||
      profile === 44 || profile === 83 || profile === 86 || profile === 118 || profile === 128) {
    const chromaFormat = r.readUE(); w.writeUE(chromaFormat);
    if (chromaFormat === 3) { const sep = r.readBit(); w.writeBit(sep); }
    const bitDepthLuma = r.readUE(); w.writeUE(bitDepthLuma);
    const bitDepthChroma = r.readUE(); w.writeUE(bitDepthChroma);
    const qpPrime = r.readBit(); w.writeBit(qpPrime);
    const seqScaling = r.readBit(); w.writeBit(seqScaling);
    if (seqScaling) {
      const cnt = chromaFormat !== 3 ? 8 : 12;
      for (let i = 0; i < cnt; i++) {
        const present = r.readBit(); w.writeBit(present);
        if (present) {
          // Skip scaling list (complex) — just return original SPS
          return origSps;
        }
      }
    }
  }

  // log2_max_frame_num_minus4
  const log2MaxFn = r.readUE(); w.writeUE(log2MaxFn);
  // pic_order_cnt_type
  const pocType = r.readUE(); w.writeUE(pocType);
  if (pocType === 0) {
    const log2MaxPoc = r.readUE(); w.writeUE(log2MaxPoc);
  } else if (pocType === 1) {
    const delta = r.readBit(); w.writeBit(delta);
    const offNonRef = r.readSE(); w.writeSE(offNonRef);
    const offTop = r.readSE(); w.writeSE(offTop);
    const numRefCycles = r.readUE(); w.writeUE(numRefCycles);
    for (let i = 0; i < numRefCycles; i++) { const o = r.readSE(); w.writeSE(o); }
  }
  // max_num_ref_frames
  const maxRef = r.readUE(); w.writeUE(maxRef);
  // gaps_in_frame_num_value_allowed_flag
  const gaps = r.readBit(); w.writeBit(gaps);
  // pic_width_in_mbs_minus1, pic_height_in_map_units_minus1
  const width = r.readUE(); w.writeUE(width);
  const height = r.readUE(); w.writeUE(height);
  // frame_mbs_only_flag
  const frameMbs = r.readBit(); w.writeBit(frameMbs);
  if (!frameMbs) { const mbAdaptive = r.readBit(); w.writeBit(mbAdaptive); }
  // direct_8x8_inference_flag
  const direct8x8 = r.readBit(); w.writeBit(direct8x8);
  // frame_cropping_flag
  const cropping = r.readBit(); w.writeBit(cropping);
  if (cropping) {
    for (let i = 0; i < 4; i++) { const c = r.readUE(); w.writeUE(c); }
  }

  // HERE: instead of copying vui_parameters_present_flag and VUI data,
  // write vui_parameters_present_flag = 0
  w.writeBit(0); // vui_parameters_present_flag = 0

  // RBSP trailing bits
  w.writeTrailing();

  return w.toBuffer();
}

function extractH264Params(au: Buffer): { sps?: Buffer; pps?: Buffer } {
  const nals = splitAnnexBToNals(au);
  let sps: Buffer | undefined, pps: Buffer | undefined;
  for (const n of nals) {
    if (n.length < 1) continue;
    const t = n[0]! & 0x1f;
    // SPS must be at least 4 bytes (NAL header + profile_idc + constraints + level_idc)
    if (t === 7 && n.length >= 4) sps = stripSpsVui(n);
    if (t === 8) pps = n;
  }
  return { sps, pps };
}

function extractH265Params(au: Buffer): { vps?: Buffer; sps?: Buffer; pps?: Buffer } {
  const nals = splitAnnexBToNals(au);
  let vps: Buffer | undefined, sps: Buffer | undefined, pps: Buffer | undefined;
  for (const n of nals) { if (n.length < 2) continue; const t = (n[0]! >> 1) & 0x3f; if (t === 32) vps = n; if (t === 33) sps = n; if (t === 34) pps = n; }
  return { vps, sps, pps };
}

// ─── Audio codec → RTP mapping ──────────────────────────────────

interface AudioRtpInfo {
  payloadType: number;     // RTP payload type (0=PCMU, 8=PCMA, dynamic for others)
  encodingName: string;    // SDP rtpmap encoding name
  clockRate: number;       // SDP clock rate
  channels: number;        // Audio channels
  fmtp?: string;           // Optional fmtp line
}

function getAudioRtpInfo(codecId: number, sampleRate: number, channels: number): AudioRtpInfo | null {
  switch (codecId) {
    case CodecPCMU:
      // G.711 mu-law: static PT 0, always 8000Hz/1ch in standard RTP
      // If camera sends at higher rate, use dynamic PT
      if (sampleRate === 8000 && channels === 1) {
        return { payloadType: 0, encodingName: "PCMU", clockRate: 8000, channels: 1 };
      }
      return { payloadType: 97, encodingName: "PCMU", clockRate: sampleRate, channels };
    case CodecPCMA:
      if (sampleRate === 8000 && channels === 1) {
        return { payloadType: 8, encodingName: "PCMA", clockRate: 8000, channels: 1 };
      }
      return { payloadType: 97, encodingName: "PCMA", clockRate: sampleRate, channels };
    case CodecPCML:
      // Raw PCM signed 16-bit little-endian → L16 in RTP (big-endian)
      return { payloadType: 97, encodingName: "L16", clockRate: sampleRate, channels };
    case CodecAACADTS: case CodecAACRaw: case CodecAACLATM: case CodecAACAlt:
      return { payloadType: 97, encodingName: "MPEG4-GENERIC", clockRate: sampleRate, channels,
        fmtp: `streamtype=5;profile-level-id=1;mode=AAC-hbr;sizelength=13;indexlength=3;indexdeltalength=3` };
    case CodecOpus:
      return { payloadType: 97, encodingName: "opus", clockRate: 48000, channels: 2 };
    default:
      return null;
  }
}

// ─── SDP builders ───────────────────────────────────────────────

function buildVideoSdp(videoType: VideoType, videoPT: number, sps?: Buffer, pps?: Buffer, vps?: Buffer): string {
  let sdp = `m=video 0 RTP/AVP ${videoPT}\r\nc=IN IP4 0.0.0.0\r\n`;
  sdp += `a=rtpmap:${videoPT} ${videoType}/90000\r\n`;
  if (videoType === "H264" && sps && pps) {
    const pli = sps.length >= 4 ? sps.subarray(1, 4).toString("hex") : "";
    sdp += `a=fmtp:${videoPT} packetization-mode=1;${pli ? `profile-level-id=${pli};` : ""}sprop-parameter-sets=${sps.toString("base64")},${pps.toString("base64")}\r\n`;
  }
  if (videoType === "H265" && vps && sps && pps) {
    sdp += `a=fmtp:${videoPT} sprop-vps=${vps.toString("base64")};sprop-sps=${sps.toString("base64")};sprop-pps=${pps.toString("base64")}\r\n`;
  }
  return sdp;
}

function buildAudioSdp(info: AudioRtpInfo): string {
  let sdp = `m=audio 0 RTP/AVP ${info.payloadType}\r\nc=IN IP4 0.0.0.0\r\n`;
  // Always include rtpmap (even for static PTs, for clarity)
  sdp += `a=rtpmap:${info.payloadType} ${info.encodingName}/${info.clockRate}${info.channels > 1 ? `/${info.channels}` : ""}\r\n`;
  if (info.fmtp) {
    sdp += `a=fmtp:${info.payloadType} ${info.fmtp}\r\n`;
  }
  return sdp;
}

function buildFullSdp(videoSdp: string, audioSdp?: string): string {
  let sdp = "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=Wyze\r\nt=0 0\r\n";
  sdp += videoSdp;
  if (audioSdp) sdp += audioSdp;
  return sdp;
}

// ─── Video packetization ────────────────────────────────────────

function packetizeH264Nal(nal: Buffer, w: RtpWriter, ts: number, marker: boolean, maxPayload: number): Buffer[] {
  if (nal.length <= maxPayload) return [buildRtpPacket(w, marker, ts, nal)];
  // FU-A fragmentation
  const type = nal[0]! & 0x1f;
  const nri = nal[0]! & 0x60;
  const pkts: Buffer[] = [];
  let off = 1;
  while (off < nal.length) {
    const end = Math.min(off + maxPayload - 2, nal.length);
    const isFirst = off === 1, isLast = end === nal.length;
    const fuInd = (nri | 28) & 0xff; // FU indicator: NRI + type=28
    const fuHdr = ((isFirst ? 0x80 : 0) | (isLast ? 0x40 : 0) | type) & 0xff;
    const frag = Buffer.concat([Buffer.from([fuInd, fuHdr]), nal.subarray(off, end)]);
    pkts.push(buildRtpPacket(w, isLast && marker, ts, frag));
    off = end;
  }
  return pkts;
}

function packetizeH265Nal(nal: Buffer, w: RtpWriter, ts: number, marker: boolean, maxPayload: number): Buffer[] {
  if (nal.length <= maxPayload) return [buildRtpPacket(w, marker, ts, nal)];
  if (nal.length < 2) return [];
  const type = (nal[0]! >> 1) & 0x3f;
  const pkts: Buffer[] = [];
  let off = 2;
  while (off < nal.length) {
    const end = Math.min(off + maxPayload - 3, nal.length);
    const isFirst = off === 2, isLast = end === nal.length;
    const fuHdr = Buffer.alloc(3);
    fuHdr[0] = (nal[0]! & 0x81) | (49 << 1); // FU type = 49
    fuHdr[1] = nal[1]!;
    fuHdr[2] = ((isFirst ? 0x80 : 0) | (isLast ? 0x40 : 0) | type) & 0xff;
    const frag = Buffer.concat([fuHdr, nal.subarray(off, end)]);
    pkts.push(buildRtpPacket(w, isLast && marker, ts, frag));
    off = end;
  }
  return pkts;
}

// ─── PCM byte-swap (L16 LE → L16 BE for RTP) ───────────────────

function pcmLEToBE(buf: Buffer): Buffer {
  const out = Buffer.allocUnsafe(buf.length);
  for (let i = 0; i < buf.length - 1; i += 2) {
    out[i] = buf[i + 1]!;
    out[i + 1] = buf[i]!;
  }
  return out;
}

// ─── RFC 4571 framing ───────────────────────────────────────────

function writeRfc4571(socket: net.Socket, rtpPacket: Buffer): void {
  if (socket.destroyed || !socket.writable) return;
  const hdr = Buffer.alloc(2);
  hdr.writeUInt16BE(rtpPacket.length, 0);
  try { socket.write(Buffer.concat([hdr, rtpPacket])); } catch {}
}

// ─── Server ─────────────────────────────────────────────────────

export interface WyzeRfc4571ServerOptions {
  camera: WyzeCamera;
  verbose?: boolean;
  logger?: Console;
  host?: string;
  videoPayloadType?: number;
  frameSize?: number; // 0=1080p, 1=360p, 2=720p, 3=2K
  bitrate?: number;   // 0xF0=max, 0x3C=SD
}

export interface WyzeRfc4571Server {
  host: string;
  port: number;
  sdp: string;
  videoType: VideoType;
  /** The underlying P2P connection — use for camera commands, snapshots, etc. */
  connection: import("../tutk/dtls/WyzeDTLSConn.js").WyzeDTLSConn;
  close: () => Promise<void>;
  /** Number of currently connected TCP clients. */
  readonly clientCount: number;
  /** Register a callback for when a client disconnects (receives remaining client count). */
  onClientDisconnect: (cb: (remainingClients: number) => void) => void;
  /**
   * Register a callback for when the server is closed internally (e.g. by the
   * P2P health monitor detecting a dead stream). Plugins should use this to
   * release their server reference so the next stream request creates a new one.
   */
  onServerClose: (cb: (reason: string) => void) => void;
}

export async function createWyzeRfc4571Server(
  opts: WyzeRfc4571ServerOptions,
): Promise<WyzeRfc4571Server> {
  const {
    camera,
    verbose = false,
    logger = console,
    host = "127.0.0.1",
    videoPayloadType = 96,
    frameSize = 0,
    bitrate = 0xF0,
  } = opts;

  const maxPayload = 1200;
  const videoWriter = createRtpWriter(videoPayloadType);
  const clients = new Set<net.Socket>();
  let sdp = "";
  let videoType: VideoType = "H264";
  let videoSdpPart = "";
  let audioSdpPart = "";
  let paramSetsExtracted = false;
  let audioDetected = false;
  let audioWriter: RtpWriter | null = null;
  let audioCodecId = 0;
  let closed = false;

  // ─── Stream health monitoring ──────────────────────────────
  let totalPackets = 0;
  let lastPacketAt = 0;
  let healthTimer: ReturnType<typeof setInterval> | undefined;

  // ─── P2P Connection ─────────────────────────────────────────

  const conn = new WyzeDTLSConn({
    host: camera.ip,
    uid: camera.p2pId,
    enr: camera.enr,
    mac: camera.mac,
    model: camera.productModel,
    verbose,
    logger,
  });

  logger.log?.(`[wyze-rfc4571] Connecting to ${camera.nickname} (${camera.ip})...`);
  await conn.connect();
  // conn.host may have been updated by broadcast discovery if the stored IP was stale
  if ((conn as any).host !== camera.ip) {
    logger.log?.(`[wyze-rfc4571] Actual IP: ${(conn as any).host}`);
    camera.ip = (conn as any).host;
  }
  logger.log?.(`[wyze-rfc4571] Connected, starting video...`);

  await conn.startVideo(frameSize, bitrate);
  await conn.startAudio();

  const rebuildSdp = () => {
    if (videoSdpPart) {
      sdp = buildFullSdp(videoSdpPart, audioSdpPart || undefined);
    }
  };

  // ─── Frame handler → RTP muxer ─────────────────────────────

  conn.onPacket((pkt: Packet) => {
    if (closed) return;
    totalPackets++;
    lastPacketAt = Date.now();

    if (isVideoCodec(pkt.codec)) {
      const isH265 = pkt.codec === CodecH265;
      videoType = isH265 ? "H265" : "H264";

      // Extract param sets from first keyframe for SDP
      if (pkt.isKeyframe && !paramSetsExtracted) {
        if (isH265) {
          const { vps, sps, pps } = extractH265Params(pkt.payload);
          if (vps && sps && pps) {
            videoSdpPart = buildVideoSdp("H265", videoPayloadType, sps, pps, vps);
            paramSetsExtracted = true;
            rebuildSdp();
          }
        } else {
          const { sps, pps } = extractH264Params(pkt.payload);
          if (sps && pps) {
            videoSdpPart = buildVideoSdp("H264", videoPayloadType, sps, pps);
            paramSetsExtracted = true;
            rebuildSdp();
          }
        }
      }

      if (clients.size === 0) return;

      // Packetize NALs
      const nals = splitAnnexBToNals(pkt.payload);
      const ts = pkt.timestamp;

      for (let i = 0; i < nals.length; i++) {
        const nal = nals[i]!;
        const isLastNal = i === nals.length - 1;
        const rtpPkts = isH265
          ? packetizeH265Nal(nal, videoWriter, ts, isLastNal, maxPayload)
          : packetizeH264Nal(nal, videoWriter, ts, isLastNal, maxPayload);
        for (const rtp of rtpPkts) {
          for (const c of clients) writeRfc4571(c, rtp);
        }
      }
    } else if (isAudioCodec(pkt.codec)) {
      // Detect audio codec from first audio packet
      if (!audioDetected) {
        audioDetected = true;
        audioCodecId = pkt.codec;
        const info = getAudioRtpInfo(pkt.codec, pkt.sampleRate || 8000, pkt.channels || 1);
        if (info) {
          audioWriter = createRtpWriter(info.payloadType);
          audioSdpPart = buildAudioSdp(info);
          rebuildSdp();
          logger.log?.(`[wyze-rfc4571] Audio detected: ${info.encodingName}/${info.clockRate}`);
        } else {
          logger.log?.(`[wyze-rfc4571] Unsupported audio codec: 0x${pkt.codec.toString(16)}`);
        }
      }

      if (!audioWriter || clients.size === 0) return;

      // For PCML (raw PCM LE), byte-swap to big-endian for L16 RTP
      const payload = audioCodecId === CodecPCML ? pcmLEToBE(pkt.payload) : pkt.payload;
      const rtp = buildRtpPacket(audioWriter, true, pkt.timestamp, payload);
      for (const c of clients) writeRfc4571(c, rtp);
    }
  });

  // ─── TCP server ─────────────────────────────────────────────

  const disconnectCallbacks: Array<(remaining: number) => void> = [];
  const serverCloseCallbacks: Array<(reason: string) => void> = [];

  const server = net.createServer((socket) => {
    if (closed) { socket.destroy(); return; }
    logger.log?.(`[wyze-rfc4571] Client connected from ${socket.remoteAddress}`);
    clients.add(socket);
    const cleanup = () => {
      clients.delete(socket);
      try { socket.destroy(); } catch {}
      for (const cb of disconnectCallbacks) cb(clients.size);
    };
    socket.on("error", cleanup);
    socket.on("close", cleanup);
  });

  await new Promise<void>((resolve, reject) => {
    server.listen(0, host, () => resolve());
    server.on("error", reject);
  });

  const addr = server.address() as net.AddressInfo;
  logger.log?.(`[wyze-rfc4571] Listening on ${addr.address}:${addr.port}`);

  // Wait for SDP (first keyframe + optional audio, with timeout)
  if (!paramSetsExtracted) {
    logger.log?.(`[wyze-rfc4571] Waiting for first keyframe...`);
    await new Promise<void>((resolve) => {
      const check = setInterval(() => {
        if (closed) { clearInterval(check); resolve(); return; }
        // Resolve once we have video params; audio is best-effort
        if (paramSetsExtracted) { clearInterval(check); resolve(); }
      }, 100);
      setTimeout(() => { clearInterval(check); resolve(); }, 10000);
    });
  }

  // Give audio a short grace period to be detected if video is ready
  if (paramSetsExtracted && !audioDetected) {
    await new Promise<void>((resolve) => {
      const check = setInterval(() => {
        if (audioDetected || closed) { clearInterval(check); resolve(); }
      }, 50);
      setTimeout(() => { clearInterval(check); resolve(); }, 2000);
    });
  }

  // ─── P2P health monitor: detect dead connection ─────────────
  // If no packets arrive for 10s, the P2P connection is likely dead.
  // Log diagnostics and close so the plugin can reconnect.
  lastPacketAt = Date.now();
  healthTimer = setInterval(() => {
    if (closed) { clearInterval(healthTimer); return; }
    const silenceMs = Date.now() - lastPacketAt;
    if (silenceMs > 10_000) {
      const reason = `P2P stream dead: no packets for ${(silenceMs / 1000).toFixed(1)}s (totalPackets=${totalPackets} clients=${clients.size})`;
      logger.log?.(`[wyze-rfc4571] ${reason} — closing connection`);
      clearInterval(healthTimer);
      closeFnWithReason(reason).catch(() => {});
    }
  }, 3_000);

  const closeFnWithReason = async (reason: string) => {
    if (closed) return;
    closed = true;
    if (healthTimer) clearInterval(healthTimer);
    for (const c of clients) { try { c.destroy(); } catch {} }
    clients.clear();
    server.close();
    conn.close();
    logger.log?.(`[wyze-rfc4571] Closed reason="${reason}" totalPackets=${totalPackets}`);
    // Notify plugins so they can release stale server refs and reconnect.
    for (const cb of serverCloseCallbacks) {
      try { cb(reason); } catch {}
    }
  };

  const closeFn = async () => closeFnWithReason("external close");

  return {
    host: addr.address,
    port: addr.port,
    sdp,
    videoType,
    connection: conn,
    close: closeFn,
    get clientCount() { return clients.size; },
    onClientDisconnect: (cb: (remaining: number) => void) => { disconnectCallbacks.push(cb); },
    onServerClose: (cb: (reason: string) => void) => { serverCloseCallbacks.push(cb); },
  };
}
