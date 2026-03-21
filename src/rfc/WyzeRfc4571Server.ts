/**
 * Wyze RFC 4571 TCP Server.
 *
 * Wraps a WyzeDTLSConn into a TCP server that speaks RFC 4571 framed RTP.
 * Scrypted (or any RFC 4571 consumer) connects via TCP, receives SDP, then
 * gets a packetized H264/H265 + optional audio stream.
 *
 * Usage:
 *   const server = await createWyzeRfc4571Server({ camera, cloud, logger });
 *   // server.host, server.port, server.sdp  → give to Scrypted
 *   // server.close() when done
 */

import * as net from "node:net";
import { EventEmitter } from "node:events";
import { WyzeDTLSConn, type WyzeDTLSConnOptions } from "../tutk/dtls/WyzeDTLSConn.js";
import { isVideoCodec, isAudioCodec, CodecH264, CodecH265 } from "../tutk/codec.js";
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
  return nals;
}

function extractH264Params(au: Buffer): { sps?: Buffer; pps?: Buffer } {
  const nals = splitAnnexBToNals(au);
  let sps: Buffer | undefined, pps: Buffer | undefined;
  for (const n of nals) { const t = n[0]! & 0x1f; if (t === 7) sps = n; if (t === 8) pps = n; }
  return { sps, pps };
}

function extractH265Params(au: Buffer): { vps?: Buffer; sps?: Buffer; pps?: Buffer } {
  const nals = splitAnnexBToNals(au);
  let vps: Buffer | undefined, sps: Buffer | undefined, pps: Buffer | undefined;
  for (const n of nals) { if (n.length < 2) continue; const t = (n[0]! >> 1) & 0x3f; if (t === 32) vps = n; if (t === 33) sps = n; if (t === 34) pps = n; }
  return { vps, sps, pps };
}

function buildSdp(videoType: VideoType, videoPT: number, sps?: Buffer, pps?: Buffer, vps?: Buffer): string {
  let sdp = "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=Wyze\r\nt=0 0\r\n";
  sdp += `m=video 0 RTP/AVP ${videoPT}\r\nc=IN IP4 0.0.0.0\r\n`;
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
  let paramSetsExtracted = false;
  let closed = false;

  // ─── P2P Connection ─────────────────────────────────────────

  const conn = new WyzeDTLSConn({
    host: camera.ip,
    uid: camera.p2pId,
    enr: camera.enr,
    mac: camera.mac,
    model: camera.productModel,
    verbose,
  });

  logger.log?.(`[wyze-rfc4571] Connecting to ${camera.nickname} (${camera.ip})...`);
  await conn.connect();
  logger.log?.(`[wyze-rfc4571] Connected, starting video...`);

  await conn.startVideo(frameSize, bitrate);
  await conn.startAudio();

  // ─── Frame handler → RTP muxer ─────────────────────────────

  conn.onPacket((pkt: Packet) => {
    if (closed) return;

    if (isVideoCodec(pkt.codec)) {
      const isH265 = pkt.codec === CodecH265;
      videoType = isH265 ? "H265" : "H264";

      // Extract param sets from first keyframe for SDP (ALWAYS, even without clients)
      if (pkt.isKeyframe && !paramSetsExtracted) {
        if (isH265) {
          const { vps, sps, pps } = extractH265Params(pkt.payload);
          if (vps && sps && pps) {
            sdp = buildSdp("H265", videoPayloadType, sps, pps, vps);
            paramSetsExtracted = true;
          }
        } else {
          const { sps, pps } = extractH264Params(pkt.payload);
          if (sps && pps) {
            sdp = buildSdp("H264", videoPayloadType, sps, pps);
            paramSetsExtracted = true;
          }
        }
      }

      // Only send RTP to clients if there are any
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
    }
    // Audio: skip for now (PCM raw isn't standard RTP; could add PCMU/AAC later)
  });

  // ─── TCP server ─────────────────────────────────────────────

  const server = net.createServer((socket) => {
    if (closed) { socket.destroy(); return; }
    logger.log?.(`[wyze-rfc4571] Client connected from ${socket.remoteAddress}`);
    clients.add(socket);
    const cleanup = () => { clients.delete(socket); try { socket.destroy(); } catch {} };
    socket.on("error", cleanup);
    socket.on("close", cleanup);
  });

  await new Promise<void>((resolve, reject) => {
    server.listen(0, host, () => resolve());
    server.on("error", reject);
  });

  const addr = server.address() as net.AddressInfo;
  logger.log?.(`[wyze-rfc4571] Listening on ${addr.address}:${addr.port}`);

  // Wait for SDP (first keyframe)
  if (!paramSetsExtracted) {
    logger.log?.(`[wyze-rfc4571] Waiting for first keyframe...`);
    await new Promise<void>((resolve) => {
      const check = setInterval(() => {
        if (paramSetsExtracted || closed) { clearInterval(check); resolve(); }
      }, 100);
      setTimeout(() => { clearInterval(check); resolve(); }, 10000);
    });
  }

  const closeFn = async () => {
    if (closed) return;
    closed = true;
    for (const c of clients) { try { c.destroy(); } catch {} }
    clients.clear();
    server.close();
    conn.close();
    logger.log?.(`[wyze-rfc4571] Closed`);
  };

  return {
    host: addr.address,
    port: addr.port,
    sdp,
    videoType,
    connection: conn,
    close: closeFn,
  };
}
