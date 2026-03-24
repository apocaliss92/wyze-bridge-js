/**
 * TUTK AV frame parser — reassembles multi-packet frames.
 * Ported from go2rtc/pkg/tutk/frame.go
 */

import { isVideoCodec, isAudioCodec, getSampleRate, getChannels } from "./codec.js";

// Frame types
export const FrameTypeStart = 0x08;
export const FrameTypeStartAlt = 0x09;
export const FrameTypeCont = 0x00;
export const FrameTypeContAlt = 0x04;
export const FrameTypeEndSingle = 0x01;
export const FrameTypeEndMulti = 0x05;
export const FrameTypeEndExt = 0x0d;

// Channel types
export const ChannelIVideo = 0x05;
export const ChannelAudio = 0x03;
export const ChannelPVideo = 0x07;

const FRAME_INFO_SIZE = 40;
const TS_WRAP_PERIOD = 1_000_000;

// ─── Types ──────────────────────────────────────────────────────

export interface FrameInfo {
  codecId: number;
  flags: number;
  camIndex: number;
  onlineNum: number;
  fps: number;
  resTier: number;
  bitrate: number;
  timestamp: number;
  sessionId: number;
  payloadSize: number;
  frameNo: number;
}

export interface Packet {
  channel: number;
  codec: number;
  timestamp: number;
  payload: Buffer;
  isKeyframe: boolean;
  frameNo: number;
  sampleRate: number;
  channels: number;
}

export interface PacketHeader {
  channel: number;
  frameType: number;
  headerSize: number;
  frameNo: number;
  pktIdx: number;
  pktTotal: number;
  payloadSize: number;
  hasFrameInfo: boolean;
}

// ─── Parsers ────────────────────────────────────────────────────

export function parseFrameInfo(data: Buffer): FrameInfo | null {
  if (data.length < FRAME_INFO_SIZE) return null;
  const off = data.length - FRAME_INFO_SIZE;
  return {
    codecId: data[off]!,
    flags: data[off + 2]!,
    camIndex: data[off + 3]!,
    onlineNum: data[off + 4]!,
    fps: data[off + 5]!,
    resTier: data[off + 6]!,
    bitrate: data[off + 7]!,
    timestamp: data.readUInt32LE(off + 8),
    sessionId: data.readUInt32LE(off + 12),
    payloadSize: data.readUInt32LE(off + 16),
    frameNo: data.readUInt32LE(off + 20),
  };
}

export function parsePacketHeader(data: Buffer): PacketHeader | null {
  if (data.length < 28) return null;

  const frameType = data[1]!;
  const headerSize =
    frameType === FrameTypeStart || frameType === FrameTypeStartAlt || frameType === FrameTypeEndExt
      ? 36 : 28;

  if (data.length < headerSize) return null;

  const hdr: PacketHeader = {
    channel: data[0]!,
    frameType,
    headerSize,
    frameNo: 0,
    pktIdx: 0,
    pktTotal: 0,
    payloadSize: 0,
    hasFrameInfo: false,
  };

  if (headerSize === 28) {
    hdr.pktTotal = data.readUInt16LE(12);
    const marker = data.readUInt16LE(14);
    hdr.payloadSize = data.readUInt16LE(16);
    hdr.frameNo = data.readUInt32LE(24);
    if (marker === 0x0028 && (isEndFrame(frameType) || hdr.pktTotal === 1)) {
      hdr.hasFrameInfo = true;
      hdr.pktIdx = hdr.pktTotal > 0 ? hdr.pktTotal - 1 : 0;
    } else {
      hdr.pktIdx = marker;
    }
  } else {
    hdr.pktTotal = data.readUInt16LE(20);
    const marker = data.readUInt16LE(22);
    hdr.payloadSize = data.readUInt16LE(24);
    hdr.frameNo = data.readUInt32LE(32);
    if (marker === 0x0028 && (isEndFrame(frameType) || hdr.pktTotal === 1)) {
      hdr.hasFrameInfo = true;
      hdr.pktIdx = hdr.pktTotal > 0 ? hdr.pktTotal - 1 : 0;
    } else {
      hdr.pktIdx = marker;
    }
  }

  return hdr;
}

export function isStartFrame(t: number): boolean {
  return t === FrameTypeStart || t === FrameTypeStartAlt;
}

export function isEndFrame(t: number): boolean {
  return t === FrameTypeEndSingle || t === FrameTypeEndMulti || t === FrameTypeEndExt;
}

// ─── Frame Handler (reassembly) ─────────────────────────────────

interface ChannelState {
  frameNo: number;
  pktTotal: number;
  waitSeq: number;
  waitData: Buffer[];
  frameInfo: FrameInfo | null;
  hasStarted: boolean;
}

interface TsTracker {
  lastRawTS: number;
  accumUS: bigint;
  started: boolean;
}

export class FrameHandler {
  private channels = new Map<number, ChannelState>();
  private videoTS: TsTracker = { lastRawTS: 0, accumUS: 0n, started: false };
  private audioTS: TsTracker = { lastRawTS: 0, accumUS: 0n, started: false };
  private queue: Packet[] = [];
  private closed = false;
  private onPacket?: (pkt: Packet) => void;

  constructor(private verbose = false) {}

  /** Set callback for received packets. */
  setHandler(handler: (pkt: Packet) => void): void {
    this.onPacket = handler;
  }

  close(): void {
    this.closed = true;
  }

  /** Feed raw data from TUTK AV channel. */
  handle(data: Buffer): void {
    const hdr = parsePacketHeader(data);
    if (!hdr) return;

    const { payload, fi } = this.extractPayload(data, hdr.channel);
    if (!payload) return;

    if (hdr.channel === ChannelAudio) {
      this.handleAudio(payload, fi);
    } else if (hdr.channel === ChannelIVideo || hdr.channel === ChannelPVideo) {
      this.handleVideo(hdr, payload, fi);
    }
  }

  private extractPayload(data: Buffer, channel: number): { payload: Buffer | null; fi: FrameInfo | null } {
    if (data.length < 2) return { payload: null, fi: null };
    const frameType = data[1]!;

    let headerSize = 28;
    let fiSize = 0;

    switch (frameType) {
      case FrameTypeStart: case FrameTypeStartAlt: headerSize = 36; break;
      case FrameTypeEndSingle: case FrameTypeEndMulti: fiSize = FRAME_INFO_SIZE; break;
      case FrameTypeEndExt: headerSize = 36; fiSize = FRAME_INFO_SIZE; break;
    }

    if (frameType === FrameTypeStartAlt && data.length >= 22) {
      if (data.readUInt16LE(20) === 1) fiSize = FRAME_INFO_SIZE;
    }

    if (data.length < headerSize) return { payload: null, fi: null };

    if (fiSize === 0) return { payload: data.subarray(headerSize), fi: null };
    if (data.length < headerSize + fiSize) return { payload: data.subarray(headerSize), fi: null };

    const fi = parseFrameInfo(data);
    if (!fi) return { payload: data.subarray(headerSize), fi: null };

    const validCodec = (channel === ChannelIVideo || channel === ChannelPVideo)
      ? isVideoCodec(fi.codecId) : isAudioCodec(fi.codecId);

    if (validCodec) {
      return { payload: data.subarray(headerSize, data.length - fiSize), fi };
    }
    return { payload: data.subarray(headerSize), fi: null };
  }

  private handleVideo(hdr: PacketHeader, payload: Buffer, fi: FrameInfo | null): void {
    let cs = this.channels.get(hdr.channel);
    if (!cs) { cs = this.newChannelState(); this.channels.set(hdr.channel, cs); }

    if (hdr.frameNo !== cs.frameNo) {
      cs.frameNo = hdr.frameNo;
      cs.pktTotal = hdr.pktTotal;
      cs.waitSeq = 0;
      cs.waitData = [];
      cs.frameInfo = null;
      cs.hasStarted = false;
    }

    if (hdr.pktIdx !== cs.waitSeq) { this.resetChannel(cs); return; }
    if (cs.waitSeq === 0) cs.hasStarted = true;

    cs.waitData.push(payload);
    cs.waitSeq++;
    if (fi) cs.frameInfo = fi;

    if (cs.waitSeq !== cs.pktTotal || !cs.frameInfo) return;

    const raw = Buffer.concat(cs.waitData);
    const info = cs.frameInfo;
    this.resetChannel(cs);

    if (raw.length === 0) return;

    // Trim to the declared payload size from the FrameInfo trailer.
    // The concatenated packet payloads may contain trailing padding bytes
    // beyond the actual video data, which corrupt NAL unit parsing
    // (e.g., garbage SPS values, RangeError in h264-sps-parser).
    const fullPayload = info.payloadSize > 0 && info.payloadSize < raw.length
      ? raw.subarray(0, info.payloadSize)
      : raw;

    const accumUS = this.updateTS(this.videoTS, info.timestamp);
    const rtpTS = Number((accumUS * 90000n) / 1000000n);

    this.emit({
      channel: hdr.channel,
      payload: fullPayload,
      codec: info.codecId,
      timestamp: rtpTS,
      isKeyframe: info.flags === 0x01,
      frameNo: info.frameNo,
      sampleRate: 0,
      channels: 0,
    });
  }

  private handleAudio(payload: Buffer, fi: FrameInfo | null): void {
    if (!payload.length || !fi) return;

    const sampleRate = getSampleRate(fi.flags);
    const channels = getChannels(fi.flags);

    const accumUS = this.updateTS(this.audioTS, fi.timestamp);
    const rtpTS = Number((accumUS * BigInt(sampleRate)) / 1000000n);

    this.emit({
      channel: ChannelAudio,
      payload: Buffer.from(payload),
      codec: fi.codecId,
      timestamp: rtpTS,
      isKeyframe: false,
      frameNo: fi.frameNo,
      sampleRate,
      channels,
    });
  }

  private updateTS(tracker: TsTracker, rawTS: number): bigint {
    if (!tracker.started) {
      tracker.started = true;
      tracker.lastRawTS = rawTS;
      return 0n;
    }
    const delta = rawTS >= tracker.lastRawTS
      ? rawTS - tracker.lastRawTS
      : (TS_WRAP_PERIOD - tracker.lastRawTS) + rawTS;
    tracker.accumUS += BigInt(delta);
    tracker.lastRawTS = rawTS;
    return tracker.accumUS;
  }

  private emit(pkt: Packet): void {
    if (this.closed) return;
    this.onPacket?.(pkt);
  }

  private newChannelState(): ChannelState {
    return { frameNo: 0, pktTotal: 0, waitSeq: 0, waitData: [], frameInfo: null, hasStarted: false };
  }

  private resetChannel(cs: ChannelState): void {
    cs.frameNo = 0; cs.pktTotal = 0; cs.waitSeq = 0; cs.waitData = []; cs.frameInfo = null; cs.hasStarted = false;
  }
}
