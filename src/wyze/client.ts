/**
 * Wyze P2P camera client.
 * Ported from go2rtc/pkg/wyze/client.go
 *
 * Connects to a Wyze camera using the TUTK/DTLS P2P protocol.
 * Provides video/audio streaming and two-way audio support.
 *
 * NOTE: This is a partial implementation. The full TUTK session
 * negotiation (session0/16/25) and DTLS transport require additional
 * work. This client provides the high-level API and frame handling.
 */

import { EventEmitter } from "node:events";
import { calculateAuthKey } from "../tutk/dtls/auth.js";
import { FrameHandler, type Packet } from "../tutk/frame.js";
import { xxteaDecryptVar } from "../tutk/crypto.js";

export interface WyzeClientOptions {
  /** Camera local IP address. */
  host: string;
  /** Camera UID (P2P ID). */
  uid: string;
  /** ENR encryption key. */
  enr: string;
  /** Device MAC address. */
  mac: string;
  /** Camera model. */
  model: string;
  /** Enable DTLS (default: true). */
  dtls?: boolean;
  /** Enable verbose logging. */
  verbose?: boolean;
}

// Resolution constants
export const FrameSize1080P = 0;
export const FrameSize360P = 1;
export const FrameSize720P = 2;
export const FrameSize2K = 3;

// HL command IDs
const KCmdAuth = 10000;
const KCmdChallenge = 10001;
const KCmdChallengeResp = 10002;
const KCmdAuthResult = 10003;
const KCmdControlChannel = 10010;
const KCmdSetResolution = 10056;

// Media types
const MediaTypeVideo = 1;
const MediaTypeAudio = 2;
const MediaTypeReturnAudio = 3;

/** Challenge response status codes. */
const StatusDefault = 1;
const StatusENR16 = 3;
const StatusENR32 = 6;

export class WyzeClient extends EventEmitter {
  private options: WyzeClientOptions;
  private authKey: string;
  private frameHandler: FrameHandler;
  private _hasAudio = false;
  private _hasIntercom = false;
  private _closed = false;

  constructor(options: WyzeClientOptions) {
    super();
    this.options = options;
    this.authKey = calculateAuthKey(options.enr, options.mac).toString("ascii");
    this.frameHandler = new FrameHandler(options.verbose ?? false);

    // Forward parsed packets as events
    this.frameHandler.setHandler((pkt) => {
      this.emit("packet", pkt);
    });
  }

  get hasAudio(): boolean { return this._hasAudio; }
  get hasIntercom(): boolean { return this._hasIntercom; }

  /**
   * Build K10000 (auth request) packet.
   */
  buildAuthRequest(): Buffer {
    const json = Buffer.from('{"cameraInfo":{"audioEncoderList":[137,138,140]}}');
    const b = Buffer.alloc(16 + json.length);
    b.write("HL", 0, 2, "ascii");
    b[2] = 5;
    b.writeUInt16LE(KCmdAuth, 4);
    b.writeUInt16LE(json.length, 6);
    json.copy(b, 16);
    return b;
  }

  /**
   * Parse K10001 (challenge) response.
   */
  parseChallenge(data: Buffer): { challenge: Buffer; status: number } | null {
    if (data.length < 33 || data[0] !== 0x48 || data[1] !== 0x4c) return null;
    const cmdId = data.readUInt16LE(4);
    if (cmdId !== KCmdChallenge) return null;
    const status = data[16]!;
    const challenge = Buffer.alloc(16);
    data.copy(challenge, 0, 17, 33);
    return { challenge, status };
  }

  /**
   * Build K10002 (challenge response) packet.
   */
  buildChallengeResponse(challenge: Buffer, status: number): Buffer {
    const resp = this.generateChallengeResponse(challenge, status);
    const sessionId = Buffer.alloc(4);
    require("node:crypto").randomFillSync(sessionId);

    const b = Buffer.alloc(38);
    b.write("HL", 0, 2, "ascii");
    b[2] = 5;
    b.writeUInt16LE(KCmdChallengeResp, 4);
    b[6] = 22;
    resp.copy(b, 16, 0, 16);
    sessionId.copy(b, 32);
    b[36] = 1; // video enabled
    b[37] = 1; // audio enabled
    return b;
  }

  /**
   * Build K10010 (control channel) packet.
   */
  buildControlChannel(mediaType: number, enabled: boolean): Buffer {
    const b = Buffer.alloc(18);
    b.write("HL", 0, 2, "ascii");
    b[2] = 5;
    b.writeUInt16LE(KCmdControlChannel, 4);
    b.writeUInt16LE(2, 6);
    b[16] = mediaType;
    b[17] = enabled ? 1 : 2;
    return b;
  }

  /**
   * Build K10056 (set resolution) packet.
   */
  buildSetResolution(frameSize: number, bitrate: number): Buffer {
    const b = Buffer.alloc(21);
    b.write("HL", 0, 2, "ascii");
    b[2] = 5;
    b.writeUInt16LE(KCmdSetResolution, 4);
    b.writeUInt16LE(5, 6);
    b[16] = frameSize + 1;
    b.writeUInt16LE(bitrate, 17);
    return b;
  }

  /** Start video streaming. */
  startVideo(): Buffer {
    return this.buildControlChannel(MediaTypeVideo, true);
  }

  /** Start audio streaming. */
  startAudio(): Buffer {
    return this.buildControlChannel(MediaTypeAudio, true);
  }

  /** Start intercom (return audio). */
  startIntercom(): Buffer {
    return this.buildControlChannel(MediaTypeReturnAudio, true);
  }

  /** Stop intercom. */
  stopIntercom(): Buffer {
    return this.buildControlChannel(MediaTypeReturnAudio, false);
  }

  /** Feed raw AV data to the frame handler. */
  feedData(data: Buffer): void {
    this.frameHandler.handle(data);
  }

  close(): void {
    this._closed = true;
    this.frameHandler.close();
  }

  /** Get HD frame size for this camera model. */
  getHdFrameSize(): number {
    const model = this.options.model;
    if (["HL_CAM3P", "HL_PANP", "HL_CAM4", "HL_DB2", "HL_CFL2"].includes(model)) {
      return FrameSize2K;
    }
    if (model === "HL_CFL2") return FrameSize1080P; // floodlight
    return FrameSize1080P;
  }

  // ─── Internal crypto ──────────────────────────────────────────

  private generateChallengeResponse(challengeBytes: Buffer, status: number): Buffer {
    let secretKey: Buffer;

    switch (status) {
      case StatusDefault:
        secretKey = Buffer.from("FFFFFFFFFFFFFFFF", "ascii");
        break;
      case StatusENR16:
        secretKey = Buffer.alloc(16);
        Buffer.from(this.options.enr.slice(0, 16), "ascii").copy(secretKey);
        break;
      case StatusENR32: {
        if (this.options.enr.length >= 16) {
          const firstKey = Buffer.from(this.options.enr.slice(0, 16), "ascii");
          challengeBytes = xxteaDecryptVar(challengeBytes, firstKey);
        }
        secretKey = Buffer.alloc(16);
        if (this.options.enr.length >= 32) {
          Buffer.from(this.options.enr.slice(16, 32), "ascii").copy(secretKey);
        } else if (this.options.enr.length > 16) {
          Buffer.from(this.options.enr.slice(16), "ascii").copy(secretKey);
        } else {
          secretKey = Buffer.from("FFFFFFFFFFFFFFFF", "ascii");
        }
        break;
      }
      default:
        secretKey = Buffer.from("FFFFFFFFFFFFFFFF", "ascii");
    }

    return xxteaDecryptVar(challengeBytes, secretKey);
  }
}
