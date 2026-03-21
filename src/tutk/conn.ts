/**
 * TUTK P2P UDP connection.
 * Ported from go2rtc/pkg/tutk/conn.go
 *
 * Handles:
 * - UDP socket management
 * - TransCode encryption/decryption on all messages
 * - Message routing (ping, commands, media frames)
 * - Session version detection (v16, v25)
 */

import * as dgram from "node:dgram";
import { EventEmitter } from "node:events";
import { transCodePartial, reverseTransCodePartial } from "./crypto.js";
import { genSessionId } from "./helpers.js";

export interface TutkConnOptions {
  host: string;
  port?: number;
  uid: string;
  verbose?: boolean;
}

/** Message types from handleMsg. */
export const MsgType = {
  Unknown: 0,
  Error: 1,
  Ping: 2,
  Command: 8,
  CommandAck: 9,
  MediaChunk: 11,
  MediaFrame: 12,
} as const;

export class TutkConn extends EventEmitter {
  private socket: dgram.Socket | null = null;
  private remoteHost: string;
  private remotePort: number;
  private sessionId: Buffer;
  private protocolVersion: number[] = [];
  private closed = false;

  constructor(private options: TutkConnOptions) {
    super();
    this.remoteHost = options.host;
    this.remotePort = options.port ?? 32761;
    this.sessionId = genSessionId();
  }

  get version(): string {
    if (this.protocolVersion.length === 1) return `TUTK/${this.protocolVersion[0]}`;
    if (this.protocolVersion.length >= 5) {
      return `TUTK/${this.protocolVersion[0]} SDK ${this.protocolVersion[1]}.${this.protocolVersion[2]}.${this.protocolVersion[3]}.${this.protocolVersion[4]}`;
    }
    return "TUTK/unknown";
  }

  get isConnected(): boolean {
    return this.socket !== null && !this.closed;
  }

  /** Send raw data (applies TransCode encryption). */
  async send(data: Buffer): Promise<void> {
    if (!this.socket || this.closed) throw new Error("Not connected");
    const encrypted = transCodePartial(data);
    return new Promise((resolve, reject) => {
      this.socket!.send(encrypted, this.remotePort, this.remoteHost, (err) => {
        if (err) reject(err); else resolve();
      });
    });
  }

  /** Connect to the camera via UDP. */
  async connect(): Promise<void> {
    if (this.socket) throw new Error("Already connected");

    this.socket = dgram.createSocket("udp4");

    this.socket.on("message", (msg, rinfo) => {
      if (rinfo.address !== this.remoteHost || msg.length < 16) return;
      // Update port if changed (NAT traversal)
      if (rinfo.port !== this.remotePort) this.remotePort = rinfo.port;
      // Decrypt
      const decrypted = reverseTransCodePartial(msg);
      this.handleMessage(decrypted);
    });

    this.socket.on("error", (err) => {
      this.emit("error", err);
    });

    await new Promise<void>((resolve, reject) => {
      this.socket!.bind(0, () => resolve());
      setTimeout(() => reject(new Error("Bind timeout")), 5000);
    });

    if (this.options.verbose) {
      const addr = this.socket.address();
      console.log(`[TUTK] Bound to ${addr.address}:${addr.port}, connecting to ${this.remoteHost}:${this.remotePort}`);
    }
  }

  close(): void {
    this.closed = true;
    if (this.socket) {
      try { this.socket.close(); } catch { /* ignore */ }
      this.socket = null;
    }
  }

  // ─── Message handling ─────────────────────────────────────────

  private handleMessage(msg: Buffer): void {
    if (msg.length < 16) return;

    const msgType = msg[8]!;

    switch (msgType) {
      case 0x08: {
        // Data message — route by channel
        const channel = msg[14]!;
        if (channel === 0 || channel === 1) {
          // Session data (commands or media)
          this.emit("session-data", channel, msg.subarray(28));
        } else if (channel === 5 && msg.length === 48) {
          // Channel 5 ack
          const ack = Buffer.from(msg);
          ack[8] = 0x07;
          ack[10] = 0x21;
          ack[32] = 0x41;
          this.send(ack).catch(() => {});
        }
        break;
      }

      case 0x28: {
        // Ping — reply
        if (msg.length === 24) {
          const ack = Buffer.from(msg);
          ack[8] = 0x27;
          ack[10] = 0x21;
          this.send(ack).catch(() => {});
          this.emit("ping");
        }
        break;
      }

      case 0x18:
        // Unknown ping variant
        break;

      default:
        if (this.options.verbose) {
          console.log(`[TUTK] Unknown msg type 0x${msgType.toString(16)}: ${msg.subarray(0, Math.min(32, msg.length)).toString("hex")}`);
        }
    }
  }
}
