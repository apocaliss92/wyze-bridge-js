/**
 * TUTK Session v16 — handles command/media framing over the P2P connection.
 * Ported from go2rtc/pkg/tutk/session16.go
 *
 * The session manages:
 * - IO control commands (auth, resolution, channel control)
 * - Media frame reassembly from chunked packets
 * - Two-way audio channel setup
 * - Sequence numbering and acknowledgments
 */

import { EventEmitter } from "node:events";

const MAGIC = Buffer.from([0x04, 0x02]); // TUTK magic bytes
const MSG_HDR_SIZE = 28;
const CMD_HDR_SIZE = 24;

export class Session16 extends EventEmitter {
  private sid16: Buffer;
  private seqSendCh0 = 0;
  private seqSendCh1 = 0;
  private seqSendCmd1 = 0;
  private seqSendAud = 0;

  // Frame reassembly state
  private waitFSeq = 0;
  private waitCSeq = 0;
  private waitSize = 0;
  private waitData: Buffer[] = [];

  private closed = false;

  /** Callback to send data over the connection. */
  onSend?: (chId: number, data: Buffer) => void;

  constructor(sid8: Buffer) {
    super();
    this.sid16 = Buffer.alloc(16);
    sid8.copy(this.sid16, 8, 0, 8);
    sid8.copy(this.sid16, 0, 0, 2);
    this.sid16[4] = 0x0c;
  }

  close(): void {
    this.closed = true;
  }

  /** Build a message envelope with TUTK header + session ID. */
  private msg(size: number): Buffer {
    const b = Buffer.alloc(size);
    MAGIC.copy(b, 0);
    b[3] = 0x0a; // connected stage
    b.writeUInt16LE(size - 16, 4);
    b[8] = 0x07; b[9] = 0x04; b[10] = 0x21; // client request
    this.sid16.copy(b, 12);
    return b;
  }

  /** Build ClientStart message. */
  buildClientStart(username: string, password: string): Buffer {
    const size = 566 + 32;
    const msg = this.msg(size);
    const cmd = msg.subarray(MSG_HDR_SIZE);

    cmd[0] = 0x00; cmd[1] = 0x00; cmd[2] = 0x0b; cmd[3] = 0x00;
    cmd.writeUInt16LE(size - 52, 16);
    cmd[18] = 1;
    cmd.writeUInt32LE(Date.now() & 0xffffffff, 20);

    const data = cmd.subarray(CMD_HDR_SIZE);
    Buffer.from(username, "ascii").copy(data, 0);
    Buffer.from(password, "ascii").copy(data, 257);

    // Config bytes
    const cfg = data.subarray(257 + 257);
    cfg[4] = 4;
    cfg[8] = 0xfb; cfg[9] = 0x07; cfg[10] = 0x1f; cfg[11] = 0x00;
    cfg[22] = 3;

    return msg;
  }

  /** Build SendIOCtrl message. */
  buildIOCtrl(ctrlType: number, ctrlData: Buffer): Buffer {
    const dataSize = 4 + ctrlData.length;
    const msg = this.msg(MSG_HDR_SIZE + CMD_HDR_SIZE + dataSize);
    const cmd = msg.subarray(MSG_HDR_SIZE);

    cmd[0] = 0x00; cmd[1] = 0x70; cmd[2] = 0x0b; cmd[3] = 0x00;
    this.seqSendCmd1++;
    cmd.writeUInt16LE(this.seqSendCmd1, 4);
    cmd.writeUInt16LE(dataSize, 16);
    cmd.writeUInt32LE(Date.now() & 0xffffffff, 20);

    const data = cmd.subarray(CMD_HDR_SIZE);
    data.writeUInt32LE(ctrlType, 0);
    ctrlData.copy(data, 4);

    return msg;
  }

  /** Build SendFrameData message (for two-way audio). */
  buildFrameData(frameInfo: Buffer, frameData: Buffer): Buffer {
    const n = frameData.length;
    const dataSize = n + 8 + 32;
    const msg = this.msg(MSG_HDR_SIZE + CMD_HDR_SIZE + dataSize);
    const cmd = msg.subarray(MSG_HDR_SIZE);

    cmd[0] = 0x01; cmd[1] = 0x03; cmd[2] = 0x0b; cmd[3] = 0x00;
    cmd.writeUInt16LE(this.seqSendAud, 4);
    this.seqSendAud++;
    cmd.writeUInt16LE(n, 8);
    cmd[14] = 0x28;
    cmd.writeUInt16LE(dataSize, 16);
    cmd.writeUInt16LE(Date.now() & 0xffff, 18);
    cmd[20] = 1;

    const data = cmd.subarray(CMD_HDR_SIZE);
    frameData.copy(data, 0);
    Buffer.from("ODUA\x20\x00\x00\x00", "ascii").copy(data, n);
    frameInfo.copy(data, n + 8);

    return msg;
  }

  /**
   * Process received session data from channel 0 or 1.
   * Emits "command" and "frame" events.
   */
  handleSessionData(chId: number, cmd: Buffer): void {
    if (chId !== 0) {
      this.handleCh1(cmd);
      return;
    }

    const cmdType = cmd[0]!;
    const cmdSub = cmd[1]!;

    if (cmdType === 0x01) {
      // Media frame
      if (cmdSub === 0x03) {
        this.handleMediaChunk(cmd);
      } else if (cmdSub === 0x04) {
        // Single-packet frame
        const data = cmd.subarray(24);
        const hdrSize = cmd.readUInt16LE(14);
        this.emit("frame", data.subarray(0, hdrSize), data.subarray(hdrSize));
      }
    } else if (cmdType === 0x00) {
      if (cmdSub === 0x70) {
        // IOCtrl command received
        this.sendAck0070(cmd);
        const payload = cmd.subarray(24);
        const ctrlType = payload.readUInt32LE(0);
        this.emit("command", ctrlType, payload.subarray(4));
      } else if (cmdSub === 0x71) {
        // Command ACK
        this.emit("command-ack");
      } else if (cmdSub === 0x12) {
        this.sendAck0012(cmd);
      }
    }
  }

  /** Write to the connection with sequence numbering. */
  sessionWrite(chId: number, buf: Buffer): void {
    if (chId === 0) {
      buf.writeUInt16LE(this.seqSendCh0, 6);
      this.seqSendCh0++;
    } else {
      buf.writeUInt16LE(this.seqSendCh1, 6);
      this.seqSendCh1++;
      buf[14] = 1; // channel
    }
    this.onSend?.(chId, buf);
  }

  // ─── Media reassembly ────────────────────────────────────────

  private handleMediaChunk(cmd: Buffer): void {
    const frameSeq = cmd.readUInt16LE(4);
    const chunkSeq = cmd.readUInt16LE(12);

    if (chunkSeq === 0) {
      this.waitFSeq = frameSeq;
      this.waitCSeq = 0;
      this.waitData = [];
      const payloadSize = cmd.readUInt32LE(8);
      const hdrSize = cmd.readUInt16LE(14);
      this.waitSize = hdrSize + payloadSize;
    } else if (frameSeq !== this.waitFSeq || chunkSeq !== this.waitCSeq) {
      this.waitCSeq = 0;
      return;
    }

    this.waitData.push(Buffer.from(cmd.subarray(24)));
    const totalLen = this.waitData.reduce((s, b) => s + b.length, 0);

    if (totalLen < this.waitSize) {
      this.waitCSeq++;
      return;
    }

    this.waitCSeq = 0;
    const full = Buffer.concat(this.waitData);
    const payloadSize = cmd.readUInt32LE(8);

    this.emit("frame", full.subarray(payloadSize), full.subarray(0, payloadSize));
  }

  // ─── ACK messages ────────────────────────────────────────────

  private sendAck0070(original: Buffer): void {
    const msg = this.msg(MSG_HDR_SIZE + CMD_HDR_SIZE);
    const cmd = msg.subarray(MSG_HDR_SIZE);
    cmd[0] = 0x00; cmd[1] = 0x71;
    original.copy(cmd, 2, 2, 6);
    original.copy(cmd, 20, 20, 24);
    this.sessionWrite(0, msg);
  }

  private sendAck0012(original: Buffer): void {
    const dataSize = 20;
    const msg = this.msg(MSG_HDR_SIZE + CMD_HDR_SIZE + dataSize);
    const cmd = msg.subarray(MSG_HDR_SIZE);
    cmd[0] = 0x00; cmd[1] = 0x13; cmd[2] = 0x0b; cmd[3] = 0x00;
    cmd[16] = dataSize;
    original.subarray(CMD_HDR_SIZE).copy(cmd, CMD_HDR_SIZE);
    this.sessionWrite(0, msg);
  }

  // ─── Channel 1 (two-way audio) ───────────────────────────────

  private handleCh1(cmd: Buffer): void {
    const cid = cmd.subarray(0, 2).toString("hex");
    switch (cid) {
      case "0000": // client start
        this.sendCh1Ack0000(cmd);
        this.sendCh1Msg0012();
        break;
      case "0007":
        this.sendCh1Ack0007();
        break;
      case "0008":
        this.sendCh1Ack0008(cmd);
        break;
    }
  }

  private sendCh1Ack0000(original: Buffer): void {
    const msg = this.msg(MSG_HDR_SIZE + CMD_HDR_SIZE + 32);
    const cmd = msg.subarray(MSG_HDR_SIZE);
    cmd[0] = 0x00; cmd[1] = 0x14; cmd[2] = 0x0b; cmd[3] = 0x00;
    cmd[16] = 32;
    original.copy(cmd, 20, 20, 24);
    original.subarray(original.length - 32).copy(cmd, CMD_HDR_SIZE);
    this.sessionWrite(1, msg);
  }

  private sendCh1Msg0012(): void {
    const msg = this.msg(MSG_HDR_SIZE + CMD_HDR_SIZE + 12);
    const cmd = msg.subarray(MSG_HDR_SIZE);
    cmd[0] = 0x00; cmd[1] = 0x12; cmd[2] = 0x0b; cmd[3] = 0x00;
    cmd[16] = 12;
    const data = cmd.subarray(CMD_HDR_SIZE);
    data[0] = 2; data[4] = 1; data[9] = 1;
    this.sessionWrite(1, msg);
  }

  private sendCh1Ack0007(): void {
    const msg = this.msg(MSG_HDR_SIZE + 28);
    const cmd = msg.subarray(MSG_HDR_SIZE);
    cmd[0] = 0x01; cmd[1] = 0x0a; cmd[2] = 0x0b; cmd[3] = 0x00;
    cmd[20] = 1;
    this.sessionWrite(1, msg);
  }

  private sendCh1Ack0008(original: Buffer): void {
    const msg = this.msg(MSG_HDR_SIZE + 28);
    const cmd = msg.subarray(MSG_HDR_SIZE);
    cmd[0] = 0x01; cmd[1] = 0x09; cmd[2] = 0x0b; cmd[3] = 0x00;
    original.copy(cmd, 20, 20);
    this.sessionWrite(1, msg);
  }
}
