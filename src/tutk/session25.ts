/**
 * TUTK Session v25 — modern variant with reorder buffer and enhanced counters.
 * Ported from go2rtc/pkg/tutk/session25.go
 *
 * Extends Session16 with:
 * - Packet reordering buffer (handles out-of-order UDP packets)
 * - Enhanced counter acknowledgments
 * - Multi-chunk frame assembly with flags
 * - V25 specific channel 1 handling (0x20/0x21 handshake)
 */

import { Session16 } from "./session16.js";

const MSG_HDR_SIZE = 28;
const CMD_HDR_SIZE_25 = 28;

// ─── Reorder Buffer ─────────────────────────────────────────────

class ReorderBuffer {
  private buf = new Map<number, Buffer>();
  private seq = 0;
  private maxSize: number;

  constructor(size: number) {
    this.maxSize = size;
  }

  check(seq: number): boolean {
    return seq === this.seq;
  }

  next(): void {
    this.seq++;
  }

  available(): number {
    return this.maxSize - this.buf.size;
  }

  push(seq: number, data: Buffer): void {
    this.buf.set(seq, Buffer.from(data));
  }

  pop(): Buffer | null {
    while (true) {
      const data = this.buf.get(this.seq);
      if (data) {
        this.buf.delete(this.seq);
        this.next();
        return data;
      }
      if (this.available() > 0) return null;
      this.next(); // drop missing packet
    }
  }
}

// ─── Session25 ──────────────────────────────────────────────────

export class Session25 extends Session16 {
  private rb = new ReorderBuffer(5);

  private seqSendCmd2 = 0;
  private seqSendCnt = 0;
  private seqRecvPkt0 = 0;
  private seqRecvPkt1 = 0;
  private seqRecvCmd2 = 0;

  // Frame assembly state (v25 specific)
  private v25WaitData: Buffer[] = [];
  private v25WaitCSeq = 0;

  constructor(sid8: Buffer) {
    super(sid8);
  }

  /** Build IOCtrl for v25 (uses double sequence numbering). */
  buildIOCtrlV25(ctrlType: number, ctrlData: Buffer): Buffer {
    const size = MSG_HDR_SIZE + CMD_HDR_SIZE_25 + 4 + ctrlData.length;
    const msg = this['msg'](size); // access parent private method via bracket notation
    const cmd = msg.subarray(MSG_HDR_SIZE);

    cmd[0] = 0x00; cmd[1] = 0x70; cmd[2] = 0x0b; cmd[3] = 0x00;
    // seqSendCmd1 managed by parent
    cmd[9] = 0x70;
    cmd[12] = 1;
    cmd.writeUInt16LE(size - 52, 16);

    cmd.writeUInt16LE(this.seqSendCmd2, 10);
    cmd.writeUInt16LE(this.seqSendCmd2, 20);
    this.seqSendCmd2++;

    const data = cmd.subarray(28);
    data.writeUInt32LE(ctrlType, 0);
    ctrlData.copy(data, 4);

    return msg;
  }

  /**
   * Handle v25 session data from channel 0.
   * Overrides the v16 handler with enhanced chunk handling.
   */
  handleSessionDataV25(chId: number, cmd: Buffer): void {
    if (chId !== 0) {
      this.handleCh1V25(cmd);
      return;
    }

    const cmdType = cmd[0]!;

    switch (cmdType) {
      case 0x03: case 0x05: case 0x07: {
        // Media chunks — handle with reorder buffer
        this.handleChunkV25(cmd, true);
        let reordered: Buffer | null;
        while ((reordered = this.rb.pop()) !== null) {
          this.handleChunkV25(reordered, false);
        }
        return;
      }

      case 0x00: {
        // Commands
        this.sendAckCounters();
        this.seqRecvCmd2 = cmd.readUInt16LE(2);

        const subCmd = cmd[1]!;
        if (subCmd === 0x70) {
          // IO control command
          const payload = cmd.subarray(28);
          const ct = payload.readUInt32LE(0);
          this.emit("command", ct, payload.subarray(4));
        } else if (subCmd === 0x71) {
          this.emit("command-ack");
        }
        return;
      }

      case 0x09: {
        // Counter ACK
        this.emit("command-ack");
        return;
      }

      case 0x0a: {
        // Unknown 0a08 — ack
        this.sendAck0A08(cmd);
        return;
      }
    }
  }

  private handleChunkV25(cmd: Buffer, checkSeq: boolean): void {
    const flags = cmd[1]!;
    let cmd2: Buffer;

    if ((flags & 0b1000) === 0) {
      cmd2 = cmd.subarray(8);
    } else {
      cmd2 = cmd.subarray(16);
    }

    const seq = cmd2.readUInt16LE(2);

    if (checkSeq) {
      if (this.rb.check(seq)) {
        this.rb.next();
      } else {
        this.rb.push(seq, cmd);
        return;
      }
    }

    // Check if first chunk (chunk seq == 0 or single chunk)
    const chunkSeq = cmd2.readUInt16LE(6);
    const chunkTotal = cmd2.readUInt16LE(4);

    if (chunkSeq === 0 || chunkTotal === 1) {
      this.v25WaitData = [];
      this.v25WaitCSeq = seq;
    } else if (seq !== this.v25WaitCSeq) {
      return; // lost
    }

    this.v25WaitData.push(cmd2.subarray(20));

    // Check if this is the last chunk
    if ((flags & 0b0001) === 0) {
      this.v25WaitCSeq++;
      return;
    }

    this.seqRecvPkt1 = seq;
    this.sendAckCounters();

    const full = Buffer.concat(this.v25WaitData);
    const n = full.length - 32;
    if (n > 0) {
      this.emit("frame", full.subarray(n), full.subarray(0, n));
    }
  }

  private sendAckCounters(): void {
    const msg = this['msg'](MSG_HDR_SIZE + 24);
    const cmd = msg.subarray(MSG_HDR_SIZE);

    cmd[0] = 0x09; cmd[1] = 0x00; cmd[2] = 0x0b; cmd[3] = 0x00;

    cmd.writeUInt16LE(this.seqRecvPkt0, 8);
    this.seqRecvPkt0 = this.seqRecvPkt1;
    cmd.writeUInt16LE(this.seqRecvPkt1, 10);
    cmd.writeUInt16LE(this.seqRecvCmd2, 12);

    cmd.writeUInt16LE(this.seqSendCnt, 18);
    this.seqSendCnt++;
    cmd.writeUInt16LE(Date.now() & 0xffff, 20);

    this.sessionWrite(0, msg);
  }

  private handleCh1V25(cmd: Buffer): void {
    const c0 = cmd[0]!;
    const c1 = cmd[1]!;

    if (c0 === 0x00 && c1 === 0x07) {
      // Time sync
      const ack = this['msg'](MSG_HDR_SIZE + 28);
      const ackCmd = ack.subarray(MSG_HDR_SIZE);
      ackCmd[0] = 0x01; ackCmd[1] = 0x0a; ackCmd[2] = 0x0b; ackCmd[3] = 0x00;
      ackCmd[20] = 1;
      this.sessionWrite(1, ack);
    } else if (c0 === 0x00 && c1 === 0x20) {
      // Client start v25
      this.sendAck0020(cmd);
    }
  }

  private sendAck0020(original: Buffer): void {
    const dataSize = 36;
    const msg = this['msg'](MSG_HDR_SIZE + CMD_HDR_SIZE_25 + dataSize);
    const cmd = msg.subarray(MSG_HDR_SIZE);

    cmd[0] = 0x00; cmd[1] = 0x21; cmd[2] = 0x0b; cmd[3] = 0x00;
    cmd[16] = dataSize;
    original.copy(cmd, 20, 20, 24);

    const data = cmd.subarray(CMD_HDR_SIZE_25);
    data[5] = 1; data[7] = 1; data[8] = 1;
    data[12] = 4;
    data[16] = 0xfb; data[17] = 0x07; data[18] = 0x1f; data[19] = 0x00;
    data[30] = 3; data[32] = 1;

    this.sessionWrite(1, msg);
  }

  private sendAck0A08(original: Buffer): void {
    const msg = this['msg'](MSG_HDR_SIZE + 20);
    const cmd = msg.subarray(MSG_HDR_SIZE);
    cmd[0] = 0x0b; cmd[1] = 0x00; cmd[2] = 0x0b; cmd[3] = 0x00;
    original.copy(cmd, 8, 8, 10);
    this.sessionWrite(0, msg);
  }
}
