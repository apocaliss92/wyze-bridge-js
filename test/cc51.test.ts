import { describe, it, expect } from "vitest";
import { createHmac } from "node:crypto";
import { WyzeDTLSConn } from "../src/tutk/dtls/WyzeDTLSConn.js";
import { transCodeBlob } from "../src/tutk/crypto.js";

const MAGIC_CC51 = "\x51\xcc";

function makeConn(): any {
  const c: any = new WyzeDTLSConn({
    host: "192.168.1.50",
    uid: "ABCD1234WXYZ",
    enr: "0123456789ABCDEF0123456789ABCDEF",
    mac: "AABBCCDDEEFF",
    model: "WYZE_CAKP2JFUS",
  });
  // Deterministic session id + ticket for golden assertions.
  c.sid = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]);
  c.ticket = 0x1234;
  return c;
}

describe("CC51 transport alignment to go2rtc", () => {
  it("msgTxDataCC51 has the go2rtc wire layout", () => {
    const c = makeConn();
    const payload = Buffer.from([0xaa, 0xbb, 0xcc]);
    const b: Buffer = c.msgTxDataCC51(payload, 0);

    expect(b.length).toBe(28 + payload.length + 20);
    expect(b.subarray(0, 2).toString("binary")).toBe(MAGIC_CC51);
    expect(b.readUInt16LE(4)).toBe(0x1502); // CMD_DTLS_CC51
    expect(b.readUInt16LE(6)).toBe(16 + payload.length + 20); // payloadSize
    expect(b.readUInt16LE(12)).toBe(0x0010 | (0 << 8)); // channel in high byte
    expect(b.readUInt16LE(14)).toBe(0x1234); // ticket
    expect(b.subarray(16, 24)).toEqual(c.sid);
    expect(b.readUInt32LE(24)).toBe(1);
    expect(b.subarray(28, 28 + payload.length)).toEqual(payload);

    // HMAC-SHA1 over the 28-byte header, keyed by uid+authKey
    const key = Buffer.concat([Buffer.from(c.uid, "ascii"), Buffer.from(c.authKey, "ascii")]);
    const expected = createHmac("sha1", key).update(b.subarray(0, 28)).digest();
    expect(b.subarray(28 + payload.length)).toEqual(expected);

    // channel must land in the high byte
    const b1: Buffer = c.msgTxDataCC51(payload, 1);
    expect(b1.readUInt16LE(12)).toBe(0x0010 | (1 << 8));
  });

  it("msgDiscoCC51 and msgKeepaliveCC51 carry magic + valid HMAC", () => {
    const c = makeConn();
    const disco: Buffer = c.msgDiscoCC51(2, 0x1234, false);
    expect(disco.length).toBe(52);
    expect(disco.subarray(0, 2).toString("binary")).toBe(MAGIC_CC51);
    expect(disco.readUInt16LE(4)).toBe(0x1002);
    expect(disco.readUInt16LE(12)).toBe(2); // seq
    expect(disco.readUInt16LE(14)).toBe(0x1234); // ticket

    const ka: Buffer = c.msgKeepaliveCC51();
    expect(ka.length).toBe(48);
    expect(ka.readUInt16LE(4)).toBe(0x1202);
    expect(ka.readUInt32LE(16)).toBe(2); // kaSeq advanced by 2
  });

  it("msgTxData dispatches IOTC vs CC51 on the isCC51 flag", () => {
    const c = makeConn();
    const payload = Buffer.from([1, 2, 3, 4]);

    c.isCC51 = false;
    const iotc: Buffer = c.msgTxData(payload, 0);
    expect(iotc[0]).toBe(0x04); // IOTC marker
    expect(iotc.readUInt16LE(8)).toBe(0x0407); // CMD_DATA_TX
    expect(iotc.subarray(28, 28 + payload.length)).toEqual(payload);

    c.isCC51 = true;
    const cc51: Buffer = c.msgTxData(payload, 0);
    expect(cc51.subarray(0, 2).toString("binary")).toBe(MAGIC_CC51);
  });

  it("decodeInbound extracts DTLS records for both transports", () => {
    const c = makeConn();

    // IOTC: build a 0x0408 data packet, obfuscate it as it arrives on the wire.
    c.isCC51 = false;
    const records = Buffer.from([0x16, 0xfe, 0xfd, 0xde, 0xad]);
    const d = Buffer.alloc(28 + records.length);
    d.writeUInt16LE(0x0408, 8);
    d[14] = 0; // channel 0
    records.copy(d, 28);
    const wire = transCodeBlob(d);
    expect(c.decodeInbound(wire)).toEqual({ channel: 0, records });

    // CC51: build a 0x1502 frame with channel 0; raw on the wire.
    c.isCC51 = true;
    const payload = Buffer.from([0x16, 0xfe, 0xfd, 0x01, 0x02]);
    const frame = Buffer.alloc(28 + payload.length + 20);
    frame[0] = 0x51; frame[1] = 0xcc;
    frame.writeUInt16LE(0x1502, 4);
    frame.writeUInt16LE(0x0010 | (0 << 8), 12); // channel 0 high byte
    payload.copy(frame, 28);
    expect(c.decodeInbound(frame)).toEqual({ channel: 0, records: payload });
  });

  it("decodeInbound returns null for keepalives (no throw without a socket)", () => {
    const c = makeConn();

    // IOTC keepalive 0x0428
    c.isCC51 = false;
    const ka = Buffer.alloc(28);
    ka.writeUInt16LE(0x0428, 8);
    expect(c.decodeInbound(transCodeBlob(ka))).toBeNull();

    // CC51 keepalive 0x1202
    c.isCC51 = true;
    const kaCC51 = Buffer.alloc(48);
    kaCC51[0] = 0x51; kaCC51[1] = 0xcc;
    kaCC51.writeUInt16LE(0x1202, 4);
    expect(c.decodeInbound(kaCC51)).toBeNull();
  });

  it("doorbell models select K10052 resolution", () => {
    const mk = (model: string) => {
      const c: any = new WyzeDTLSConn({ host: "1.1.1.1", uid: "U", enr: "E".repeat(32), mac: "M", model });
      return c.useDoorbellResolution();
    };
    expect(mk("WYZEDB3")).toBe(true);
    expect(mk("WVOD1")).toBe(true);
    expect(mk("WYZE_CAKP2JFUS")).toBe(false);
  });
});
