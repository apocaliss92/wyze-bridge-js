import { describe, it, expect } from "vitest";
import { randomBytes } from "node:crypto";
import { WyzeDtlsServer } from "../src/tutk/dtls/dtlsServer.js";

function dtlsRecord(ct: number, epoch: number, seq: number, frag: Buffer): Buffer {
  const b = Buffer.alloc(13 + frag.length);
  b[0] = ct; b[1] = 0xfe; b[2] = 0xfd;
  b.writeUInt16BE(epoch, 3); b.writeUIntBE(seq, 5, 6); b.writeUInt16BE(frag.length, 11);
  frag.copy(b, 13); return b;
}
function handshake(type: number, seq: number, body: Buffer): Buffer {
  const b = Buffer.alloc(12 + body.length);
  b[0] = type; b.writeUIntBE(body.length, 1, 3); b.writeUInt16BE(seq, 4);
  b.writeUIntBE(body.length, 9, 3); body.copy(b, 12); return b;
}

describe("WyzeDtlsServer (backchannel DTLS, experimental)", () => {
  it("AES-128-CBC-SHA256 record layer round-trips at every padding boundary", () => {
    const srv: any = new WyzeDtlsServer({ psk: Buffer.alloc(16, 7), send: () => {} });
    const key = randomBytes(16);
    const mac = randomBytes(32);
    // Make server-write == client-read so encrypt then decrypt is symmetric.
    srv.serverKey = key; srv.serverMacKey = mac;
    srv.clientKey = key; srv.clientMacKey = mac;

    for (const len of [0, 1, 15, 16, 17, 31, 32, 160, 323]) {
      const content = randomBytes(len);
      const rec: Buffer = srv.encryptRecord(23, content);
      expect(rec[0]).toBe(23); // app data
      expect(rec.readUInt16BE(3)).toBe(1); // epoch 1
      const frag = rec.subarray(13);
      const out: Buffer = srv.decryptRecord({ ct: 23, epoch: 1, seq: rec.readUIntBE(5, 6), frag });
      expect(out).toEqual(content);
    }
  });

  it("answers the first ClientHello with a HelloVerifyRequest", async () => {
    const sends: Buffer[] = [];
    const srv = new WyzeDtlsServer({ psk: Buffer.alloc(16, 1), send: (r) => sends.push(r) });
    const done = srv.handshake(500).catch(() => {});

    const chBody = Buffer.concat([
      Buffer.from([0xfe, 0xfd]), // client_version
      randomBytes(32), // random
      Buffer.from([0x00]), // session_id len 0
      Buffer.from([0x00]), // cookie len 0
      Buffer.from([0x00, 0x02, 0x00, 0xae]), // cipher_suites: TLS_PSK_WITH_AES_128_CBC_SHA256
      Buffer.from([0x01, 0x00]), // compression methods
    ]);
    srv.feed(dtlsRecord(22, 0, 0, handshake(1, 0, chBody)));

    await new Promise((r) => setTimeout(r, 20));
    expect(sends.length).toBeGreaterThan(0);
    expect(sends[0]![0]).toBe(22); // handshake record
    expect(sends[0]![13]).toBe(3); // HelloVerifyRequest
    // cookie present
    const cookieLen = sends[0]![13 + 12 + 2]!;
    expect(cookieLen).toBeGreaterThan(0);

    srv.close();
    await done;
  });
});
