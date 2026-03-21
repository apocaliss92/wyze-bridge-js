# @apocaliss92/wyze-bridge-js

Node.js library for local P2P streaming from Wyze cameras using the native TUTK/DTLS protocol. Port of [go2rtc's Wyze implementation](https://github.com/AlexxIT/go2rtc/tree/master/pkg/wyze).

## Features

- **Wyze Cloud API** — login, device discovery, camera parameters
- **P2P Connection** — IOTC discovery, DTLS 1.2 handshake (ECDHE-PSK + ChaCha20-Poly1305), AV login, K-Auth
- **Video Streaming** — H264/H265 frame parsing, multi-packet reassembly
- **Audio** — PCM 16-bit LE receive (codec 0x8C)
- **RFC 4571 Server** — TCP server with RTP packetization for Scrypted integration
- **Two-way audio** — detected (playback support coming soon)

## Installation

```bash
npm install @apocaliss92/wyze-bridge-js
```

## Quick Start

### Cloud Discovery

```typescript
import { WyzeCloud } from "@apocaliss92/wyze-bridge-js";

const cloud = new WyzeCloud("your-api-key", "your-key-id");
await cloud.login("user@email.com", "password");

const cameras = await cloud.getCameraList();
for (const cam of cameras) {
  console.log(`${cam.nickname} (${cam.productModel}) — ${cam.ip}`);
}
```

### Direct P2P Streaming

```typescript
import { WyzeDTLSConn } from "@apocaliss92/wyze-bridge-js";

const conn = new WyzeDTLSConn({
  host: "192.168.1.41",
  uid: "3Y5N8XHM...",
  enr: "ZWsncOqw...",
  mac: "80482C53405B",
  model: "WYZE_CAKP2JFUS",
});

await conn.connect();
await conn.startVideo();
await conn.startAudio();

conn.onPacket((pkt) => {
  if (pkt.codec === 0x4e) {
    // H264 video frame
    console.log(`Video: ${pkt.payload.length} bytes, keyframe=${pkt.isKeyframe}`);
  }
});

// When done:
conn.close();
```

### RFC 4571 Server (for Scrypted)

```typescript
import { WyzeCloud, createWyzeRfc4571Server } from "@apocaliss92/wyze-bridge-js";

const cloud = new WyzeCloud(apiKey, keyId);
await cloud.login(email, password);
const cameras = await cloud.getCameraList();

const server = await createWyzeRfc4571Server({
  camera: cameras[0],
  frameSize: 0,  // 0=1080p, 1=360p, 2=720p, 3=2K
  bitrate: 0xF0, // 0xF0=max, 0x3C=SD
});

console.log(`RFC 4571 server: tcp://${server.host}:${server.port}`);
console.log(`SDP:\n${server.sdp}`);

// Server accepts TCP connections and sends RFC 4571 framed RTP
// Scrypted connects to this and feeds it to the rebroadcast system

// When done:
await server.close();
```

## API Reference

### `WyzeCloud`

Wyze cloud API client for authentication and device discovery.

```typescript
new WyzeCloud(apiKey: string, apiId: string)
```

| Method | Returns | Description |
|--------|---------|-------------|
| `login(email, password)` | `Promise<void>` | Login to Wyze cloud |
| `getCameraList()` | `Promise<WyzeCamera[]>` | Get all cameras |
| `getCamera(id)` | `Promise<WyzeCamera \| null>` | Find camera by MAC or name |

### `WyzeDTLSConn`

Full P2P connection to a Wyze camera. Handles the entire protocol stack.

```typescript
new WyzeDTLSConn(options: WyzeDTLSConnOptions)
```

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `host` | `string` | ✅ | Camera local IP |
| `uid` | `string` | ✅ | P2P UID from cloud |
| `enr` | `string` | ✅ | ENR encryption key |
| `mac` | `string` | ✅ | Camera MAC address |
| `model` | `string` | ✅ | Product model |
| `port` | `number` | | UDP port (default: 32761) |
| `verbose` | `boolean` | | Enable debug logging |

| Method | Returns | Description |
|--------|---------|-------------|
| `connect()` | `Promise<{ hasTwoWay, authInfo }>` | Full connection: discovery → DTLS → auth |
| `startVideo(frameSize?, bitrate?)` | `Promise<void>` | Start video streaming |
| `startAudio()` | `Promise<void>` | Start audio streaming |
| `onPacket(handler)` | `void` | Set frame callback |
| `close()` | `void` | Close connection |

### `createWyzeRfc4571Server`

Creates an RFC 4571 TCP server wrapping a P2P connection.

```typescript
createWyzeRfc4571Server(options: WyzeRfc4571ServerOptions): Promise<WyzeRfc4571Server>
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `camera` | `WyzeCamera` | — | Camera info from cloud |
| `host` | `string` | `"127.0.0.1"` | TCP listen address |
| `frameSize` | `number` | `0` | Resolution (0=1080p) |
| `bitrate` | `number` | `0xF0` | Bitrate (0xF0=max) |
| `videoPayloadType` | `number` | `96` | RTP payload type |
| `verbose` | `boolean` | `false` | Debug logging |
| `logger` | `Console` | `console` | Logger |

Returns:

| Property | Type | Description |
|----------|------|-------------|
| `host` | `string` | TCP listen address |
| `port` | `number` | TCP listen port |
| `sdp` | `string` | SDP with SPS/PPS params |
| `videoType` | `"H264" \| "H265"` | Detected video codec |
| `close()` | `Promise<void>` | Shutdown server + P2P |

### `Packet`

Video/audio frame from the camera.

| Property | Type | Description |
|----------|------|-------------|
| `codec` | `number` | Codec ID (0x4E=H264, 0x50=H265, 0x8C=PCML) |
| `payload` | `Buffer` | Raw frame data (Annex-B for video) |
| `timestamp` | `number` | RTP timestamp |
| `isKeyframe` | `boolean` | Whether this is a keyframe/IDR |
| `channel` | `number` | Channel (0x05=video, 0x03=audio) |

## Protocol Details

### Connection Flow

```
1. IOTC Discovery     UDP probe → camera:32761
2. Session Setup      Direct connect + session request
3. DTLS Handshake     ECDHE x25519 + PSK + ChaCha20-Poly1305 (0xCCAC)
4. AV Login           Client start + response (two-way audio detection)
5. Periodic ACK       100ms ticker (required for camera to accept commands)
6. K-Auth             HL 10000→10001→10002→10003 (XXTEA challenge/response)
7. Start Channels     K10056 (resolution) + K10010 (video/audio enable)
8. Frame Reception    TUTK frame parsing + multi-packet reassembly
```

### Encryption Layers

| Layer | Algorithm | Purpose |
|-------|-----------|---------|
| IOTC transport | TransCode (custom XOR+rotation) | UDP packet encryption |
| DTLS 1.2 | ECDHE-PSK + ChaCha20-Poly1305 | End-to-end P2P encryption |
| K-Auth challenge | XXTEA | Camera authentication |
| PSK derivation | SHA-256(ENR) | DTLS pre-shared key |
| Auth key | SHA-256(ENR+MAC) → Base64 | Discovery authentication |

## Acknowledgments

- [go2rtc](https://github.com/AlexxIT/go2rtc) — original Go implementation by AlexxIT
- [TUTK/IOTC protocol](https://github.com/AlexxIT/go2rtc/tree/master/pkg/tutk) — reverse-engineered P2P protocol
