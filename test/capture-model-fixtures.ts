/**
 * Capture per-model fixture data from a Wyze camera.
 *
 * Structure:
 *   test/fixtures/models/<ProductModel>/
 *     cloud-info.json        — cloud API camera info (sanitised)
 *     auth-info.json         — K10003 auth response
 *     diagnostics.json       — full diagnostics (all K10xxx queries)
 *     capabilities.json      — probed capabilities
 *     sample-keyframe.bin    — first H264 keyframe (raw Annex-B)
 *     stream-probe.json      — codec, resolution, fps from first frames
 *
 * Run:  npx tsx test/capture-model-fixtures.ts
 * Env:  WYZE_EMAIL, WYZE_PASSWORD, WYZE_API_KEY, WYZE_KEY_ID
 *       (or pass as args: npx tsx test/capture-model-fixtures.ts email pass key id)
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { WyzeCloud } from "../src/cloud/cloud.js";
import { WyzeDTLSConn } from "../src/tutk/dtls/WyzeDTLSConn.js";
import { isVideoCodec, isAudioCodec } from "../src/tutk/codec.js";
import type { Packet } from "../src/tutk/frame.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const MODELS_DIR = path.join(__dirname, "fixtures", "models");

function sanitise(obj: any): any {
  if (!obj || typeof obj !== "object") return obj;
  const clone = Array.isArray(obj) ? [...obj] : { ...obj };
  for (const key of Object.keys(clone)) {
    const k = key.toLowerCase();
    if (k.includes("token") || k.includes("password") || k.includes("secret")) {
      clone[key] = "***REDACTED***";
    } else if (k === "ip" || k === "p2pid" || k === "p2p_id") {
      clone[key] = "x.x.x.x";
    } else if (k === "enr") {
      clone[key] = "***ENR***";
    } else if (k === "mac" && typeof clone[key] === "string") {
      clone[key] = clone[key].replace(/(..)(?=..)/g, "$1:");
    } else if (typeof clone[key] === "object") {
      clone[key] = sanitise(clone[key]);
    }
  }
  return clone;
}

function getCredentials() {
  const args = process.argv.slice(2);
  return {
    email: args[0] || process.env.WYZE_EMAIL || "",
    password: args[1] || process.env.WYZE_PASSWORD || "",
    apiKey: args[2] || process.env.WYZE_API_KEY || "",
    keyId: args[3] || process.env.WYZE_KEY_ID || "",
  };
}

async function captureCamera(cam: any, cloud: WyzeCloud): Promise<void> {
  const modelDir = path.join(MODELS_DIR, cam.productModel.replace(/[/\\:*?"<>|]+/g, "_"));
  fs.mkdirSync(modelDir, { recursive: true });

  console.log(`\n📹 ${cam.nickname} (${cam.productModel}) @ ${cam.ip}`);

  // 1. Cloud info (sanitised)
  fs.writeFileSync(path.join(modelDir, "cloud-info.json"), JSON.stringify(sanitise(cam), null, 2));
  console.log("  ✅ cloud-info.json");

  // 2. Cloud events
  try {
    const events = await cloud.getEventList({ macs: [cam.mac], count: 5 });
    fs.writeFileSync(path.join(modelDir, "cloud-events.json"), JSON.stringify(sanitise(events), null, 2));
    console.log(`  ✅ cloud-events.json (${events.length} events)`);
  } catch (e: any) {
    fs.writeFileSync(path.join(modelDir, "cloud-events.json"), JSON.stringify({ error: e?.message }));
    console.log(`  ⚠️  cloud-events.json (${e?.message})`);
  }

  // 3. P2P connection + diagnostics
  let conn: WyzeDTLSConn | null = null;
  try {
    conn = new WyzeDTLSConn({
      host: cam.ip, uid: cam.p2pId, enr: cam.enr, mac: cam.mac, model: cam.productModel,
    });

    const { authInfo } = await conn.connect();
    fs.writeFileSync(path.join(modelDir, "auth-info.json"), JSON.stringify(sanitise(authInfo), null, 2));
    console.log("  ✅ auth-info.json");

    await conn.startVideo();
    await conn.startAudio();

    // 4. Probe stream (collect first keyframe + codec info)
    const streamProbe: any = { videoCodec: null, audioCodec: null, firstKeyframeSize: 0, framesIn5s: { video: 0, audio: 0 } };
    let keyframeSaved = false;

    await new Promise<void>((resolve) => {
      const timer = setTimeout(resolve, 5000);
      conn!.onPacket((pkt: Packet) => {
        if (isVideoCodec(pkt.codec)) {
          streamProbe.framesIn5s.video++;
          if (!streamProbe.videoCodec) {
            streamProbe.videoCodec = pkt.codec === 0x4e ? "H264" : pkt.codec === 0x50 ? "H265" : `0x${pkt.codec.toString(16)}`;
          }
          if (pkt.isKeyframe && !keyframeSaved) {
            keyframeSaved = true;
            streamProbe.firstKeyframeSize = pkt.payload.length;
            fs.writeFileSync(path.join(modelDir, "sample-keyframe.bin"), pkt.payload);
            console.log(`  ✅ sample-keyframe.bin (${pkt.payload.length}B)`);
          }
        }
        if (isAudioCodec(pkt.codec)) {
          streamProbe.framesIn5s.audio++;
          if (!streamProbe.audioCodec) {
            streamProbe.audioCodec = `0x${pkt.codec.toString(16)}`;
            streamProbe.audioSampleRate = pkt.sampleRate;
            streamProbe.audioChannels = pkt.channels;
          }
        }
      });
    });

    streamProbe.estimatedFps = Math.round(streamProbe.framesIn5s.video / 5);
    fs.writeFileSync(path.join(modelDir, "stream-probe.json"), JSON.stringify(streamProbe, null, 2));
    console.log(`  ✅ stream-probe.json (${streamProbe.videoCodec} ${streamProbe.estimatedFps}fps)`);

    // 5. Full diagnostics
    console.log("  🔍 Running diagnostics (this takes ~30s)...");
    const diag = await conn.runDiagnostics();
    // Sanitise any IP/MAC/ENR in diagnostics
    delete (diag as any)._host;
    delete (diag as any)._uid;
    fs.writeFileSync(path.join(modelDir, "diagnostics.json"), JSON.stringify(sanitise(diag), null, 2));
    console.log("  ✅ diagnostics.json");

    // 6. Capabilities probe
    try {
      const caps = await conn.probeCapabilities();
      fs.writeFileSync(path.join(modelDir, "capabilities.json"), JSON.stringify(caps, null, 2));
      console.log(`  ✅ capabilities.json (${JSON.stringify(caps)})`);
    } catch (e: any) {
      fs.writeFileSync(path.join(modelDir, "capabilities.json"), JSON.stringify({ error: e?.message }));
    }

  } catch (e: any) {
    console.error(`  ❌ P2P failed: ${e?.message}`);
    fs.writeFileSync(path.join(modelDir, "error.json"), JSON.stringify({ error: e?.message, stack: e?.stack }));
  } finally {
    conn?.close();
  }

  console.log(`  📁 Saved to ${modelDir}`);
}

async function main() {
  const creds = getCredentials();
  if (!creds.email || !creds.password || !creds.apiKey || !creds.keyId) {
    console.error("Usage: npx tsx test/capture-model-fixtures.ts <email> <password> <apiKey> <keyId>");
    console.error("   Or: set WYZE_EMAIL, WYZE_PASSWORD, WYZE_API_KEY, WYZE_KEY_ID env vars");
    process.exit(1);
  }

  console.log("☁️  Logging in...");
  const cloud = new WyzeCloud(creds.apiKey, creds.keyId);
  await cloud.login(creds.email, creds.password);
  const cameras = await cloud.getCameraList();
  console.log(`Found ${cameras.length} camera(s)\n`);

  for (const cam of cameras) {
    if (!cam.isOnline) {
      console.log(`⬜ Skipping offline: ${cam.nickname}`);
      continue;
    }
    await captureCamera(cam, cloud);
  }

  console.log("\n✅ Done! Fixtures saved to test/fixtures/models/");
  process.exit(0);
}

main().catch(e => { console.error("❌", e); process.exit(1); });
