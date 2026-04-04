/**
 * P2P connection debug script.
 * Connects to a Wyze camera, streams video, and logs detailed diagnostics
 * to understand why the connection drops.
 *
 * Run:  npx tsx test-p2p-debug.ts
 * Env:  WYZE_EMAIL, WYZE_PASSWORD, WYZE_API_KEY, WYZE_KEY_ID (or .env file)
 */

import "dotenv/config";
import { WyzeCloud } from "./src/cloud/cloud.js";
import { WyzeDTLSConn } from "./src/tutk/dtls/WyzeDTLSConn.js";
import { isVideoCodec, isAudioCodec } from "./src/tutk/codec.js";
import type { Packet } from "./src/tutk/frame.js";

const email = process.env.WYZE_EMAIL || "";
const password = process.env.WYZE_PASSWORD || "";
const apiKey = process.env.WYZE_API_KEY || "";
const keyId = process.env.WYZE_KEY_ID || "";

if (!email || !password || !apiKey || !keyId) {
  console.error("Missing env vars. Set WYZE_EMAIL, WYZE_PASSWORD, WYZE_API_KEY, WYZE_KEY_ID");
  process.exit(1);
}

async function main() {
  console.log("=== Wyze P2P Debug ===\n");

  // 1. Cloud login + discover cameras
  console.log("[1] Logging in to Wyze Cloud...");
  const cloud = new WyzeCloud(apiKey, keyId);
  await cloud.login(email, password);
  console.log("    Login OK");

  const cameras = await cloud.getCameraList();
  console.log(`    Found ${cameras.length} camera(s):`);
  for (const cam of cameras) {
    console.log(`      - ${cam.nickname} (${cam.productModel}) IP=${cam.ip} online=${cam.isOnline} dtls=${cam.dtls}`);
  }

  const cam = cameras.find(c => c.isOnline && c.dtls === 1);
  if (!cam) {
    console.error("No online DTLS camera found!");
    process.exit(1);
  }
  console.log(`\n[2] Using: ${cam.nickname} (${cam.ip})\n`);

  // 2. P2P connection
  console.log("[3] Connecting P2P/DTLS...");
  const conn = new WyzeDTLSConn({
    host: cam.ip,
    uid: cam.p2pId,
    enr: cam.enr,
    mac: cam.mac,
    model: cam.productModel,
    verbose: true,
    logger: console,
  });

  const { hasTwoWay, authInfo } = await conn.connect();
  console.log(`    Connected! twoWay=${hasTwoWay}`);
  console.log(`    Auth info:`, JSON.stringify(authInfo).slice(0, 200));

  // 3. Start video
  console.log("\n[4] Starting video stream...");
  await conn.startVideo(0, 0xF0);
  await conn.startAudio();
  console.log("    Video+Audio started\n");

  // 4. Monitor frames
  let videoFrames = 0;
  let audioFrames = 0;
  let keyframes = 0;
  let totalBytes = 0;
  let lastFrameAt = Date.now();
  const startedAt = Date.now();
  let lastLogAt = Date.now();

  conn.onPacket((pkt: Packet) => {
    const now = Date.now();
    const gap = now - lastFrameAt;
    lastFrameAt = now;
    totalBytes += pkt.payload.length;

    if (isVideoCodec(pkt.codec)) {
      videoFrames++;
      if (pkt.isKeyframe) {
        keyframes++;
        const elapsed = ((now - startedAt) / 1000).toFixed(1);
        console.log(
          `  [KEYFRAME #${keyframes}] t=${elapsed}s video=${videoFrames} audio=${audioFrames} ` +
          `size=${pkt.payload.length} gap=${gap}ms totalKB=${(totalBytes / 1024).toFixed(0)}`,
        );
      }
    } else if (isAudioCodec(pkt.codec)) {
      audioFrames++;
    }

    // Log every 5 seconds
    if (now - lastLogAt > 5_000) {
      const elapsed = ((now - startedAt) / 1000).toFixed(1);
      const fps = videoFrames / ((now - startedAt) / 1000);
      console.log(
        `  [STATS] t=${elapsed}s video=${videoFrames} audio=${audioFrames} ` +
        `keyframes=${keyframes} fps=${fps.toFixed(1)} gap=${gap}ms totalKB=${(totalBytes / 1024).toFixed(0)}`,
      );
      lastLogAt = now;
    }
  });

  // 5. Silence detector
  const silenceCheck = setInterval(() => {
    const silenceMs = Date.now() - lastFrameAt;
    if (silenceMs > 3_000) {
      const elapsed = ((Date.now() - startedAt) / 1000).toFixed(1);
      console.log(
        `\n  ⚠️  SILENCE: no frames for ${(silenceMs / 1000).toFixed(1)}s! ` +
        `(t=${elapsed}s total video=${videoFrames} audio=${audioFrames} keyframes=${keyframes})`,
      );
    }
    if (silenceMs > 15_000) {
      console.log("\n  ❌ CONNECTION DEAD — no frames for 15s. Exiting.");
      clearInterval(silenceCheck);
      conn.close();
      process.exit(1);
    }
  }, 2_000);

  // Let it run for 2 minutes max
  console.log("[5] Monitoring for up to 2 minutes...\n");
  await new Promise(r => setTimeout(r, 120_000));

  console.log("\n[6] Test complete. Closing...");
  clearInterval(silenceCheck);
  conn.close();
  const elapsed = ((Date.now() - startedAt) / 1000).toFixed(1);
  console.log(
    `    Final: ${elapsed}s  video=${videoFrames} audio=${audioFrames} ` +
    `keyframes=${keyframes} totalKB=${(totalBytes / 1024).toFixed(0)}`,
  );
}

main().catch(e => {
  console.error("Fatal:", e);
  process.exit(1);
});
