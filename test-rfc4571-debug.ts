/**
 * RFC4571 server debug — tests the full path including SDP generation.
 * Connects to camera, starts RFC4571 server, monitors stream health.
 *
 * Run:  npx tsx test-rfc4571-debug.ts
 */

import "dotenv/config";
import * as net from "node:net";
import { WyzeCloud } from "./src/cloud/cloud.js";
import { createWyzeRfc4571Server } from "./src/rfc/WyzeRfc4571Server.js";

const email = process.env.WYZE_EMAIL || "";
const password = process.env.WYZE_PASSWORD || "";
const apiKey = process.env.WYZE_API_KEY || "";
const keyId = process.env.WYZE_KEY_ID || "";

if (!email || !password || !apiKey || !keyId) {
  console.error("Missing env vars");
  process.exit(1);
}

async function main() {
  console.log("=== RFC4571 Server Debug ===\n");

  const cloud = new WyzeCloud(apiKey, keyId);
  await cloud.login(email, password);
  const cameras = await cloud.getCameraList();
  const cam = cameras.find(c => c.isOnline && c.dtls === 1);
  if (!cam) { console.error("No camera"); process.exit(1); }
  console.log(`Camera: ${cam.nickname} (${cam.ip})\n`);

  console.log("Creating RFC4571 server...");
  const server = await createWyzeRfc4571Server({
    camera: cam,
    verbose: true,
    logger: console,
  });

  console.log(`\nServer: tcp://${server.host}:${server.port}`);
  console.log(`Video: ${server.videoType}`);
  console.log(`SDP length: ${server.sdp.length}`);
  console.log(`SDP:\n${server.sdp}\n`);

  server.onClientDisconnect((remaining) => {
    console.log(`[EVENT] Client disconnected, remaining: ${remaining}`);
  });

  // Now connect a TCP client to simulate what the prebuffer does
  console.log("Connecting TCP client...");
  const client = net.createConnection(server.port, server.host);

  let bytesReceived = 0;
  let chunks = 0;
  const startedAt = Date.now();
  let lastChunkAt = Date.now();
  let lastLogAt = Date.now();

  client.on("data", (data) => {
    bytesReceived += data.length;
    chunks++;
    lastChunkAt = Date.now();

    if (Date.now() - lastLogAt > 5_000) {
      const elapsed = ((Date.now() - startedAt) / 1000).toFixed(1);
      const kbps = ((bytesReceived * 8) / (Date.now() - startedAt)).toFixed(0);
      console.log(`  [TCP] t=${elapsed}s chunks=${chunks} bytes=${bytesReceived} kbps=${kbps}`);
      lastLogAt = Date.now();
    }
  });

  client.on("close", () => {
    const elapsed = ((Date.now() - startedAt) / 1000).toFixed(1);
    console.log(`\n  [TCP CLOSED] after ${elapsed}s — chunks=${chunks} bytes=${bytesReceived}`);
  });

  client.on("error", (e) => {
    console.log(`  [TCP ERROR] ${e.message}`);
  });

  // Silence detector
  const silenceCheck = setInterval(() => {
    const silence = Date.now() - lastChunkAt;
    if (silence > 3_000 && chunks > 0) {
      console.log(`  ⚠️  TCP silence: ${(silence / 1000).toFixed(1)}s`);
    }
    if (silence > 15_000 && chunks > 0) {
      console.log("  ❌ TCP dead after 15s silence");
      clearInterval(silenceCheck);
      client.destroy();
    }
  }, 2_000);

  // Run for 60s
  console.log("Monitoring for 60 seconds...\n");
  await new Promise(r => setTimeout(r, 60_000));

  console.log("\nClosing...");
  clearInterval(silenceCheck);
  client.destroy();
  await server.close();
  const elapsed = ((Date.now() - startedAt) / 1000).toFixed(1);
  console.log(`Done. ${elapsed}s total, ${chunks} chunks, ${(bytesReceived / 1024).toFixed(0)}KB`);
}

main().catch(e => { console.error("Fatal:", e); process.exit(1); });
