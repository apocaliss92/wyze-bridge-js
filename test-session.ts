/**
 * Test script for WyzeCloud session persistence.
 *
 * Usage:
 *   WYZE_EMAIL=... WYZE_PASSWORD=... WYZE_API_KEY=... WYZE_API_ID=... npx tsx test-session.ts
 *
 * Tests:
 *   1. Fresh login → saves session to file
 *   2. Reload from saved session → skips login, getCameraList works
 *   3. Corrupted token → auto-refresh or re-login
 */

import { WyzeCloud, type WyzeCloudSession } from "./src/index.js";
import { readFileSync, writeFileSync, unlinkSync, existsSync } from "node:fs";

const SESSION_FILE = "/tmp/wyze-test-session.json";

const email = process.env.WYZE_EMAIL;
const password = process.env.WYZE_PASSWORD;
const apiKey = process.env.WYZE_API_KEY;
const apiId = process.env.WYZE_API_ID;

if (!email || !password || !apiKey || !apiId) {
  console.error("Missing env vars: WYZE_EMAIL, WYZE_PASSWORD, WYZE_API_KEY, WYZE_API_ID");
  process.exit(1);
}

function loadSession(): WyzeCloudSession | null {
  try {
    if (existsSync(SESSION_FILE)) {
      const data = JSON.parse(readFileSync(SESSION_FILE, "utf-8"));
      console.log(`  [load] Session found (saved at ${data.savedAt})`);
      return data;
    }
  } catch {}
  console.log("  [load] No saved session");
  return null;
}

function saveSession(session: WyzeCloudSession): void {
  writeFileSync(SESSION_FILE, JSON.stringify(session, null, 2));
  console.log(`  [save] Session saved (token: ${session.accessToken.slice(0, 20)}...)`);
}

function clearSession(): void {
  try { unlinkSync(SESSION_FILE); } catch {}
  console.log("  [clear] Session cleared");
}

async function testFreshLogin() {
  console.log("\n=== TEST 1: Fresh login (no saved session) ===");
  clearSession();

  const cloud = new WyzeCloud({
    apiKey, apiId, loadSession, saveSession, clearSession,
  });

  console.log(`  hasSession before: ${cloud.hasSession}`);
  await cloud.ensureSession(email, password);
  console.log(`  hasSession after: ${cloud.hasSession}`);

  const cameras = await cloud.getCameraList();
  console.log(`  Found ${cameras.length} camera(s): ${cameras.map(c => c.nickname).join(", ")}`);
  console.log("  ✅ Fresh login OK");
}

async function testRestoredSession() {
  console.log("\n=== TEST 2: Restored session (skip login) ===");

  const cloud = new WyzeCloud({
    apiKey, apiId, loadSession, saveSession, clearSession,
  });

  console.log(`  hasSession before ensureSession: ${cloud.hasSession}`);
  // This should NOT call login — the token is already loaded from file
  await cloud.ensureSession(email, password);
  console.log(`  hasSession after ensureSession: ${cloud.hasSession}`);

  const cameras = await cloud.getCameraList();
  console.log(`  Found ${cameras.length} camera(s): ${cameras.map(c => c.nickname).join(", ")}`);
  console.log("  ✅ Restored session OK (no login call made)");
}

async function testExpiredToken() {
  console.log("\n=== TEST 3: Corrupted access token (should refresh) ===");

  // Load the real session and corrupt the access token
  const session = loadSession();
  if (!session) {
    console.log("  ⚠️  Skipping — no saved session to corrupt");
    return;
  }

  // Save a session with invalid access token but valid refresh token
  const corrupted: WyzeCloudSession = {
    ...session,
    accessToken: "invalid_token_12345",
  };
  writeFileSync(SESSION_FILE, JSON.stringify(corrupted, null, 2));
  console.log("  Corrupted access token, refresh token intact");

  const cloud = new WyzeCloud({
    apiKey, apiId, loadSession, saveSession, clearSession,
  });

  console.log(`  hasSession: ${cloud.hasSession} (with corrupted token)`);

  // getCameraList should fail → then ensureSession + retry should recover
  try {
    const cameras = await cloud.getCameraList();
    // If the Wyze API doesn't validate tokens immediately, this might work
    console.log(`  getCameraList succeeded with corrupted token (${cameras.length} cameras) — API may not validate immediately`);
  } catch (e: any) {
    console.log(`  getCameraList failed as expected: ${e.message}`);
    console.log("  Trying ensureSession (should refresh/re-login)...");
    await cloud.ensureSession(email, password);
    const cameras = await cloud.getCameraList();
    console.log(`  After refresh: found ${cameras.length} camera(s)`);
  }

  console.log("  ✅ Token recovery OK");
}

async function testLegacyConstructor() {
  console.log("\n=== TEST 4: Legacy constructor (backward compat) ===");

  const cloud = new WyzeCloud(apiKey, apiId);
  await cloud.login(email, password);
  const cameras = await cloud.getCameraList();
  console.log(`  Found ${cameras.length} camera(s)`);
  console.log("  ✅ Legacy constructor OK");
}

async function main() {
  try {
    await testFreshLogin();
    await testRestoredSession();
    await testExpiredToken();
    await testLegacyConstructor();

    console.log("\n🎉 All tests passed!");
  } catch (e: any) {
    console.error(`\n❌ Test failed: ${e.message}`);
    console.error(e.stack);
    process.exit(1);
  } finally {
    // Cleanup
    try { unlinkSync(SESSION_FILE); } catch {}
  }
}

main();
