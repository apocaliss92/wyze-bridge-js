import "dotenv/config";
import { WyzeCloud } from "./src/cloud/cloud.js";
import { createWyzeRfc4571Server } from "./src/rfc/WyzeRfc4571Server.js";

async function main() {
  const cloud = new WyzeCloud(process.env.WYZE_API_KEY!, process.env.WYZE_KEY_ID!);
  await cloud.login(process.env.WYZE_EMAIL!, process.env.WYZE_PASSWORD!);
  const cams = await cloud.getCameraList();
  const cam = cams.find(c => c.isOnline && c.dtls === 1)!;
  console.log("Camera:", cam.nickname);

  const server = await createWyzeRfc4571Server({ camera: cam, logger: console });
  console.log("\nSDP:\n" + server.sdp);

  const m = server.sdp.match(/sprop-parameter-sets=([^,]+)/);
  if (m) {
    const spsB64 = m[1]!;
    const sps = Buffer.from(spsB64, "base64");
    console.log("\nSPS NAL hex:", sps.toString("hex"));
    console.log("SPS length:", sps.length, "bytes");
    console.log("Profile:", sps[1], "Level:", sps[3]);
    // Check: vui_parameters_present_flag should be 0 (last meaningful bit before RBSP trailing)
    // A clean SPS for Main profile 1920x1080 should be ~15-18 bytes
    console.log("Clean?", sps.length < 30 ? "YES (short, no VUI)" : "MAYBE (still long)");
  }

  await server.close();
}
main().catch(e => { console.error(e); process.exit(1); });
