import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = path.join(__dirname, "..", "fixtures");
const MODELS_DIR = path.join(FIXTURES_DIR, "models");

function loadModelFixture(model: string, name: string): any {
  const p = path.join(MODELS_DIR, model, name);
  if (!fs.existsSync(p)) return null;
  if (name.endsWith(".bin")) return fs.readFileSync(p);
  return JSON.parse(fs.readFileSync(p, "utf-8"));
}

function getModels(): string[] {
  if (!fs.existsSync(MODELS_DIR)) return [];
  return fs.readdirSync(MODELS_DIR).filter(d =>
    fs.statSync(path.join(MODELS_DIR, d)).isDirectory()
  );
}

describe("Model fixture validation", () => {
  const models = getModels();

  if (models.length === 0) {
    it.skip("No model fixtures found (run: npx tsx test/capture-model-fixtures.ts)", () => {});
    return;
  }

  for (const model of models) {
    describe(model, () => {

      it("has cloud-info with required fields", () => {
        const info = loadModelFixture(model, "cloud-info.json");
        expect(info).not.toBeNull();
        expect(info).toHaveProperty("nickname");
        expect(info).toHaveProperty("productModel");
        expect(info.productModel).toBe(model);
        expect(info).toHaveProperty("firmwareVer");
        expect(info).toHaveProperty("dtls");
      });

      it("has auth-info from K10003", () => {
        const auth = loadModelFixture(model, "auth-info.json");
        expect(auth).not.toBeNull();
        // Auth response should be an object (may have connectionRes, cameraInfo)
        expect(typeof auth).toBe("object");
      });

      it("has stream-probe with video codec", () => {
        const probe = loadModelFixture(model, "stream-probe.json");
        expect(probe).not.toBeNull();
        expect(probe.videoCodec).toBeTruthy();
        expect(["H264", "H265"]).toContain(probe.videoCodec);
        expect(probe.estimatedFps).toBeGreaterThan(0);
        expect(probe.framesIn5s.video).toBeGreaterThan(0);
        expect(probe.firstKeyframeSize).toBeGreaterThan(0);
      });

      it("has sample-keyframe binary", () => {
        const kf = loadModelFixture(model, "sample-keyframe.bin");
        expect(kf).not.toBeNull();
        expect(Buffer.isBuffer(kf)).toBe(true);
        expect(kf.length).toBeGreaterThan(100);
        // H264 keyframe should start with Annex-B start code
        const hasStartCode = (kf[0] === 0 && kf[1] === 0 && kf[2] === 0 && kf[3] === 1) ||
                             (kf[0] === 0 && kf[1] === 0 && kf[2] === 1);
        expect(hasStartCode).toBe(true);
      });

      it("has diagnostics with known parameters", () => {
        const diag = loadModelFixture(model, "diagnostics.json");
        expect(diag).not.toBeNull();
        expect(diag).toHaveProperty("_timestamp");
        expect(diag).toHaveProperty("_model");
        expect(diag._model).toBe(model);

        // At least some parameters should be queryable
        const knownKeys = ["statusLight", "nightVision", "irLed", "videoParams", "cameraTime", "motionAlarm"];
        const foundKeys = knownKeys.filter(k => diag[k] !== undefined && !(diag[k]?.error));
        expect(foundKeys.length).toBeGreaterThan(0);
      });

      it("diagnostics nightVision is on/off/auto", () => {
        const diag = loadModelFixture(model, "diagnostics.json");
        if (!diag?.nightVision || diag.nightVision.error) return;
        expect(["on", "off", "auto"]).toContain(diag.nightVision.label);
      });

      it("diagnostics videoParams has resolution and fps", () => {
        const diag = loadModelFixture(model, "diagnostics.json");
        if (!diag?.videoParams || diag.videoParams.error) return;
        expect(diag.videoParams.resolution).toBeDefined();
        expect(diag.videoParams.fps).toBeGreaterThan(0);
        expect(diag.videoParams.bitrate).toBeGreaterThan(0);
      });

      it("diagnostics cameraTime is recent", () => {
        const diag = loadModelFixture(model, "diagnostics.json");
        if (!diag?.cameraTime || diag.cameraTime.error) return;
        const ts = diag.cameraTime.unixTimestamp;
        // Camera time should be within last year
        const now = Math.floor(Date.now() / 1000);
        expect(ts).toBeGreaterThan(now - 365 * 86400);
        expect(ts).toBeLessThan(now + 86400);
      });

      it("has capabilities probe", () => {
        const caps = loadModelFixture(model, "capabilities.json");
        expect(caps).not.toBeNull();
        if (caps.error) return; // Some cameras may fail capability probe
        expect(typeof caps.hasSpotlight).toBe("boolean");
        expect(typeof caps.hasSiren).toBe("boolean");
        expect(typeof caps.hasFloodlight).toBe("boolean");
      });

      it("diagnostics cameraInfo has numbered parameters", () => {
        const diag = loadModelFixture(model, "diagnostics.json");
        if (!diag?.cameraInfo || diag.cameraInfo.error) return;
        // K10020 returns numbered parameters (1, 2, 3, ...)
        const keys = Object.keys(diag.cameraInfo);
        const numericKeys = keys.filter(k => /^\d+$/.test(k));
        expect(numericKeys.length).toBeGreaterThan(5);
      });
    });
  }
});
