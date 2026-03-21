/**
 * Wyze Cloud API — login and device discovery.
 *
 * Ported from go2rtc/pkg/wyze/cloud.go.
 * Uses the Wyze auth + device list APIs to discover cameras
 * and their P2P connection parameters (UID, ENR, IP, DTLS).
 */

import { createHash, randomBytes } from "node:crypto";
import type { WyzeCamera, WyzeAuthError } from "./types.js";

const BASE_URL_AUTH = "https://auth-prod.api.wyze.com";
const BASE_URL_API = "https://api.wyzecam.com";
const APP_NAME = "com.hualai.WyzeCam";
const APP_VERSION = "2.50.0";

/** Triple-MD5 hash the password (same as Wyze app). */
function hashPassword(password: string): string {
  let encoded = password.trim();
  if (encoded.toLowerCase().startsWith("md5:")) {
    return encoded.slice(4);
  }
  for (let i = 0; i < 3; i++) {
    encoded = createHash("md5").update(encoded).digest("hex");
  }
  return encoded;
}

/** Generate a random phone ID (16 hex chars). */
function generatePhoneId(): string {
  return randomBytes(8).toString("hex");
}

// ─── Response types ─────────────────────────────────────────────

interface LoginResponse {
  access_token?: string;
  refresh_token?: string;
  user_id?: string;
  mfa_options?: string[];
  sms_session_id?: string;
  email_session_id?: string;
}

interface DeviceParams {
  p2p_id?: string;
  p2p_type?: number;
  ip?: string;
  dtls?: number;
}

interface DeviceInfo {
  mac: string;
  enr: string;
  nickname: string;
  product_model: string;
  product_type: string;
  firmware_ver: string;
  conn_state: number;
  device_params: DeviceParams;
}

interface DeviceListResponse {
  code: string;
  msg: string;
  data: {
    device_list: DeviceInfo[];
  };
}

interface ApiErrorResponse {
  code?: string;
  errorCode?: number;
  msg?: string;
  description?: string;
}

// ─── Cloud client ───────────────────────────────────────────────

export class WyzeCloud {
  private apiKey: string;
  private keyId: string;
  private phoneId: string;
  private accessToken: string | null = null;
  private cameras: WyzeCamera[] = [];

  constructor(apiKey: string, apiId: string) {
    this.apiKey = apiKey;
    this.keyId = apiId;
    this.phoneId = generatePhoneId();
  }

  /**
   * Login to Wyze cloud.
   * @throws WyzeAuthError if MFA is required
   */
  async login(email: string, password: string): Promise<void> {
    const payload = {
      email: email.trim(),
      password: hashPassword(password),
    };

    const res = await fetch(`${BASE_URL_AUTH}/api/user/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Apikey: this.apiKey,
        Keyid: this.keyId,
        "User-Agent": "go2rtc",
      },
      body: JSON.stringify(payload),
    });

    const body = await res.json() as LoginResponse & ApiErrorResponse;

    // Check for API errors
    if (body.code && body.code !== "1" && body.code !== "0") {
      throw new Error(`Wyze login failed (code ${body.code}): ${body.msg || body.description || "Unknown error"}`);
    }
    if (body.errorCode && body.errorCode !== 0) {
      throw new Error(`Wyze login failed (error ${body.errorCode}): ${body.msg || body.description || "Unknown error"}`);
    }

    // Check for MFA
    if (body.mfa_options && body.mfa_options.length > 0) {
      const err: WyzeAuthError = {
        message: "MFA required",
        needsMfa: true,
        mfaType: body.mfa_options.join(","),
      };
      throw err;
    }

    if (!body.access_token) {
      throw new Error("Wyze: no access token in response");
    }

    this.accessToken = body.access_token;
  }

  /**
   * Get list of cameras from Wyze cloud.
   * Only returns cameras with IP addresses (skip Gwell-based cameras).
   */
  async getCameraList(): Promise<WyzeCamera[]> {
    if (!this.accessToken) {
      throw new Error("Wyze: not logged in");
    }

    const payload = {
      access_token: this.accessToken,
      phone_id: this.phoneId,
      app_name: APP_NAME,
      app_ver: `${APP_NAME}___${APP_VERSION}`,
      app_version: APP_VERSION,
      phone_system_type: 1,
      sc: "9f275790cab94a72bd206c8876429f3c",
      sv: "9d74946e652647e9b6c9d59326aef104",
      ts: Date.now(),
    };

    const res = await fetch(`${BASE_URL_API}/app/v2/home_page/get_object_list`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const body = await res.json() as DeviceListResponse;

    if (body.code !== "1") {
      throw new Error(`Wyze API error: ${body.code} - ${body.msg}`);
    }

    this.cameras = [];
    for (const dev of body.data.device_list) {
      if (dev.product_type !== "Camera") continue;
      if (!dev.device_params.ip) continue; // skip cameras without IP (gwell protocol)

      this.cameras.push({
        mac: dev.mac,
        p2pId: dev.device_params.p2p_id ?? "",
        enr: dev.enr,
        ip: dev.device_params.ip,
        nickname: dev.nickname,
        productModel: dev.product_model,
        productType: dev.product_type,
        dtls: dev.device_params.dtls ?? 0,
        firmwareVer: dev.firmware_ver,
        isOnline: dev.conn_state === 1,
      });
    }

    return this.cameras;
  }

  /**
   * Find a camera by MAC or nickname.
   */
  async getCamera(id: string): Promise<WyzeCamera | null> {
    if (this.cameras.length === 0) {
      await this.getCameraList();
    }

    const upper = id.toUpperCase();
    return (
      this.cameras.find(
        (c) => c.mac.toUpperCase() === upper || c.nickname.toLowerCase() === id.toLowerCase(),
      ) ?? null
    );
  }

  // ─── Events API ────────────────────────────────────────────────

  /**
   * Get event list from Wyze cloud.
   * Events include motion, sound, doorbell, face detection etc.
   * Each event may have associated files (thumbnails, video clips).
   *
   * @param macs - Filter by camera MAC addresses (empty = all cameras)
   * @param beginTime - Start time in ms (default: 24h ago)
   * @param endTime - End time in ms (default: now)
   * @param count - Max events to return (default: 20)
   */
  async getEventList(options?: {
    macs?: string[];
    beginTime?: number;
    endTime?: number;
    count?: number;
  }): Promise<WyzeEvent[]> {
    if (!this.accessToken) throw new Error("Wyze: not logged in");

    const now = Date.now();
    const payload = {
      access_token: this.accessToken,
      phone_id: this.phoneId,
      app_name: APP_NAME,
      app_ver: `${APP_NAME}___${APP_VERSION}`,
      app_version: APP_VERSION,
      phone_system_type: 1,
      sc: "9f275790cab94a72bd206c8876429f3c",
      sv: "9d74946e652647e9b6c9d59326aef104",
      ts: now,
      count: options?.count ?? 20,
      order_by: 2,
      begin_time: options?.beginTime ?? now - 86400000,
      end_time: options?.endTime ?? now + 60000,
      device_mac_list: options?.macs ?? [],
      event_value_list: [],
      event_tag_list: [],
    };

    const res = await fetch(`${BASE_URL_API}/app/v2/device/get_event_list`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const body = await res.json() as any;
    if (body.code !== "1") {
      throw new Error(`Wyze events API error: ${body.code} - ${body.msg}`);
    }

    const events: WyzeEvent[] = [];
    for (const ev of body.data?.event_list ?? []) {
      const files: WyzeEventFile[] = [];
      for (const f of ev.file_list ?? []) {
        files.push({
          fileId: f.file_id,
          type: f.type === 1 ? "image" : f.type === 2 ? "video" : "unknown",
          url: f.url ?? "",
          status: f.status,
        });
      }

      events.push({
        eventId: ev.event_id,
        deviceMac: ev.device_mac,
        deviceModel: ev.device_model,
        timestamp: ev.event_ts,
        alarmType: parseAlarmType(ev.event_value),
        aiTags: (ev.tag_list ?? []).map(parseAiTag).filter(Boolean) as string[],
        files,
        isRead: ev.read_state === 1,
      });
    }

    return events;
  }

  /** Get the access token (needed for downloading event files). */
  getAccessToken(): string | null {
    return this.accessToken;
  }
}

// ─── Event types ────────────────────────────────────────────────

export interface WyzeEvent {
  eventId: string;
  deviceMac: string;
  deviceModel: string;
  timestamp: number;
  alarmType: string; // "motion" | "sound" | "smoke" | "co" | "doorbell" | "face" | "unknown"
  aiTags: string[];  // "person" | "vehicle" | "pet" | "package" etc.
  files: WyzeEventFile[];
  isRead: boolean;
}

export interface WyzeEventFile {
  fileId: string;
  type: "image" | "video" | "unknown";
  url: string;
  status: number;
}

function parseAlarmType(value: number | string): string {
  const code = typeof value === "string" ? parseInt(value) : value;
  switch (code) {
    case 1: case 6: case 7: case 13: return "motion";
    case 2: return "sound";
    case 4: return "smoke";
    case 5: return "co";
    case 8: return "triggered";
    case 10: return "doorbell";
    case 11: return "scene";
    case 12: return "face";
    default: return "unknown";
  }
}

function parseAiTag(code: number): string | null {
  switch (code) {
    case 101: return "person";
    case 102: return "vehicle";
    case 103: return "pet";
    case 104: return "package";
    case 800001: return "baby_crying";
    case 800002: return "dog_barking";
    case 800003: return "cat_meowing";
    default: return null;
  }
}
