/**
 * Wyze Cloud API types.
 */

export interface WyzeCamera {
  mac: string;
  p2pId: string;
  enr: string;
  ip: string;
  nickname: string;
  productModel: string;
  productType: string;
  dtls: number;
  firmwareVer: string;
  isOnline: boolean;
}

export interface WyzeAccountConfig {
  apiKey: string;
  apiId: string;
  email: string;
  password: string;
}

export interface WyzeAuthError {
  message: string;
  needsMfa: boolean;
  mfaType?: string;
}

/** Build the local stream URL for a Wyze camera. */
export function buildStreamUrl(cam: WyzeCamera): string {
  const params = new URLSearchParams({
    uid: cam.p2pId,
    enr: cam.enr,
    mac: cam.mac,
    model: cam.productModel,
  });
  if (cam.dtls === 1) {
    params.set("dtls", "true");
  }
  return `wyze://${cam.ip}?${params.toString()}`;
}
