/**
 * TUTK/IOTC protocol types.
 *
 * TODO: Port from go2rtc/pkg/tutk/
 * - conn.go: IOTC P2P connection (UDP hole punching, session management)
 * - frame.go: AV frame parsing (video/audio packet structure)
 * - helpers.go: HL protocol helpers
 * - session0.go / session16.go / session25.go: Session negotiation variants
 * - codec.go: Codec ID constants
 */

/** TUTK media types. */
export const MediaType = {
  Video: 1,
  Audio: 2,
  ReturnAudio: 3,
  RDT: 4,
} as const;

/** TUTK codec IDs (from go2rtc/pkg/tutk/codec.go). */
export const CodecID = {
  // Video
  H264: 0x4c,
  H265: 0x4e,
  MJPEG: 0x4a,
  // Audio
  PCMU: 0x89,     // G.711 μ-law
  PCMA: 0x8a,     // G.711 A-law
  AAC_ADTS: 0x8b,
  AAC_ALT: 0x8e,
  AAC_RAW: 0x8f,
  AAC_LATM: 0x90,
  Opus: 0x91,
  PCML: 0x92,     // PCM 16-bit LE
  MP3: 0x93,
} as const;

/** Parsed AV frame from the TUTK stream. */
export interface TutkPacket {
  codec: number;
  frameNo: number;
  timestamp: number;
  payload: Buffer;
  sampleRate?: number;
  channels?: number;
}

/** HL command IDs (Wyze authentication protocol). */
export const HLCommand = {
  Auth: 10000,
  Challenge: 10001,
  ChallengeResp: 10002,
  AuthResult: 10003,
  ControlChannel: 10010,
  ControlChannelResp: 10011,
  SetResolutionDB: 10052,
  SetResolutionDBRes: 10053,
  SetResolution: 10056,
  SetResolutionResp: 10057,
} as const;
