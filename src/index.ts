/**
 * @apocaliss92/wyze-bridge-js — Wyze camera local P2P streaming bridge.
 * Node.js port of go2rtc/pkg/wyze + go2rtc/pkg/tutk.
 */

// Cloud API
export { WyzeCloud } from "./cloud/cloud.js";
export type { WyzeCamera, WyzeAccountConfig, WyzeAuthError } from "./cloud/types.js";
export type { WyzeEvent, WyzeEventFile, WyzeCloudSession, WyzeCloudOptions } from "./cloud/cloud.js";
export { buildStreamUrl } from "./cloud/types.js";

// P2P Connection
export { WyzeDTLSConn } from "./tutk/dtls/WyzeDTLSConn.js";
export type { WyzeDTLSConnOptions } from "./tutk/dtls/WyzeDTLSConn.js";

// RFC 4571 Server
export { createWyzeRfc4571Server } from "./rfc/WyzeRfc4571Server.js";
export type { WyzeRfc4571Server, WyzeRfc4571ServerOptions } from "./rfc/WyzeRfc4571Server.js";

// TUTK Protocol (low-level)
export {
  reverseTransCodePartial, reverseTransCodeBlob,
  transCodePartial, transCodeBlob,
  xxteaDecrypt, xxteaDecryptVar,
} from "./tutk/crypto.js";
export {
  CodecH264, CodecH265, CodecMJPEG, CodecPCMU, CodecPCMA,
  CodecAACADTS, CodecAACAlt, CodecAACRaw, CodecAACLATM, CodecOpus, CodecPCML, CodecMP3,
  isVideoCodec, isAudioCodec, getSampleRate, getChannels, getSamplesPerFrame,
} from "./tutk/codec.js";
export { genSessionId, icam, hl, parseHL, findHL } from "./tutk/helpers.js";
export {
  FrameHandler, parseFrameInfo, parsePacketHeader,
  isStartFrame, isEndFrame,
  ChannelIVideo, ChannelAudio, ChannelPVideo,
} from "./tutk/frame.js";
export { HLCommand, MediaType, CodecID } from "./tutk/types.js";
export { calculateAuthKey, derivePSK } from "./tutk/dtls/auth.js";

// Types
export type { Packet, FrameInfo, PacketHeader } from "./tutk/frame.js";
export type { TutkPacket } from "./tutk/types.js";
