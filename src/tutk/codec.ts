/**
 * TUTK codec constants and helpers.
 * Ported from go2rtc/pkg/tutk/codec.go
 */

// Video codecs
export const CodecMPEG4 = 0x4c;
export const CodecH263 = 0x4d;
export const CodecH264 = 0x4e;
export const CodecMJPEG = 0x4f;
export const CodecH265 = 0x50;

// Audio codecs
export const CodecAACRaw = 0x86;
export const CodecAACADTS = 0x87;
export const CodecAACLATM = 0x88;
export const CodecPCMU = 0x89;
export const CodecPCMA = 0x8a;
export const CodecADPCM = 0x8b;
export const CodecPCML = 0x8c;
export const CodecSPEEX = 0x8d;
export const CodecMP3 = 0x8e;
export const CodecG726 = 0x8f;
export const CodecAACAlt = 0x90;
export const CodecOpus = 0x92;

const SAMPLE_RATES = [8000, 11025, 12000, 16000, 22050, 24000, 32000, 44100, 48000] as const;

export function getSampleRateIndex(sampleRate: number): number {
  const idx = SAMPLE_RATES.indexOf(sampleRate as any);
  return idx >= 0 ? idx : 3; // default 16kHz
}

export function getSamplesPerFrame(codecId: number): number {
  switch (codecId) {
    case CodecAACRaw: case CodecAACADTS: case CodecAACLATM: case CodecAACAlt:
      return 1024;
    case CodecPCMU: case CodecPCMA: case CodecPCML: case CodecADPCM: case CodecSPEEX: case CodecG726:
      return 160;
    case CodecMP3:
      return 1152;
    case CodecOpus:
      return 960;
    default:
      return 1024;
  }
}

export function isVideoCodec(id: number): boolean {
  return id >= CodecMPEG4 && id <= CodecH265;
}

export function isAudioCodec(id: number): boolean {
  return id >= CodecAACRaw && id <= CodecOpus;
}

export function getSampleRate(flagsByte: number): number {
  const idx = (flagsByte >> 2) & 0x0f;
  return idx < SAMPLE_RATES.length ? SAMPLE_RATES[idx]! : 16000;
}

export function getChannels(flagsByte: number): number {
  return (flagsByte & 0x01) === 1 ? 2 : 1;
}
