/**
 * Wyze stream producer — probes codecs and produces AV packets.
 * Ported from go2rtc/pkg/wyze/producer.go
 *
 * The producer:
 * 1. Connects to a Wyze camera via WyzeClient
 * 2. Probes for video/audio codecs (reads first frames)
 * 3. Emits parsed packets (H264/H265 + audio)
 *
 * These packets can then be fed to a BaichuanRtspServer or
 * registered as a go2rtc source.
 */

import { EventEmitter } from "node:events";
import { WyzeClient, type WyzeClientOptions } from "./client.js";
import { FrameHandler, type Packet, ChannelAudio } from "../tutk/frame.js";
import {
  CodecH264, CodecH265, CodecPCMU, CodecPCMA,
  CodecAACADTS, CodecAACAlt, CodecAACRaw, CodecAACLATM,
  CodecOpus, CodecPCML, CodecMP3, CodecMJPEG,
  isVideoCodec, isAudioCodec,
} from "../tutk/codec.js";

export interface ProducerCodecInfo {
  video?: { codec: number; codecName: string };
  audio?: { codec: number; codecName: string; sampleRate: number; channels: number };
  hasIntercom: boolean;
}

const CODEC_NAMES: Record<number, string> = {
  [CodecH264]: "H264",
  [CodecH265]: "H265",
  [CodecMJPEG]: "MJPEG",
  [CodecPCMU]: "PCMU",
  [CodecPCMA]: "PCMA",
  [CodecAACADTS]: "AAC",
  [CodecAACAlt]: "AAC",
  [CodecAACRaw]: "AAC",
  [CodecAACLATM]: "AAC",
  [CodecOpus]: "Opus",
  [CodecPCML]: "PCM",
  [CodecMP3]: "MP3",
};

/**
 * WyzeProducer — connects to a Wyze camera and produces AV packets.
 *
 * Usage:
 * ```ts
 * const producer = new WyzeProducer({ host, uid, enr, mac, model });
 * producer.on("packet", (pkt: Packet) => { ... });
 *
 * const codecs = await producer.probe();
 * console.log("Video:", codecs.video?.codecName, "Audio:", codecs.audio?.codecName);
 *
 * // Start continuous streaming
 * producer.start();
 * ```
 */
export class WyzeProducer extends EventEmitter {
  private client: WyzeClient;
  private frameHandler: FrameHandler;
  private probeTimeout = 10_000;

  constructor(options: WyzeClientOptions) {
    super();
    this.client = new WyzeClient(options);
    this.frameHandler = new FrameHandler(options.verbose ?? false);

    // Forward packets from frame handler
    this.frameHandler.setHandler((pkt) => {
      this.emit("packet", pkt);
    });
  }

  /**
   * Probe the camera for available codecs.
   * Connects, authenticates, and reads frames until both
   * video and audio codecs are detected (or timeout).
   */
  async probe(quality: number = 0): Promise<ProducerCodecInfo> {
    const result: ProducerCodecInfo = { hasIntercom: false };

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        cleanup();
        resolve(result); // Return whatever we found
      }, this.probeTimeout);

      const cleanup = () => {
        clearTimeout(timer);
        this.frameHandler.setHandler(() => {}); // stop processing
      };

      this.frameHandler.setHandler((pkt: Packet) => {
        if (!result.video && isVideoCodec(pkt.codec)) {
          result.video = {
            codec: pkt.codec,
            codecName: CODEC_NAMES[pkt.codec] ?? `0x${pkt.codec.toString(16)}`,
          };
        }

        if (!result.audio && isAudioCodec(pkt.codec) && pkt.channel === ChannelAudio) {
          result.audio = {
            codec: pkt.codec,
            codecName: CODEC_NAMES[pkt.codec] ?? `0x${pkt.codec.toString(16)}`,
            sampleRate: pkt.sampleRate,
            channels: pkt.channels,
          };
        }

        if (result.video && result.audio) {
          cleanup();
          result.hasIntercom = this.client.hasIntercom;
          resolve(result);
        }
      });
    });
  }

  /** Feed raw AV data to the frame parser. */
  feedData(data: Buffer): void {
    this.frameHandler.handle(data);
  }

  /** Get the underlying client for sending commands. */
  getClient(): WyzeClient {
    return this.client;
  }

  close(): void {
    this.client.close();
    this.frameHandler.close();
  }
}
