export { calculateAuthKey, derivePSK } from "./auth.js";
export { ChaCha20Poly1305Cipher, computeNonce, generateAAD } from "./cipher.js";
export { WyzeDTLSConn } from "./WyzeDTLSConn.js";
export type { WyzeDTLSConnOptions } from "./WyzeDTLSConn.js";

export const CIPHER_SUITE_ID_CCAC = 0xccac;
