// Frame protocol: every QR frame is fully self-describing, so there is NO
// handshake — the receiver locks onto a stream mid-flight, and a new session
// id on any frame simply starts a fresh transfer.
//
// Layout (little-endian), 20 bytes, followed by `blockLen` payload bytes:
//   0  u8   magic 0xD1
//   1  u8   version  (see PROTO_VERSION below)
//   2  u16  sessionId   random per sender start
//   4  u32  seq         drives the fountain PRNG (see fountain.ts)
//   8  u16  k           source block count
//  10  u16  blockLen    payload bytes per frame
//  12  u32  totalLen    encrypted ciphertext length (IV + ciphertext + auth tag)
//  16  u32  payloadFnv  FNV-1a of the encrypted bytes — verified on completion
//
// Protocol versioning:
//   v0 (original): byte 1 = 0x0C (second magic). Raw uncompressed payload.
//   v1: byte 1 = 0x01. gzip-compressed payload.
//   v2: byte 1 = 0x02. gzip-compressed THEN AES-256-GCM encrypted payload.
//       Key is delivered out-of-band via a separate QR code shown at session start.
//       Wire format of encrypted blob: [12-byte IV || AES-GCM ciphertext+auth-tag].
//
// Backward compatibility: parseFrame rejects any version not in ACCEPTED_VERSIONS,
// returning null (clean failure, no silent corruption or misparse).

export const HEADER_LEN = 20;
const MAGIC0 = 0xd1;
export const PROTO_VERSION = 0x02;

// Upper bounds for frame header fields — defence against malformed/malicious QR streams.
// A frame that passes these checks can be safely decoded without risking unbounded
// memory allocation on the receiver.
//
// MAX_K: k is u16 (0–65,535). LTDecoder allocates solved[k] (Uint32Array or null
//   per block) and solitonCdf(k) (Float64Array). With blockLen=2953 each solved block
//   is ceil(2953/4)×4 = 2,956 bytes; 65,535 × 2,956 ≈ 187 MB worst-case — tolerable
//   for a receiver on a real device. No separate cap on k is needed beyond the u16 wire
//   max, since blockLen is independently capped.
// MAX_BLOCK_LEN: QR V40 at error correction L holds 2,953 bytes maximum. A blockLen
//   above this cannot have originated from a real QR code — reject it.
// MAX_TOTAL_LEN: u32 wire max is ~4 GB. Cap at 500 MB to prevent downstream issues
//   from a corrupted frame claiming an enormous payload before any real validation.
export const MAX_BLOCK_LEN = 2953; // QR V40 ECC-L maximum payload bytes
export const MAX_TOTAL_LEN = 500 * 1024 * 1024; // 500 MB ceiling

// Accepted version bytes. A v2 receiver rejects v0/v1 frames; this is intentional
// — a v0/v1 sender and v2 receiver are not protocol-compatible.
const ACCEPTED_VERSIONS = new Set([PROTO_VERSION]);

export interface FrameHeader {
  version: number;
  sessionId: number;
  seq: number;
  k: number;
  blockLen: number;
  totalLen: number;
  payloadFnv: number;
}

export function packFrame(h: FrameHeader, block: Uint8Array): Uint8Array {
  const out = new Uint8Array(HEADER_LEN + block.length);
  const dv = new DataView(out.buffer);
  dv.setUint8(0, MAGIC0);
  dv.setUint8(1, h.version);
  dv.setUint16(2, h.sessionId, true);
  dv.setUint32(4, h.seq, true);
  dv.setUint16(8, h.k, true);
  dv.setUint16(10, h.blockLen, true);
  dv.setUint32(12, h.totalLen, true);
  dv.setUint32(16, h.payloadFnv, true);
  out.set(block, HEADER_LEN);
  return out;
}

export function parseFrame(
  bytes: Uint8Array,
): { header: FrameHeader; block: Uint8Array } | null {
  if (bytes.length <= HEADER_LEN) return null;
  if (bytes[0] !== MAGIC0) return null;
  const version = bytes[1]!;
  if (!ACCEPTED_VERSIONS.has(version)) return null;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const header: FrameHeader = {
    version,
    sessionId: dv.getUint16(2, true),
    seq: dv.getUint32(4, true),
    k: dv.getUint16(8, true),
    blockLen: dv.getUint16(10, true),
    totalLen: dv.getUint32(12, true),
    payloadFnv: dv.getUint32(16, true),
  };
  if (header.k === 0 || header.blockLen === 0 || header.totalLen === 0) return null;
  // Upper-bound checks: reject obviously malformed/malicious frames before
  // the receiver allocates memory proportional to these values.
  if (header.blockLen > MAX_BLOCK_LEN) return null;   // above QR V40 max capacity
  if (header.totalLen > MAX_TOTAL_LEN) return null;   // above 500 MB ceiling
  if (bytes.length !== HEADER_LEN + header.blockLen) return null;
  return { header, block: bytes.subarray(HEADER_LEN) };
}

export function fnv1a(bytes: Uint8Array): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < bytes.length; i++) {
    h ^= bytes[i]!;
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

/** splitmix32 — deterministic across JS engines (integer ops only). */
export function splitmix32(seed: number): () => number {
  let s = seed | 0;
  return () => {
    s = (s + 0x9e3779b9) | 0;
    let t = s ^ (s >>> 16);
    t = Math.imul(t, 0x21f0aaad);
    t ^= t >>> 15;
    t = Math.imul(t, 0x735a2d97);
    t ^= t >>> 15;
    return t >>> 0;
  };
}
