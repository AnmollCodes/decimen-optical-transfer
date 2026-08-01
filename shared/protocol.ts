// Frame protocol: every QR frame is fully self-describing, so there is NO
// handshake — the receiver locks onto a stream mid-flight, and a new session
// id on any frame simply starts a fresh transfer.
//
// Layout (little-endian), 20 bytes, followed by `blockLen` payload bytes:
//   0  u8   magic 0xD1
//   1  u8   version  0x01 = gzip-compressed payload (was 0x0C in proto v0)
//   2  u16  sessionId   random per sender start
//   4  u32  seq         drives the fountain PRNG (see fountain.ts)
//   8  u16  k           source block count
//  10  u16  blockLen    payload bytes per frame
//  12  u32  totalLen    compressed byte count (what travels the optical channel)
//  16  u32  payloadFnv  FNV-1a of the COMPRESSED bytes — verified on completion
//
// Protocol versioning:
//   v0 (original): byte 1 = 0x0C (second magic). Receivers expected [0xD1, 0x0C].
//   v1 (this version): byte 1 = 0x01, signals gzip-compressed payload.
//   A v0 receiver's parseFrame checks bytes[1] !== 0x0C and returns null for
//   any v1 frame — clean failure, no silent data corruption.
//   A v1 receiver rejects unknown version bytes (anything ≠ 0x01) the same way.

export const HEADER_LEN = 20;
const MAGIC0 = 0xd1;
export const PROTO_VERSION = 0x01;

// Accepted version bytes. Extend this set when adding future protocol versions.
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
