/**
 * Fountain code round-trip tests for shared/fountain.ts
 *
 * We use maxFrames = k * 10 as the upper bound for decode attempts.
 * Robust-soliton converges well within k*2 in practice, but for very small k
 * the PRNG draw can be unlucky with a fixed seed. k*10 is deterministically
 * safe while still breaking early on completion (no wasted work).
 */

import { describe, expect, it } from "vitest";
import { LTDecoder, LTEncoder } from "../shared/fountain";
import { fnv1a } from "../shared/protocol";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Deterministic payload: byte[i] = i & 0xff */
function makePayload(len: number): Uint8Array {
  const b = new Uint8Array(len);
  for (let i = 0; i < len; i++) b[i] = i & 0xff;
  return b;
}

function roundTrip(payload: Uint8Array, blockLen: number, sessionId: number): Uint8Array | null {
  const encoder = new LTEncoder(payload, blockLen, sessionId);
  const decoder = new LTDecoder(encoder.k, blockLen, sessionId, payload.length);
  const maxFrames = Math.max(50, encoder.k * 10);
  for (let seq = 0; seq < maxFrames; seq++) {
    decoder.addFrame(seq, encoder.encode(seq));
    if (decoder.isComplete) break;
  }
  return decoder.assemble();
}

// ---------------------------------------------------------------------------
// Round-trip tests
// ---------------------------------------------------------------------------

describe("LTEncoder / LTDecoder round-trip", () => {
  it("100-byte payload, blockLen=20 — clean multiple (k=5)", () => {
    const payload = makePayload(100);
    const result = roundTrip(payload, 20, 1);
    expect(result).not.toBeNull();
    expect(result!.length).toBe(100);
    expect(result!).toEqual(payload);
  });

  it("101-byte payload, blockLen=20 — not a clean multiple", () => {
    const payload = makePayload(101);
    const result = roundTrip(payload, 20, 1);
    expect(result).not.toBeNull();
    expect(result!.length).toBe(101);
    expect(result!).toEqual(payload);
  });

  it("blockLen-1 bytes — k=1 edge case (degree always 1)", () => {
    const payload = makePayload(19); // blockLen=20, k=1
    const result = roundTrip(payload, 20, 1);
    expect(result).not.toBeNull();
    expect(result!.length).toBe(19);
    expect(result!).toEqual(payload);
  });

  it("exactly blockLen bytes — k=1", () => {
    const payload = makePayload(20);
    const result = roundTrip(payload, 20, 1);
    expect(result).not.toBeNull();
    expect(result!.length).toBe(20);
    expect(result!).toEqual(payload);
  });

  it("1-byte payload — extreme small edge case", () => {
    const payload = new Uint8Array([0xde]);
    const result = roundTrip(payload, 20, 1);
    expect(result).not.toBeNull();
    expect(result![0]).toBe(0xde);
  });

  it("1000-byte payload, blockLen=97 — irregular block boundaries", () => {
    // 1000 / 97 = 10 full blocks + 30-byte partial last block (k=11)
    const payload = makePayload(1000);
    const result = roundTrip(payload, 97, 7);
    expect(result).not.toBeNull();
    expect(result!.length).toBe(1000);
    expect(result!).toEqual(payload);
  });

  it("500-byte payload, blockLen=50, sessionId=42 (k=10)", () => {
    const payload = makePayload(500);
    const result = roundTrip(payload, 50, 42);
    expect(result).not.toBeNull();
    expect(result!).toEqual(payload);
  });

  it("FNV-1a hash of assembled output matches hash of original payload", () => {
    const payload = makePayload(500);
    const result = roundTrip(payload, 50, 99);
    expect(result).not.toBeNull();
    expect(fnv1a(result!)).toBe(fnv1a(payload));
  });

  it("5 KB payload, blockLen=100 (k=50) — larger soliton distribution", () => {
    const payload = makePayload(5000);
    const result = roundTrip(payload, 100, 0x1234);
    expect(result).not.toBeNull();
    expect(result!.length).toBe(5000);
    expect(result!).toEqual(payload);
  });
});

// ---------------------------------------------------------------------------
// Decoder behavioural tests
// ---------------------------------------------------------------------------

describe("LTDecoder behaviour", () => {
  it("assemble() returns null while isComplete is false", () => {
    const payload = makePayload(200);
    const encoder = new LTEncoder(payload, 20, 1);
    const decoder = new LTDecoder(encoder.k, 20, 1, 200);
    decoder.addFrame(0, encoder.encode(0)); // k=10, 1 frame is nowhere near enough
    expect(decoder.isComplete).toBe(false);
    expect(decoder.assemble()).toBeNull();
  });

  it("duplicate frames (same seq) increment framesDup, not framesNew", () => {
    const payload = makePayload(100);
    const encoder = new LTEncoder(payload, 20, 5);
    const decoder = new LTDecoder(encoder.k, 20, 5, 100);
    for (let i = 0; i < 3; i++) decoder.addFrame(0, encoder.encode(0));
    expect(decoder.framesNew).toBe(1);
    expect(decoder.framesDup).toBe(2);
  });

  it("framesNew + framesDup equals total addFrame calls", () => {
    const encoder = new LTEncoder(makePayload(200), 20, 11);
    const decoder = new LTDecoder(encoder.k, 20, 11, 200);
    // 2 passes × 10 frames = 20 total calls; second pass is all dups
    for (let pass = 0; pass < 2; pass++) {
      for (let seq = 0; seq < 10; seq++) decoder.addFrame(seq, encoder.encode(seq));
    }
    expect(decoder.framesNew + decoder.framesDup).toBe(20);
  });

  it("out-of-order frame delivery still decodes correctly", () => {
    const payload = makePayload(300);
    const blockLen = 30;
    const sessionId = 3;
    const encoder = new LTEncoder(payload, blockLen, sessionId);
    const decoder = new LTDecoder(encoder.k, blockLen, sessionId, 300);

    // Collect frames then shuffle with a fixed-seed deterministic shuffle
    const frames: Array<{ seq: number; block: Uint8Array }> = [];
    for (let seq = 0; seq < encoder.k * 10; seq++) {
      frames.push({ seq, block: encoder.encode(seq) });
    }
    for (let i = frames.length - 1; i > 0; i--) {
      const j = (i * 1103515245 + 12345) % (i + 1);
      [frames[i], frames[j]] = [frames[j]!, frames[i]!];
    }

    for (const { seq, block } of frames) {
      decoder.addFrame(seq, block);
      if (decoder.isComplete) break;
    }

    const result = decoder.assemble();
    expect(result).not.toBeNull();
    expect(result!).toEqual(payload);
  });

  it("isComplete stays true after receiving extra frames beyond decode threshold", () => {
    const payload = makePayload(100);
    const encoder = new LTEncoder(payload, 20, 1);
    const decoder = new LTDecoder(encoder.k, 20, 1, 100);
    let completedAt = -1;
    for (let seq = 0; seq < encoder.k * 10; seq++) {
      decoder.addFrame(seq, encoder.encode(seq));
      if (decoder.isComplete && completedAt === -1) completedAt = seq;
    }
    expect(completedAt).toBeGreaterThan(0);
    expect(decoder.isComplete).toBe(true);
  });
});
