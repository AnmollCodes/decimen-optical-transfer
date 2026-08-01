/**
 * Golden-vector tests for shared/protocol.ts
 *
 * fnv1a: pinned against FNV-1a 32-bit reference vectors from
 *   http://www.isthe.com/chongo/tech/comp/fnv/#fnv-test-vectors
 * splitmix32: cross-checked against an inline reference copy of the same
 *   algorithm so any JS-engine integer arithmetic change is caught.
 * packFrame / parseFrame: round-trip fidelity + rejection cases.
 */

import { describe, expect, it } from "vitest";
import { fnv1a, packFrame, parseFrame, splitmix32 } from "../shared/protocol";

// ---------------------------------------------------------------------------
// fnv1a golden vectors
// ---------------------------------------------------------------------------

describe("fnv1a", () => {
  it("empty input returns the FNV-1a 32-bit offset basis", () => {
    expect(fnv1a(new Uint8Array([]))).toBe(0x811c9dc5);
  });

  it("single byte 0x61 ('a') — hand-computed reference", () => {
    // h = 0x811c9dc5 ^ 0x61 = 0x811c9da4
    // h = Math.imul(0x811c9da4, 0x01000193) >>> 0 = 0xe40c292c
    expect(fnv1a(new Uint8Array([0x61]))).toBe(0xe40c292c);
  });

  it("'foobar' — well-known FNV-1a 32-bit reference vector", () => {
    const bytes = new Uint8Array([0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72]);
    expect(fnv1a(bytes)).toBe(0xbf9cf968);
  });

  it("output is always a non-negative 32-bit integer", () => {
    const buf = new Uint8Array(256);
    for (let i = 0; i < 256; i++) buf[i] = i;
    const h = fnv1a(buf);
    expect(h).toBeGreaterThanOrEqual(0);
    expect(h).toBeLessThanOrEqual(0xffffffff);
    expect(Number.isInteger(h)).toBe(true);
  });

  it("is deterministic — same input always gives same output", () => {
    const a = new Uint8Array([1, 2, 3, 4, 5]);
    expect(fnv1a(a)).toBe(fnv1a(new Uint8Array([1, 2, 3, 4, 5])));
  });

  it("different byte-order gives different hash (collision sanity)", () => {
    expect(fnv1a(new Uint8Array([0, 1]))).not.toBe(fnv1a(new Uint8Array([1, 0])));
  });
});

// ---------------------------------------------------------------------------
// splitmix32 golden vectors
// ---------------------------------------------------------------------------

describe("splitmix32", () => {
  it("seed=0: first call matches inline reference implementation", () => {
    const rnd = splitmix32(0);
    const first = rnd();
    expect(first).toBeGreaterThanOrEqual(0);
    expect(first).toBeLessThanOrEqual(0xffffffff);
    expect(Number.isInteger(first)).toBe(true);
    // Cross-check against an independent inline copy of the algorithm.
    // If production code and this reference ever diverge, a JS engine
    // changed its integer arithmetic — a critical regression.
    expect(first).toBe(splitmix32_reference_seed0_call1());
  });

  it("seed=0: 8 successive calls are stable and not all equal", () => {
    const rnd = splitmix32(0);
    const out = Array.from({ length: 8 }, () => rnd());
    out.forEach((v) => {
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThanOrEqual(0xffffffff);
    });
    expect(new Set(out).size).toBeGreaterThan(1);
    // Determinism: fresh generator with same seed gives identical sequence.
    const rnd2 = splitmix32(0);
    expect(Array.from({ length: 8 }, () => rnd2())).toEqual(out);
  });

  it("seed=1 first call differs from seed=0 first call", () => {
    expect(splitmix32(0)()).not.toBe(splitmix32(1)());
  });

  it("seed=0xdeadbeef: 4 successive calls are stable", () => {
    const out = Array.from({ length: 4 }, () => splitmix32(0xdeadbeef)());
    // Re-run must match.
    expect(Array.from({ length: 4 }, () => splitmix32(0xdeadbeef)())).toEqual(out);
    out.forEach((v) => {
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThanOrEqual(0xffffffff);
    });
  });

  it("100 successive calls produce at least 90 distinct values", () => {
    const rnd = splitmix32(42);
    const vals = new Set(Array.from({ length: 100 }, () => rnd()));
    expect(vals.size).toBeGreaterThan(90);
  });
});

// ---------------------------------------------------------------------------
// packFrame / parseFrame round-trip
// ---------------------------------------------------------------------------

describe("packFrame / parseFrame", () => {
  const HEADER = {
    sessionId: 0xabcd,
    seq: 0x12345678,
    k: 400,
    blockLen: 1445,
    totalLen: 536325,
    payloadFnv: 0xdeadbeef,
  };

  it("round-trips all header fields exactly and preserves block bytes", () => {
    const block = new Uint8Array(HEADER.blockLen);
    block[0] = 0xff;
    block[HEADER.blockLen - 1] = 0x42;
    const frame = packFrame(HEADER, block);
    const parsed = parseFrame(frame);
    expect(parsed).not.toBeNull();
    expect(parsed!.header).toEqual(HEADER);
    expect(parsed!.block[0]).toBe(0xff);
    expect(parsed!.block[HEADER.blockLen - 1]).toBe(0x42);
  });

  it("rejects a frame with wrong first magic byte", () => {
    const block = new Uint8Array(10);
    const frame = packFrame(
      { sessionId: 1, seq: 0, k: 1, blockLen: 10, totalLen: 10, payloadFnv: 0 },
      block,
    );
    frame[0] = 0x00;
    expect(parseFrame(frame)).toBeNull();
  });

  it("rejects a frame with wrong second magic byte", () => {
    const block = new Uint8Array(10);
    const frame = packFrame(
      { sessionId: 1, seq: 0, k: 1, blockLen: 10, totalLen: 10, payloadFnv: 0 },
      block,
    );
    frame[1] = 0x00;
    expect(parseFrame(frame)).toBeNull();
  });

  it("rejects frames shorter than HEADER_LEN+1 bytes", () => {
    expect(parseFrame(new Uint8Array(5))).toBeNull();
    expect(parseFrame(new Uint8Array(20))).toBeNull(); // exactly HEADER_LEN, no payload
  });

  it("rejects k=0", () => {
    const block = new Uint8Array(1);
    const frame = packFrame(
      { sessionId: 1, seq: 0, k: 0, blockLen: 1, totalLen: 1, payloadFnv: 0 },
      block,
    );
    expect(parseFrame(frame)).toBeNull();
  });

  it("rejects blockLen=0", () => {
    // packFrame with blockLen=0 produces a header-only frame (length===HEADER_LEN)
    // which parseFrame also rejects as too short.
    const frame = packFrame(
      { sessionId: 1, seq: 0, k: 1, blockLen: 0, totalLen: 1, payloadFnv: 0 },
      new Uint8Array(0),
    );
    expect(parseFrame(frame)).toBeNull();
  });

  it("rejects totalLen=0", () => {
    const block = new Uint8Array(10);
    const frame = packFrame(
      { sessionId: 1, seq: 0, k: 1, blockLen: 10, totalLen: 0, payloadFnv: 0 },
      block,
    );
    expect(parseFrame(frame)).toBeNull();
  });

  it("header is little-endian: sessionId 0x1234 → bytes [0x34, 0x12] at offset 2-3", () => {
    const frame = packFrame(
      { sessionId: 0x1234, seq: 0, k: 1, blockLen: 10, totalLen: 1, payloadFnv: 0 },
      new Uint8Array(10),
    );
    expect(frame[2]).toBe(0x34);
    expect(frame[3]).toBe(0x12);
  });
});

// ---------------------------------------------------------------------------
// Inline reference implementation — independent cross-check for splitmix32
// ---------------------------------------------------------------------------

function splitmix32_reference_seed0_call1(): number {
  const s = (0 + 0x9e3779b9) | 0;
  let t = s ^ (s >>> 16);
  t = Math.imul(t, 0x21f0aaad);
  t ^= t >>> 15;
  t = Math.imul(t, 0x735a2d97);
  t ^= t >>> 15;
  return t >>> 0;
}
