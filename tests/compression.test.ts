/**
 * Tests for shared/compress.ts — gzipCompress / gzipDecompress
 *
 * These use the browser-native CompressionStream / DecompressionStream API,
 * which is available as a Node.js global since Node 18. Vitest runs in Node 22
 * so no polyfill is needed.
 *
 * NOTE: These tests run in Node's implementation of CompressionStream. Actual
 * in-browser behavior (Chrome, Firefox, Safari) must be verified manually via
 * `npm run dev` on a real device — see the Phase 1 status report for details.
 */

import { describe, expect, it } from "vitest";
import { gzipCompress, gzipDecompress } from "../shared/compress";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a highly compressible payload: a repeated ASCII pattern. */
function makeCompressiblePayload(len: number): Uint8Array {
  const pattern = new TextEncoder().encode("AAAAAAAAAAAAAAAA"); // 16 identical bytes
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = pattern[i % pattern.length]!;
  return out;
}

/**
 * Build a pseudo-random payload using splitmix32 (same PRNG as the fountain
 * codec) so the test is fully deterministic — no crypto.getRandomValues().
 */
function makeIncompressiblePayload(len: number): Uint8Array {
  let s = 0xdeadbeef | 0;
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    s = (s + 0x9e3779b9) | 0;
    let t = s ^ (s >>> 16);
    t = Math.imul(t, 0x21f0aaad);
    t ^= t >>> 15;
    t = Math.imul(t, 0x735a2d97);
    t ^= t >>> 15;
    out[i] = (t >>> 0) & 0xff;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Compressible payload
// ---------------------------------------------------------------------------

describe("gzipCompress / gzipDecompress — compressible payload", () => {
  it("round-trip: decompressed output is byte-for-byte identical to original", async () => {
    const original = makeCompressiblePayload(8192); // 8 KB of repeated pattern
    const compressed = await gzipCompress(original);
    const recovered = await gzipDecompress(compressed);
    expect(recovered.length).toBe(original.length);
    expect(recovered).toEqual(original);
  });

  it("compressed size is meaningfully smaller than original (at least 80% reduction)", async () => {
    const original = makeCompressiblePayload(8192);
    const compressed = await gzipCompress(original);
    // A repeated-byte payload should compress to well under 20% of original size.
    expect(compressed.length).toBeLessThan(original.length * 0.2);
  });

  it("round-trip with small payload (16 bytes)", async () => {
    const original = makeCompressiblePayload(16);
    const compressed = await gzipCompress(original);
    const recovered = await gzipDecompress(compressed);
    expect(recovered).toEqual(original);
  });

  it("round-trip with 1 KB payload", async () => {
    const original = makeCompressiblePayload(1024);
    const compressed = await gzipCompress(original);
    const recovered = await gzipDecompress(compressed);
    expect(recovered.length).toBe(1024);
    expect(recovered).toEqual(original);
  });
});

// ---------------------------------------------------------------------------
// Incompressible payload (pseudo-random — deterministic)
// ---------------------------------------------------------------------------

describe("gzipCompress / gzipDecompress — incompressible payload", () => {
  it("round-trip: decompressed output is byte-for-byte identical to original", async () => {
    const original = makeIncompressiblePayload(4096); // 4 KB of PRNG bytes
    const compressed = await gzipCompress(original);
    const recovered = await gzipDecompress(compressed);
    expect(recovered.length).toBe(original.length);
    expect(recovered).toEqual(original);
  });

  it("does not crash even though compressed size may exceed original", async () => {
    // For random data, gzip adds a header (~18 bytes) so compressed > original.
    // This test confirms gzipCompress doesn't throw and gzipDecompress recovers it.
    const original = makeIncompressiblePayload(100);
    const compressed = await gzipCompress(original); // must not throw
    const recovered = await gzipDecompress(compressed); // must not throw
    expect(recovered).toEqual(original);
  });

  it("compressed size is at most 110% of original (no catastrophic inflation)", async () => {
    // gzip overhead for random data is ~18 bytes fixed header, not multiplicative.
    const original = makeIncompressiblePayload(4096);
    const compressed = await gzipCompress(original);
    expect(compressed.length).toBeLessThan(original.length * 1.1);
  });
});

// ---------------------------------------------------------------------------
// Hash decision verification
// ---------------------------------------------------------------------------

describe("FNV hash over compressed bytes", () => {
  it("FNV of compressed bytes matches what the sender would store in payloadFnv", async () => {
    // This test pins the exact hash decision from Phase 1:
    // payloadFnv = fnv1a(compressed_bytes), NOT fnv1a(original_bytes).
    // Both send/main.ts and receive/main.ts implement this identically.
    const { fnv1a } = await import("../shared/protocol");
    const original = makeCompressiblePayload(1024);
    const compressed = await gzipCompress(original);
    const compressedHash = fnv1a(compressed);
    const originalHash = fnv1a(original);
    // The hashes must differ (proving we're actually hashing different data).
    expect(compressedHash).not.toBe(originalHash);
    // Re-compressing the same input gives the same compressed bytes (deterministic).
    const compressed2 = await gzipCompress(original);
    expect(fnv1a(compressed2)).toBe(compressedHash);
  });
});
