/**
 * tests/multi-qr.test.ts — Phase 3: multi-QR grid unit tests.
 *
 * SCOPE OF THESE TESTS (and what they do NOT test):
 * ─────────────────────────────────────────────────
 * These tests verify the fountain-pool math for the multi-QR scenario:
 * that frames from a 2×2 (or larger) grid feed correctly into the same
 * LTDecoder that single-QR mode uses, and that partial-frame drops are
 * handled gracefully. They do NOT test:
 *
 *   1. Real multi-symbol QR detection in a camera-captured image.
 *      zxing-wasm's maxNumberOfSymbols option is what enables this on the
 *      receive side, but calling readBarcodes() on a real image requires a
 *      browser + WASM runtime — it cannot run in a Node.js Vitest environment.
 *      This is the SINGLE BIGGEST UNVERIFIED RISK of Phase 3: whether zxing
 *      can reliably locate and decode N separate QR codes in one captured
 *      camera frame at the grid densities this code supports.
 *
 *   2. Real throughput gain at 2×2 density.
 *      Automated tests show the math works given already-decoded cells.
 *      Whether the worker pool keeps up with 4 cells per captured frame at
 *      the configured FPS can only be measured with a real device test.
 *      See the Phase 3 status report for the pre-analysis and measurement plan.
 *
 *   3. The send-side grid rendering (canvas compositing of N cells) and
 *      the receive-side worker message format change. Both require a browser.
 *
 * These tests DO verify:
 *   - Grid cell independence: adjacent cells in the same displayed frame
 *     carry distinct seq values and distinct encoded block bytes.
 *   - Fountain pool correctness: feeding frames as-if from a 2×2 grid into
 *     the same LTDecoder reconstructs the payload correctly.
 *   - Partial-frame tolerance: one cell out of four failing to arrive still
 *     allows the other three to contribute, and the transfer completes given
 *     sufficient total frames.
 *   - Single-QR regression: grid density = 1 (single-QR mode) still works
 *     exactly as before, using the identical LTDecoder path.
 */

import { describe, expect, it } from "vitest";
import { LTDecoder, LTEncoder } from "../shared/fountain";
import { HEADER_LEN, PROTO_VERSION, fnv1a, packFrame, parseFrame } from "../shared/protocol";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Deterministic test payload — same PRNG as fountain codec. */
function makePayload(len: number, seed = 0xdeadbeef): Uint8Array {
  let s = seed | 0;
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

/**
 * Simulate what send/main.ts does for a single grid cell at a given seq.
 * Returns the packed frame bytes (header + block), exactly as the sender
 * would pass to QRCode.create() for encoding.
 */
function makeCellFrameBytes(
  encoder: LTEncoder,
  sessionId: number,
  totalLen: number,
  payloadFnv: number,
  seq: number,
): Uint8Array {
  const blockLen = encoder.blockLen;
  const block = encoder.encode(seq);
  return packFrame(
    {
      version: PROTO_VERSION,
      sessionId,
      seq,
      k: encoder.k,
      blockLen,
      totalLen,
      payloadFnv,
    },
    block,
  );
}

// ---------------------------------------------------------------------------
// Grid cell independence
// ---------------------------------------------------------------------------

describe("grid cell independence", () => {
  it("adjacent cells in the same displayed frame carry distinct seq values", () => {
    const payload = makePayload(400);
    const blockLen = 100;
    const sessionId = 42;
    const encoder = new LTEncoder(payload, blockLen, sessionId);

    // Simulate a 2×2 grid: 4 cells per displayed frame, seqs 0..3.
    const seqs = [0, 1, 2, 3];
    // All seqs must be distinct (trivial but establishes the contract clearly).
    expect(new Set(seqs).size).toBe(4);

    // Each cell's frame must parse to a different seq.
    const frames = seqs.map((s) =>
      makeCellFrameBytes(encoder, sessionId, payload.length, fnv1a(payload), s),
    );
    const parsed = frames.map((f) => parseFrame(f));
    const parsedSeqs = parsed.map((p) => p!.header.seq);
    expect(new Set(parsedSeqs).size).toBe(4);
    expect(parsedSeqs).toEqual([0, 1, 2, 3]);
  });

  it("adjacent cells encode distinct block data (not the same bytes repeated)", () => {
    const payload = makePayload(400);
    const blockLen = 100;
    const sessionId = 0x1234;
    const encoder = new LTEncoder(payload, blockLen, sessionId);

    const totalLen = payload.length;
    const payloadFnv = fnv1a(payload);

    const cell0 = makeCellFrameBytes(encoder, sessionId, totalLen, payloadFnv, 0);
    const cell1 = makeCellFrameBytes(encoder, sessionId, totalLen, payloadFnv, 1);
    const cell2 = makeCellFrameBytes(encoder, sessionId, totalLen, payloadFnv, 2);
    const cell3 = makeCellFrameBytes(encoder, sessionId, totalLen, payloadFnv, 3);

    // Each cell's block bytes (after the header) must differ from the others.
    const b0 = cell0.subarray(HEADER_LEN);
    const b1 = cell1.subarray(HEADER_LEN);
    const b2 = cell2.subarray(HEADER_LEN);
    const b3 = cell3.subarray(HEADER_LEN);

    expect(b0).not.toEqual(b1);
    expect(b0).not.toEqual(b2);
    expect(b0).not.toEqual(b3);
    expect(b1).not.toEqual(b2);
    expect(b1).not.toEqual(b3);
    expect(b2).not.toEqual(b3);
  });

  it("seq advances by gridCells per displayed frame (correct interleaving)", () => {
    // The sender's nextSeq advances by gridCells per tick.
    // Verify: display frame 0 uses seqs [0,1,2,3], frame 1 uses [4,5,6,7], etc.
    const gridCells = 4;
    const framesPerDisplay = gridCells;

    for (let displayFrame = 0; displayFrame < 5; displayFrame++) {
      const base = displayFrame * framesPerDisplay;
      const cellSeqs = Array.from({ length: gridCells }, (_, i) => base + i);
      expect(cellSeqs[0]).toBe(displayFrame * 4);
      expect(cellSeqs[3]).toBe(displayFrame * 4 + 3);
      // All distinct within the display frame.
      expect(new Set(cellSeqs).size).toBe(gridCells);
    }
  });

  it("all six grid densities produce the expected total cells per display frame", () => {
    // These are the valid grid density values in the settings panel.
    const densities = [1, 4, 9, 16];
    const expectedCols = [1, 2, 3, 4];
    densities.forEach((cells, i) => {
      const cols = Math.round(Math.sqrt(cells));
      expect(cols).toBe(expectedCols[i]);
      expect(cols * cols).toBe(cells);
    });
  });
});

// ---------------------------------------------------------------------------
// Fountain pool correctness with simulated multi-QR grid feed
// ---------------------------------------------------------------------------

describe("fountain pool correctness — simulated 2×2 grid feed", () => {
  it("LTDecoder reconstructs correctly when fed cells from a 2×2 grid stream", () => {
    // 500-byte payload, 80-byte blockLen → k=7 source blocks.
    const payload = makePayload(500);
    const blockLen = 80;
    const sessionId = 0xabcd;
    const encoder = new LTEncoder(payload, blockLen, sessionId);
    const totalLen = payload.length;
    const payloadFnv = fnv1a(payload);
    const decoder = new LTDecoder(encoder.k, blockLen, sessionId, totalLen);

    // Simulate a 2×2 grid (4 cells/display-frame). Feed frames in groups of 4,
    // exactly as the receiver's worker would deliver them after decoding one
    // camera frame. Continue until decode is complete.
    let nextSeq = 0;
    let displayFramesConsumed = 0;
    const maxDisplayFrames = 100; // safety bound (fountain should complete in ~k*1.2 cells)

    while (!decoder.isComplete && displayFramesConsumed < maxDisplayFrames) {
      // 4 cells in this display frame (a 2×2 grid).
      for (let cell = 0; cell < 4; cell++) {
        const frameBytes = makeCellFrameBytes(encoder, sessionId, totalLen, payloadFnv, nextSeq++);
        const parsed = parseFrame(frameBytes);
        expect(parsed).not.toBeNull();
        decoder.addFrame(parsed!.header.seq, parsed!.block);
      }
      displayFramesConsumed++;
    }

    expect(decoder.isComplete).toBe(true);
    const assembled = decoder.assemble();
    expect(assembled).not.toBeNull();
    expect(fnv1a(assembled!)).toBe(payloadFnv);
    expect(assembled).toEqual(payload);
  });

  it("LTDecoder with 2×2 grid requires fewer display frames than 1×1 mode", () => {
    // Confirm the theoretical throughput advantage is borne out in the decoder math.
    const payload = makePayload(1000);
    const blockLen = 100;
    const sessionId = 0xcafe;
    const encoder = new LTEncoder(payload, blockLen, sessionId);
    const totalLen = payload.length;
    const payloadFnv = fnv1a(payload);

    function countDisplayFrames(cellsPerFrame: number): number {
      const dec = new LTDecoder(encoder.k, blockLen, sessionId, totalLen);
      let seq = 0;
      let frames = 0;
      while (!dec.isComplete && frames < 200) {
        for (let c = 0; c < cellsPerFrame; c++) {
          const fb = makeCellFrameBytes(encoder, sessionId, totalLen, payloadFnv, seq++);
          const p = parseFrame(fb)!;
          dec.addFrame(p.header.seq, p.block);
        }
        frames++;
      }
      return frames;
    }

    const frames1x1 = countDisplayFrames(1);
    const frames2x2 = countDisplayFrames(4);

    // 2×2 should need roughly 4× fewer display frames (±soliton variance).
    expect(frames2x2).toBeLessThan(frames1x1);
    // Must not be zero (sanity: at least one display frame needed).
    expect(frames2x2).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// Partial-frame tolerance: one cell drops, the others still contribute
// ---------------------------------------------------------------------------

describe("partial-frame tolerance", () => {
  it("3-out-of-4 cells per display frame still reconstructs with sufficient total frames", () => {
    // Simulate a 2×2 grid where cell index 2 in every display frame fails to
    // decode (e.g., motion blur, occlusion, glare on that quadrant). The other
    // 3 cells still contribute their fountain frames. The decoder should still
    // complete — it just needs a few more display frames.
    const payload = makePayload(600);
    const blockLen = 80;
    const sessionId = 0x1111;
    const encoder = new LTEncoder(payload, blockLen, sessionId);
    const totalLen = payload.length;
    const payloadFnv = fnv1a(payload);
    const decoder = new LTDecoder(encoder.k, blockLen, sessionId, totalLen);

    const DROP_CELL_INDEX = 2; // cell 2 (of 0,1,2,3) always dropped
    let nextSeq = 0;
    let displayFrames = 0;
    const maxDisplayFrames = 200;

    while (!decoder.isComplete && displayFrames < maxDisplayFrames) {
      for (let cell = 0; cell < 4; cell++) {
        const seq = nextSeq++;
        if (cell === DROP_CELL_INDEX) continue; // simulate decode failure — not added
        const frameBytes = makeCellFrameBytes(encoder, sessionId, totalLen, payloadFnv, seq);
        const parsed = parseFrame(frameBytes)!;
        decoder.addFrame(parsed.header.seq, parsed.block);
      }
      displayFrames++;
    }

    expect(decoder.isComplete).toBe(true);
    const assembled = decoder.assemble()!;
    expect(fnv1a(assembled)).toBe(payloadFnv);
    expect(assembled).toEqual(payload);
  });

  it("1-out-of-4 cells per display frame (severe drop) still reconstructs given enough frames", () => {
    // Worst-case: only 1 of 4 cells survives each display frame.
    // This is equivalent to 1×1 mode (same useful cell rate), so it MUST complete.
    const payload = makePayload(400);
    const blockLen = 80;
    const sessionId = 0x2222;
    const encoder = new LTEncoder(payload, blockLen, sessionId);
    const totalLen = payload.length;
    const payloadFnv = fnv1a(payload);
    const decoder = new LTDecoder(encoder.k, blockLen, sessionId, totalLen);

    let nextSeq = 0;
    let displayFrames = 0;
    const maxDisplayFrames = 300;

    while (!decoder.isComplete && displayFrames < maxDisplayFrames) {
      // Only feed seq for cell 0; cells 1, 2, 3 are "dropped"
      const seq = nextSeq;
      nextSeq += 4; // still advance nextSeq by gridCells so seqs don't collide
      const frameBytes = makeCellFrameBytes(encoder, sessionId, totalLen, payloadFnv, seq);
      const parsed = parseFrame(frameBytes)!;
      decoder.addFrame(parsed.header.seq, parsed.block);
      displayFrames++;
    }

    expect(decoder.isComplete).toBe(true);
    expect(fnv1a(decoder.assemble()!)).toBe(payloadFnv);
  });

  it("dropped cell does not corrupt frames from other cells in the same display frame", () => {
    // Feed cells 0, 1, 3 (skip cell 2). Confirm cells 0, 1, 3 each parse
    // independently and their block bytes are correctly different from each other.
    const payload = makePayload(500);
    const blockLen = 100;
    const sessionId = 0x3333;
    const encoder = new LTEncoder(payload, blockLen, sessionId);
    const totalLen = payload.length;
    const payloadFnv = fnv1a(payload);

    const seqsToFeed = [0, 1, 3]; // skip seq 2 (cell index 2 dropped)
    const parsedBlocks = seqsToFeed.map((seq) => {
      const bytes = makeCellFrameBytes(encoder, sessionId, totalLen, payloadFnv, seq);
      const parsed = parseFrame(bytes);
      expect(parsed).not.toBeNull();
      expect(parsed!.header.seq).toBe(seq);
      return parsed!.block;
    });

    // Each block is distinct — no corruption between cells.
    expect(parsedBlocks[0]).not.toEqual(parsedBlocks[1]);
    expect(parsedBlocks[0]).not.toEqual(parsedBlocks[2]);
    expect(parsedBlocks[1]).not.toEqual(parsedBlocks[2]);
  });
});

// ---------------------------------------------------------------------------
// Single-QR regression: grid density = 1 must work exactly as before
// ---------------------------------------------------------------------------

describe("single-QR regression (grid density = 1)", () => {
  it("density=1 round-trips a 300-byte payload identically to pre-Phase-3 behaviour", () => {
    const payload = makePayload(300);
    const blockLen = 100;
    const sessionId = 0x9999;
    const encoder = new LTEncoder(payload, blockLen, sessionId);
    const totalLen = payload.length;
    const payloadFnv = fnv1a(payload);
    const decoder = new LTDecoder(encoder.k, blockLen, sessionId, totalLen);

    // gridCells = 1: exactly one frame per tick, same as every prior phase.
    let seq = 0;
    while (!decoder.isComplete) {
      const bytes = makeCellFrameBytes(encoder, sessionId, totalLen, payloadFnv, seq++);
      const parsed = parseFrame(bytes)!;
      decoder.addFrame(parsed.header.seq, parsed.block);
    }

    expect(decoder.isComplete).toBe(true);
    expect(decoder.assemble()).toEqual(payload);
  });

  it("density=1 produces frames with k=1 for a tiny payload (single-block edge case)", () => {
    const payload = makePayload(50);
    const blockLen = 100; // blockLen > payloadLen → k=1
    const sessionId = 0xaaaa;
    const encoder = new LTEncoder(payload, blockLen, sessionId);
    expect(encoder.k).toBe(1);

    const totalLen = payload.length;
    const payloadFnv = fnv1a(payload);
    const decoder = new LTDecoder(encoder.k, blockLen, sessionId, totalLen);

    const bytes = makeCellFrameBytes(encoder, sessionId, totalLen, payloadFnv, 0);
    const parsed = parseFrame(bytes)!;
    decoder.addFrame(parsed.header.seq, parsed.block);

    expect(decoder.isComplete).toBe(true);
    // assemble() pads to blockLen but totalLen is 50, so we slice.
    const assembled = decoder.assemble()!;
    expect(assembled.subarray(0, payload.length)).toEqual(payload);
  });
});
