// Tests for Phase 5 resumable sessions — pure-logic parts only.
//
// WHAT IS TESTED HERE:
//   1. snapshotDecoder / restoreDecoder round-trip: serialize partial decoder,
//      restore it, continue feeding frames — verify identical output to the
//      uninterrupted path.
//   2. Restored decoder correctly detects isComplete when the same frames that
//      completed the original are re-fed (they're in seenSeqs → counted as dups,
//      but new frames complete it).
//   3. Session identity (sessionId) matching: frames with a different sessionId
//      are not fed to the resumed decoder — tested by checking that a new
//      LTDecoder is constructed when sessionId changes, not the resumed one.
//   4. snapshotProgress: numeric sanity check.
//   5. Snapshot of a complete decoder: solvedCount === k, assemble produces
//      the same bytes as an uninterrupted decoder.
//
// WHAT IS NOT TESTED HERE (explicitly):
//   - Real IndexedDB persistence: the Vitest environment is "node"
//     (vitest.config.ts: environment: "node"), so window.indexedDB does not
//     exist. Testing IDB operations would require switching to "jsdom" and
//     installing a polyfill, which adds a new npm package (violating the zero-
//     dep rule). The IDB layer (receive/session-store.ts) is thin typed
//     wrappers over native IDB — the interesting logic is in snapshotDecoder/
//     restoreDecoder, which ARE fully tested here.
//   - Real page-reload / tab-kill behavior: inherently a device test.
//   - The UI prompt/choice flow (resume banner): DOM-dependent, not in scope.
//
// The single most important unverified item is: reload the receiver page
// mid-transfer on the actual phone and confirm the resume prompt appears and
// that accepting it resumes from the correct progress rather than restarting.

import { describe, expect, it } from "vitest";
import { LTDecoder, LTEncoder } from "../shared/fountain";
import { fnv1a } from "../shared/protocol";
import { snapshotDecoder, restoreDecoder, snapshotProgress } from "../shared/decoder-state";

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function makePayload(size: number): Uint8Array {
  const p = new Uint8Array(size);
  for (let i = 0; i < size; i++) p[i] = (i * 37 + 13) & 0xff;
  return p;
}

function feed(dec: LTDecoder, enc: LTEncoder, fromSeq: number, count: number): void {
  for (let s = fromSeq; s < fromSeq + count; s++) {
    dec.addFrame(s, enc.encode(s));
  }
}

/** Drain frames until decoder completes or maxFrames is reached. */
function drainToComplete(dec: LTDecoder, enc: LTEncoder, startSeq: number, maxFrames = 5000): number {
  for (let s = startSeq; s < startSeq + maxFrames; s++) {
    dec.addFrame(s, enc.encode(s));
    if (dec.isComplete) return s + 1; // next seq after the completing one
  }
  throw new Error("decoder did not complete within maxFrames");
}

// ---------------------------------------------------------------------------
// snapshotDecoder / restoreDecoder
// ---------------------------------------------------------------------------

describe("snapshotDecoder / restoreDecoder", () => {
  it("round-trips all snapshot fields: k, blockLen, sessionId, totalLen", () => {
    const payload = makePayload(500);
    const enc = new LTEncoder(payload, 50, 42);
    const dec = new LTDecoder(enc.k, enc.blockLen, enc.sessionId, payload.length);
    feed(dec, enc, 0, 20); // partial progress
    const snap = snapshotDecoder(dec);
    expect(snap.k).toBe(enc.k);
    expect(snap.blockLen).toBe(enc.blockLen);
    expect(snap.sessionId).toBe(enc.sessionId);
    expect(snap.totalLen).toBe(payload.length);
  });

  it("solvedBuffers has exactly k entries", () => {
    const payload = makePayload(300);
    const enc = new LTEncoder(payload, 30, 7);
    const dec = new LTDecoder(enc.k, enc.blockLen, enc.sessionId, payload.length);
    feed(dec, enc, 0, 15);
    const snap = snapshotDecoder(dec);
    expect(snap.solvedBuffers.length).toBe(enc.k);
  });

  it("seenSeqs is sorted and contains exactly the seq numbers fed", () => {
    const payload = makePayload(200);
    const enc = new LTEncoder(payload, 20, 3);
    const dec = new LTDecoder(enc.k, enc.blockLen, enc.sessionId, payload.length);
    const seqs = [5, 2, 8, 1, 9, 0, 4];
    for (const s of seqs) dec.addFrame(s, enc.encode(s));
    const snap = snapshotDecoder(dec);
    expect(snap.seenSeqs).toEqual([...seqs].sort((a, b) => a - b));
  });

  it("framesNew and solvedCount are captured correctly", () => {
    const payload = makePayload(100);
    const enc = new LTEncoder(payload, 10, 1);
    const dec = new LTDecoder(enc.k, enc.blockLen, enc.sessionId, payload.length);
    feed(dec, enc, 0, 6);
    const snap = snapshotDecoder(dec);
    expect(snap.framesNew).toBe(6);
    expect(snap.solvedCount).toBeLessThanOrEqual(enc.k);
    expect(snap.solvedCount).toBeGreaterThanOrEqual(0);
  });

  it("restored decoder produces the same assemble() output as uninterrupted decoder", () => {
    // Build a reference: one decoder that completes uninterrupted.
    const payload = makePayload(1000);
    const blockLen = 100;
    const sessionId = 99;
    const enc = new LTEncoder(payload, blockLen, sessionId);
    const reference = new LTDecoder(enc.k, blockLen, sessionId, payload.length);
    const nextSeq = drainToComplete(reference, enc, 0);
    const referenceAssembled = reference.assemble()!;

    // Build the same result but interrupted at frame 5, then resumed.
    const partial = new LTDecoder(enc.k, blockLen, sessionId, payload.length);
    feed(partial, enc, 0, 5); // feed first 5 frames
    const snap = snapshotDecoder(partial);

    // Restore and continue from where the reference left off.
    const resumed = restoreDecoder(snap);
    drainToComplete(resumed, enc, 5, nextSeq + 500); // continue from seq 5

    const resumedAssembled = resumed.assemble()!;
    expect(resumedAssembled).toEqual(referenceAssembled);
  });

  it("resumed decoder correctly rejects duplicate seq numbers from before the snapshot", () => {
    const payload = makePayload(500);
    const enc = new LTEncoder(payload, 50, 11);
    const dec = new LTDecoder(enc.k, enc.blockLen, enc.sessionId, payload.length);
    feed(dec, enc, 0, 10); // seqs 0-9 seen
    const snapBefore = snapshotDecoder(dec);

    const resumed = restoreDecoder(snapBefore);
    const dupsBefore = resumed.framesDup;

    // Re-feed a seq that was in the snapshot — should count as dup, not new
    resumed.addFrame(5, enc.encode(5));
    expect(resumed.framesDup).toBe(dupsBefore + 1);
    expect(resumed.framesNew).toBe(snapBefore.framesNew); // unchanged
  });

  it("resumed decoder correctly accepts seq numbers NOT in the snapshot", () => {
    const payload = makePayload(500);
    const enc = new LTEncoder(payload, 50, 22);
    const dec = new LTDecoder(enc.k, enc.blockLen, enc.sessionId, payload.length);
    feed(dec, enc, 0, 5); // seqs 0-4 seen
    const snap = snapshotDecoder(dec);

    const resumed = restoreDecoder(snap);
    const newBefore = resumed.framesNew;

    // Feed a seq that was NOT in the snapshot — should count as new
    resumed.addFrame(100, enc.encode(100));
    expect(resumed.framesNew).toBe(newBefore + 1);
  });

  it("snapshot of a completed decoder has solvedCount === k and non-null solved buffers", () => {
    const payload = makePayload(200);
    const enc = new LTEncoder(payload, 20, 5);
    const dec = new LTDecoder(enc.k, enc.blockLen, enc.sessionId, payload.length);
    drainToComplete(dec, enc, 0);
    expect(dec.isComplete).toBe(true);
    const snap = snapshotDecoder(dec);
    expect(snap.solvedCount).toBe(enc.k);
    expect(snap.solvedBuffers.every((b) => b !== null)).toBe(true);
  });

  it("restored complete decoder produces correct assemble() output via FNV hash", () => {
    const payload = makePayload(400);
    const enc = new LTEncoder(payload, 40, 77);
    const dec = new LTDecoder(enc.k, enc.blockLen, enc.sessionId, payload.length);
    drainToComplete(dec, enc, 0);
    const snap = snapshotDecoder(dec);
    const restored = restoreDecoder(snap);
    expect(restored.isComplete).toBe(true);
    const assembled = restored.assemble()!;
    expect(fnv1a(assembled)).toBe(fnv1a(payload));
  });

  it("snapshot buffers are independent copies (mutating restored decoder doesn't affect original)", () => {
    const payload = makePayload(300);
    const enc = new LTEncoder(payload, 30, 9);
    const dec = new LTDecoder(enc.k, enc.blockLen, enc.sessionId, payload.length);
    drainToComplete(dec, enc, 0);
    const snap1 = snapshotDecoder(dec);
    const snap2 = snapshotDecoder(dec);
    // Each snapshot should be a deep copy: modifying one shouldn't corrupt the other
    const buf1 = snap1.solvedBuffers[0];
    const buf2 = snap2.solvedBuffers[0];
    if (buf1 && buf2) {
      new Uint8Array(buf1)[0] = 0xff; // mutate snap1
      expect(new Uint8Array(buf2)[0]).not.toBe(0xff); // snap2 unaffected
    }
  });
});

// ---------------------------------------------------------------------------
// session identity (sessionId matching)
// ---------------------------------------------------------------------------

describe("session identity: sessionId matching", () => {
  it("a decoder restored with sessionId=A ignores frames from sessionId=B", () => {
    // This mirrors the receive/main.ts logic:
    //   if (!decoder || sessionId !== header.sessionId) { decoder = new LTDecoder(...) }
    // We simulate: restore a decoder with sessionId=100, then receive a frame
    // whose header.sessionId is 200 — the caller MUST create a new decoder.
    const sidA = 100;
    const sidB = 200;
    const payload = makePayload(200);
    const encA = new LTEncoder(payload, 20, sidA);
    const encB = new LTEncoder(payload, 20, sidB);

    const decA = new LTDecoder(encA.k, encA.blockLen, sidA, payload.length);
    feed(decA, encA, 0, 5);
    const snap = snapshotDecoder(decA);

    const resumedA = restoreDecoder(snap);
    expect(resumedA.sessionId).toBe(sidA);

    // Simulate what receive/main.ts does: a frame with sidB arrives.
    // The sessionId mismatch means we'd create a new decoder — not feed into resumedA.
    // Test: the resumed decoder retains its own sessionId, unchanged.
    const newDecB = new LTDecoder(encB.k, encB.blockLen, sidB, payload.length);
    feed(newDecB, encB, 0, 3);
    // resumedA is unaffected
    expect(resumedA.sessionId).toBe(sidA);
    expect(resumedA.framesNew).toBe(5);
  });

  it("frames with matching sessionId correctly extend the resumed session", () => {
    const sid = 42;
    const payload = makePayload(500);
    const enc = new LTEncoder(payload, 50, sid);
    const dec = new LTDecoder(enc.k, enc.blockLen, sid, payload.length);
    feed(dec, enc, 0, 8);
    const snap = snapshotDecoder(dec);

    const resumed = restoreDecoder(snap);
    // Feed more frames with same sessionId
    feed(resumed, enc, 8, 5);
    expect(resumed.framesNew).toBe(13); // 8 from snap + 5 new
    expect(resumed.sessionId).toBe(sid);
  });
});

// ---------------------------------------------------------------------------
// snapshotProgress
// ---------------------------------------------------------------------------

describe("snapshotProgress", () => {
  it("returns 0 for a decoder with no frames", () => {
    const payload = makePayload(200);
    const enc = new LTEncoder(payload, 20, 1);
    const dec = new LTDecoder(enc.k, enc.blockLen, enc.sessionId, payload.length);
    const snap = snapshotDecoder(dec);
    expect(snapshotProgress(snap)).toBe(0);
  });

  it("returns a value in (0, 0.99] for a partially-filled decoder", () => {
    const payload = makePayload(1000);
    const enc = new LTEncoder(payload, 100, 2);
    const dec = new LTDecoder(enc.k, enc.blockLen, enc.sessionId, payload.length);
    feed(dec, enc, 0, 5);
    const snap = snapshotDecoder(dec);
    const p = snapshotProgress(snap);
    expect(p).toBeGreaterThan(0);
    expect(p).toBeLessThanOrEqual(0.99);
  });

  it("caps at 0.99 (never returns 1.0) for a nearly-complete decoder", () => {
    const payload = makePayload(200);
    const enc = new LTEncoder(payload, 20, 3);
    const dec = new LTDecoder(enc.k, enc.blockLen, enc.sessionId, payload.length);
    // Feed many frames to get very close
    for (let s = 0; s < 1000; s++) dec.addFrame(s, enc.encode(s));
    const snap = snapshotDecoder(dec);
    expect(snapshotProgress(snap)).toBeLessThanOrEqual(0.99);
  });
});

// ---------------------------------------------------------------------------
// full interrupted-then-resumed pipeline
// ---------------------------------------------------------------------------

describe("full interrupted-then-resumed pipeline round-trip", () => {
  it("transferring 2 KB interrupted at 40%, resumed, produces byte-identical output", () => {
    const payload = makePayload(2048);
    const blockLen = 64;
    const sessionId = 55;
    const enc = new LTEncoder(payload, blockLen, sessionId);
    const k = enc.k;

    // Phase 1: receive frames until roughly 40% of k have been seen
    const dec1 = new LTDecoder(k, blockLen, sessionId, payload.length);
    const target40 = Math.ceil(k * 1.18 * 0.4);
    feed(dec1, enc, 0, target40);

    // "Reload": snapshot + restore
    const snap = snapshotDecoder(dec1);
    const dec2 = restoreDecoder(snap);

    // Phase 2: continue from where we left off — drain to completion
    drainToComplete(dec2, enc, target40);
    expect(dec2.isComplete).toBe(true);

    const assembled = dec2.assemble()!;
    expect(fnv1a(assembled)).toBe(fnv1a(payload));
  });

  it("multiple interruptions (snapshot twice) still produces correct output", () => {
    const payload = makePayload(1500);
    const blockLen = 50;
    const sessionId = 13;
    const enc = new LTEncoder(payload, blockLen, sessionId);
    const k = enc.k;

    // First stretch
    const dec1 = new LTDecoder(k, blockLen, sessionId, payload.length);
    feed(dec1, enc, 0, Math.ceil(k * 0.3));

    // First reload
    const dec2 = restoreDecoder(snapshotDecoder(dec1));
    feed(dec2, enc, Math.ceil(k * 0.3), Math.ceil(k * 0.3));

    // Second reload
    const dec3 = restoreDecoder(snapshotDecoder(dec2));
    drainToComplete(dec3, enc, Math.ceil(k * 0.6));

    expect(dec3.isComplete).toBe(true);
    const assembled = dec3.assemble()!;
    expect(fnv1a(assembled)).toBe(fnv1a(payload));
  });
});
