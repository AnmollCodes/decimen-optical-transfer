// Pure functions to serialize LTDecoder state to/from SavedSession fields,
// and to restore an LTDecoder from saved state.
//
// These functions have no DOM, no IndexedDB, no crypto dependencies — they
// operate only on LTDecoder instances and plain typed arrays. This makes them
// fully unit-testable in Node/Vitest.
//
// WHAT IS SERIALIZED:
//   - solved[]: the k solved block buffers (Uint32Array per block, or null).
//     This is the only state needed to resume — a decoder initialized with
//     these blocks can correctly continue addFrame() calls because the peeling
//     cascade uses only the solved[] array.
//   - seen: the set of seq numbers already processed, to preserve dup-detection
//     and framesNew/framesDup counts across reloads.
//   - solvedCount, framesNew: scalar counters for progress display.
//
// WHAT IS NOT SERIALIZED:
//   - byBlock map and pending frames: derived state, rebuilt naturally as new
//     frames arrive after resume. No need to persist — fountain coding is
//     inherently stateless on a per-frame basis once solved blocks are known.
//   - cdf (robust-soliton CDF): recomputed from k on construction.
//   - words: derived from blockLen.

import { LTDecoder } from "./fountain";

export interface DecoderSnapshot {
  k: number;
  blockLen: number;
  sessionId: number;
  totalLen: number;
  /** k-length array; each element is the solved block's bytes or null. */
  solvedBuffers: (ArrayBuffer | null)[];
  solvedCount: number;
  framesNew: number;
  seenSeqs: number[]; // sorted ascending for determinism
}

/**
 * Capture a snapshot of the decoder's solved state.
 * The returned snapshot is plain-data — safe to structured-clone into IDB.
 */
export function snapshotDecoder(dec: LTDecoder): DecoderSnapshot {
  // Access private fields via type cast to a shape we know from reading the source.
  // This is the only coupling point to LTDecoder internals.
  const internal = dec as unknown as {
    solved: (Uint32Array | null)[];
    seen: Set<number>;
    words: number;
  };

  const solvedBuffers: (ArrayBuffer | null)[] = new Array(dec.k).fill(null);
  for (let i = 0; i < dec.k; i++) {
    const s = internal.solved[i];
    if (s !== null && s !== undefined) {
      // Copy the underlying buffer so the snapshot is independent of the decoder.
      const copy = new ArrayBuffer(s.byteLength);
      new Uint8Array(copy).set(new Uint8Array(s.buffer, s.byteOffset, s.byteLength));
      solvedBuffers[i] = copy;
    }
  }

  const seenSeqs = [...internal.seen].sort((a, b) => a - b);

  return {
    k: dec.k,
    blockLen: dec.blockLen,
    sessionId: dec.sessionId,
    totalLen: dec.totalLen,
    solvedBuffers,
    solvedCount: dec.solvedCount,
    framesNew: dec.framesNew,
    seenSeqs,
  };
}

/**
 * Restore an LTDecoder from a snapshot.
 * The restored decoder is immediately ready for addFrame() calls — any frame
 * with a seq not in seenSeqs will be processed normally; frames in seenSeqs
 * will be counted as duplicates and skipped.
 */
export function restoreDecoder(snap: DecoderSnapshot): LTDecoder {
  const dec = new LTDecoder(snap.k, snap.blockLen, snap.sessionId, snap.totalLen);
  const words = Math.ceil(snap.blockLen / 4);

  const internal = dec as unknown as {
    solved: (Uint32Array | null)[];
    seen: Set<number>;
    solvedCount: number;
    framesNew: number;
  };

  // Restore solved blocks.
  for (let i = 0; i < snap.k; i++) {
    const buf = snap.solvedBuffers[i];
    if (buf !== null && buf !== undefined) {
      const u32 = new Uint32Array(words);
      new Uint8Array(u32.buffer).set(new Uint8Array(buf).subarray(0, words * 4));
      internal.solved[i] = u32;
    }
  }

  // Restore seen set and counters.
  internal.seen = new Set(snap.seenSeqs);
  internal.solvedCount = snap.solvedCount;
  internal.framesNew = snap.framesNew;

  return dec;
}

/**
 * Compute approximate transfer progress (0–1) from a snapshot.
 * Uses framesNew as a proxy for progress (same as the live UI).
 */
export function snapshotProgress(snap: DecoderSnapshot, overheadEst = 1.18): number {
  return Math.min(0.99, snap.framesNew / (snap.k * overheadEst));
}
