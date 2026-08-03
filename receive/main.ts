// Receiver: camera → WASM QR decode in workers → fountain decoder → file.
//
// Field lessons baked in:
// - iOS treats `frameRate: {ideal: 60}` as a suggestion and delivers 30.
//   Demand `exact` first (it works at 1280-wide), fall back to `ideal`.
// - requestVideoFrameCallback chains survive a stopped stream and resume on
//   the next one — a generation counter prevents zombie capture loops.
// - Progress must track frames COLLECTED: LT peeling back-loads its solve
//   cascade, so blocks-solved looks stalled and then teleports to done.
//
// Phase 2 — decryption:
// - The receiver must scan a small "key QR" before the main stream.
//   The key QR contains "K:" + hex(32 raw AES-256-GCM key bytes).
// - Order: fountain reconstruct → encrypted blob → FNV check → AES-GCM decrypt
//   → gzip decompress → original file.
// - FNV is verified over the encrypted blob (IV + ciphertext + tag), same as
//   what the sender computed.
// - AES-GCM auth tag failure surfaces as a clear error message — never silent.
//
// Phase 3 — multi-QR grid:
// - Worker now returns { id, results: Uint8Array[], cellDecodeMs } instead of
//   { id, bytes: Uint8Array | null }.
// - Each entry in results[] is an independently decoded QR code from the same
//   camera frame (one entry per grid cell that zxing successfully decoded).
// - Each decoded cell is fed into onDecoded independently — no codec changes.
// - cellsDecoded ring-buffer tracks cells/sec for real throughput telemetry.
//
// Concurrency safety:
// - Multiple decode workers can deliver frames to onDecoded simultaneously.
// - sessionKeyPromise uses a promise-based atomic check-and-set: the assignment
//   happens synchronously before the first `await`, so no two concurrent calls
//   can both observe sessionKeyPromise===null and both start key import.

// Phase 5 — resumable sessions:
// - On page load, IndexedDB is checked for an in-progress session record.
// - If found, a resume prompt is shown ("Resume X% / Start fresh").
// - On resume: LTDecoder state (solved blocks + seen seqs) is restored from IDB,
//   and the AES key is re-imported from the stored 32 raw bytes.
// - During a live transfer, IDB is updated every ~2 s (throttled, not per-frame).
// - On completion, the IDB record for the session is deleted.
// - The AES key is stored in IDB alongside the decoder state. Security trade-off:
//   IDB is local-device-only storage. The key is cleared on completion and on
//   manual "Clear saved session". Acceptable for this local optical transfer use
//   case — see session-store.ts for the full reasoning.

import { gzipDecompress } from "../shared/compress";
import { aesGcmDecrypt, importKeyBytes } from "../shared/crypto";
import { LTDecoder } from "../shared/fountain";
import { fnv1a, parseFrame } from "../shared/protocol";
import { isBundled, unbundleFiles } from "../shared/bundle";
import { saveSession, loadAllSessions, deleteSession, clearAllSessions, type SavedSession } from "./session-store";
import { snapshotDecoder, restoreDecoder, snapshotProgress } from "../shared/decoder-state";

const OVERHEAD_EST = 1.18; // expected frames ≈ K × this (robust-soliton ε)

// Key prefix for the out-of-band key QR: "K:" + hex(32 bytes) = 66 chars total.
const KEY_PREFIX = "K:";
const KEY_HEX_LEN = 64; // 32 bytes × 2 hex chars

const startBtn = document.getElementById("start") as HTMLButtonElement;
const video = document.getElementById("video") as HTMLVideoElement;
const preview = document.getElementById("preview")!;
const stats = document.getElementById("stats")!;
const progressEl = document.getElementById("progress")!;
const bar = document.getElementById("bar")!;
const result = document.getElementById("result")!;
const settings = document.getElementById("settings") as HTMLDetailsElement;
const metricsEl = document.getElementById("metrics")!;
const metric = (id: string) => document.getElementById(id)!;

// Key-scan status banner — inserted dynamically so the HTML needs no changes.
const keyBanner = document.createElement("div");
keyBanner.id = "key-banner";
keyBanner.style.cssText =
  "display:none;padding:10px;background:#1a1a2e;border:2px solid #f0a500;" +
  "border-radius:6px;color:#f0a500;font-family:monospace;font-size:13px;" +
  "text-align:center;margin-bottom:10px;";
keyBanner.textContent = "⌛ Waiting for key QR… point camera at the sender's key QR first.";
stats.parentElement!.insertAdjacentElement("afterend", keyBanner);

let stream: MediaStream | null = null;
let decoder: LTDecoder | null = null;
let sessionId = 0;
let startTs = 0;
let captureGen = 0;
let done = false;

// Phase 5: raw AES key bytes kept in memory so they can be persisted to IDB
// alongside the decoder state. Cleared when the session completes.
let currentKeyBytes: Uint8Array | null = null;

// Phase 5: throttle IDB saves to once per ~2 seconds during frame acceptance.
let lastSaveTs = 0;
const SAVE_INTERVAL_MS = 2000;

// Phase 5: flag set when we are resuming from a stored session
// (suppresses the key-QR wait phase).
let resumingFromStore = false;

// Grid density: how many QR cells the sender renders per display frame.
let gridCells = 1;

// Session key promise
let sessionKeyPromise: Promise<CryptoKey> | null = null;

// Phase 5: resume prompt banner — shown on page load if a saved session exists.
const resumeBanner = document.createElement("div");
resumeBanner.id = "resume-banner";
resumeBanner.style.cssText =
  "display:none;padding:12px 14px;background:#1a1a2e;border:2px solid #a78bfa;" +
  "border-radius:8px;color:#a78bfa;font-family:monospace;font-size:13px;" +
  "margin-bottom:12px;";
// Will be populated with content when a saved session is found.
stats.parentElement!.insertAdjacentElement("afterbegin", resumeBanner);

const workers: Worker[] = [];
const busy: boolean[] = [];
const captureTimes: number[] = [];
const decodeTimes: number[] = [];
const cellDecodeTimes: number[] = [];

// DIAGNOSTIC accumulators — rolling 2-second window
// rawFrames: count of worker responses (each = one camera frame processed)
// rawTotalSymbols: sum of rawCount across those frames (how many zxing found)
// validTotalSymbols: sum of validCount (how many passed isValid filter)
let diagWindowStart = 0;
let diagRawFrames = 0;
let diagRawSymbols = 0;
let diagValidSymbols = 0;

startBtn.onclick = () => void start();

// Phase 5: "Clear saved session" button in settings panel.
const clearSessionsBtn = document.getElementById("btn-clear-sessions");
if (clearSessionsBtn) {
  clearSessionsBtn.onclick = () => {
    void clearAllSessions().then(() => {
      resumeBanner.style.display = "none";
      clearSessionsBtn.textContent = "✓ Cleared";
      setTimeout(() => { clearSessionsBtn.textContent = "Clear saved session"; }, 2000);
    }).catch(() => {
      clearSessionsBtn.textContent = "✗ Error clearing";
    });
  };
}

// Phase 5: check for saved sessions on page load.
void checkForSavedSession();

/**
 * Phase 5: on page load, query IDB for any saved in-progress session.
 * If found, show a resume prompt instead of / above the normal Start button.
 */
async function checkForSavedSession(): Promise<void> {
  let sessions: SavedSession[];
  try {
    sessions = await loadAllSessions();
  } catch {
    return; // IDB unavailable (e.g. private mode on some browsers) — silently continue
  }
  if (sessions.length === 0) return;

  // Take the most recently saved session (most likely the one the user cares about).
  const saved = sessions.sort((a, b) => b.savedAt - a.savedAt)[0]!;
  const pct = Math.round(snapshotProgress(saved) * 100);
  const ageMin = Math.round((Date.now() - saved.savedAt) / 60000);
  const ageStr = ageMin < 2 ? "just now" : `${ageMin} min ago`;
  const sizeStr = `${Math.round(saved.totalLen / 1024)} KB`;

  resumeBanner.innerHTML =
    `<strong>↻ Interrupted transfer found</strong> — ${pct}% of ${sizeStr} received (${ageStr})<br>` +
    `<div style="margin-top:8px;display:flex;gap:8px;">` +
    `<button id="btn-resume" style="padding:6px 14px;background:#4c1d95;color:#a78bfa;` +
      `border:1px solid #a78bfa;border-radius:5px;font-family:monospace;cursor:pointer;">` +
      `Resume (${pct}% done)</button>` +
    `<button id="btn-fresh" style="padding:6px 14px;background:#1a1a2e;color:#888;` +
      `border:1px solid #555;border-radius:5px;font-family:monospace;cursor:pointer;">` +
      `Start fresh</button>` +
    `</div>`;
  resumeBanner.style.display = "block";

  document.getElementById("btn-resume")!.onclick = () => void resumeFromSaved(saved);
  document.getElementById("btn-fresh")!.onclick = () => {
    void deleteSession(saved.sessionId).catch(() => {/* ignore */});
    resumeBanner.style.display = "none";
  };
}

/**
 * Phase 5: restore decoder + key from IDB and start the camera in "resume" mode.
 */
async function resumeFromSaved(saved: SavedSession): Promise<void> {
  resumeBanner.style.display = "none";

  // Re-import the persisted AES key.
  let restoredKey: CryptoKey;
  try {
    restoredKey = await importKeyBytes(saved.keyBytes);
  } catch (err: unknown) {
    stats.textContent = `✗ resume: key import failed: ${err instanceof Error ? err.message : String(err)}`;
    return;
  }

  // Restore the decoder from the snapshot.
  const snap = {
    k: saved.k,
    blockLen: saved.blockLen,
    sessionId: saved.sessionId,
    totalLen: saved.totalLen,
    solvedBuffers: saved.solvedBuffers,
    solvedCount: saved.solvedCount,
    framesNew: saved.framesNew,
    seenSeqs: saved.seenSeqs,
  };
  decoder = restoreDecoder(snap);
  sessionId = saved.sessionId;
  currentKeyBytes = new Uint8Array(saved.keyBytes); // keep copy for ongoing saves

  // Synthesize a resolved sessionKeyPromise so onDecoded skips key-QR phase.
  sessionKeyPromise = Promise.resolve(restoredKey);
  resumingFromStore = true;

  // Update the key banner to reflect resumed state.
  keyBanner.style.cssText =
    "display:block;padding:10px;background:#1a1a2e;border:2px solid #a78bfa;" +
    "border-radius:6px;color:#a78bfa;font-family:monospace;font-size:13px;" +
    "text-align:center;margin-bottom:10px;";
  keyBanner.textContent = `↻ Resuming from ${Math.round(snapshotProgress(snap) * 100)}% — point camera at the QR stream to continue.`;

  // Show progress bar at the resumed position.
  progressEl.style.display = "block";
  bar.style.width = `${(snapshotProgress(snap) * 100).toFixed(1)}%`;
  startTs = performance.now();

  // Start the camera.
  void start();
}

async function start() {
  if (!navigator.mediaDevices?.getUserMedia) {
    stats.textContent =
      "✗ camera needs a secure context — this page must be served over " +
      "https to use the camera from another device (npm run dev:https).";
    return;
  }
  const captureWidth = Number((document.getElementById("cfg-width") as HTMLSelectElement).value);
  const captureFps = Number((document.getElementById("cfg-capfps") as HTMLSelectElement).value);
  const workerCount = Number((document.getElementById("cfg-workers") as HTMLSelectElement).value);
  // Read grid density from settings (cfg-grid select, added in Phase 3).
  // Falls back to 1 if the element doesn't exist (backward compat).
  const cfgGrid = document.getElementById("cfg-grid") as HTMLSelectElement | null;
  gridCells = cfgGrid ? Number(cfgGrid.value) : 1;
  settings.style.display = "none";
  startBtn.style.display = "none";
  preview.style.display = "block";
  metricsEl.style.display = "grid";
  keyBanner.style.display = "block";
  const mDiagEl = document.getElementById("m-diag");
  if (mDiagEl) {
    mDiagEl.style.display = "block";
    // Insert frameSnap canvas and download button after m-diag (idempotent).
    if (!document.getElementById("frame-snap")) {
      mDiagEl.insertAdjacentElement("afterend", snapBtn);
      mDiagEl.insertAdjacentElement("afterend", frameSnap);
    }
    frameSnap.style.display = "block";
    snapBtn.style.display = "inline-block";
  }
  const base: MediaTrackConstraints = {
    facingMode: "environment",
    width: { ideal: captureWidth },
    height: { ideal: Math.round((captureWidth * 3) / 4) },
  };
  try {
    try {
      stream = await navigator.mediaDevices.getUserMedia({
        audio: false,
        video: { ...base, frameRate: { exact: captureFps } },
      });
    } catch {
      stream = await navigator.mediaDevices.getUserMedia({
        audio: false,
        video: { ...base, frameRate: { ideal: captureFps } },
      });
    }
  } catch (err) {
    stats.textContent = `✗ camera: ${err instanceof Error ? err.message : String(err)}`;
    return;
  }
  video.srcObject = stream;
  await video.play().catch(() => undefined);
  // Show different status text depending on whether we're resuming or starting fresh.
  if (resumingFromStore) {
    resumingFromStore = false; // consumed — reset for any future fresh start
    stats.textContent = `camera ${stream.getVideoTracks()[0]?.getSettings().width}×${stream.getVideoTracks()[0]?.getSettings().height}@${stream.getVideoTracks()[0]?.getSettings().frameRate} — resuming, scan QR stream…`;
  } else {
    stats.textContent = `camera ${stream.getVideoTracks()[0]?.getSettings().width}×${stream.getVideoTracks()[0]?.getSettings().height}@${stream.getVideoTracks()[0]?.getSettings().frameRate} — scan key QR first…`;
  }

  for (let i = 0; i < workerCount; i++) {
    const w = new Worker(new URL("./worker.ts", import.meta.url), { type: "module" });
    const slot = i;
    w.onmessage = (e: MessageEvent) => {
      const { id, results, cellDecodeMs, rawCount, validCount } = e.data as {
        id: number;
        results: Uint8Array[];
        cellDecodeMs: number;
        rawCount: number;    // DIAGNOSTIC: total symbols zxing found in this frame
        validCount: number;  // DIAGNOSTIC: symbols that passed isValid+bytes filter
      };
      if (id === -1) return; // warm-up
      busy[slot] = false;

      // DIAGNOSTIC: accumulate rolling window counts
      const now = performance.now();
      if (now - diagWindowStart > 2000) {
        diagWindowStart = now;
        diagRawFrames = 0;
        diagRawSymbols = 0;
        diagValidSymbols = 0;
      }
      diagRawFrames++;
      diagRawSymbols += rawCount;
      diagValidSymbols += validCount;

      void cellDecodeMs;
      for (const bytes of results) {
        decodeTimes.push(now);
        cellDecodeTimes.push(now);
        void onDecoded(bytes);
      }
    };
    workers.push(w);
    busy.push(false);
  }
  diagWindowStart = performance.now();

  captureGen++;
  scheduleFrame(captureGen);
  setInterval(updateStats, 500);
  try {
    await (navigator as Navigator & { wakeLock?: { request(t: "screen"): Promise<unknown> } })
      .wakeLock?.request("screen");
  } catch {
    /* fine */
  }
}

type VideoRVFC = HTMLVideoElement & { requestVideoFrameCallback?: (cb: () => void) => number };

function scheduleFrame(gen: number) {
  if (done || gen !== captureGen) return;
  const v = video as VideoRVFC;
  const next = () => {
    if (done || gen !== captureGen) return;
    captureFrame();
    scheduleFrame(gen);
  };
  if (v.requestVideoFrameCallback) v.requestVideoFrameCallback(next);
  else requestAnimationFrame(next);
}

const grab = document.createElement("canvas");
let frameId = 0;

// DIAGNOSTIC: small preview canvas mirroring the last captured frame.
// Updated at most every 500ms (throttled) to avoid per-frame painting overhead.
// grab remains valid after getImageData() so we can drawImage from it.
const frameSnap = document.createElement("canvas");
frameSnap.id = "frame-snap";
frameSnap.style.cssText =
  "display:none;max-width:100%;border:1px solid #f0a500;margin:4px 8px;";
const snapBtn = document.createElement("button");
snapBtn.id = "snap-btn";
snapBtn.textContent = "Download last frame";
snapBtn.style.cssText =
  "display:none;font-family:monospace;font-size:12px;margin:4px 8px;" +
  "padding:4px 10px;background:#1a1a2e;color:#f0a500;border:1px solid #f0a500;" +
  "border-radius:4px;cursor:pointer;";
snapBtn.onclick = () => {
  if (!frameSnap.width) return;
  const a = document.createElement("a");
  a.href = frameSnap.toDataURL("image/png");
  a.download = `frame-${Date.now()}.png`;
  a.click();
};
let lastSnapMs = 0;
const SNAP_INTERVAL_MS = 500;

function captureFrame() {
  const vw = video.videoWidth;
  const vh = video.videoHeight;
  if (!vw || !vh) return;
  captureTimes.push(performance.now());
  const slot = busy.indexOf(false);
  if (slot === -1) return; // all workers busy — drop the frame, no harm done
  if (grab.width !== vw || grab.height !== vh) {
    grab.width = vw;
    grab.height = vh;
  }
  const ctx = grab.getContext("2d", { willReadFrequently: true })!;
  ctx.drawImage(video, 0, 0);

  // DIAGNOSTIC: throttled preview — grab is still valid after getImageData().
  const nowMs = performance.now();
  if (nowMs - lastSnapMs >= SNAP_INTERVAL_MS) {
    lastSnapMs = nowMs;
    const snapW = Math.min(400, vw);
    const snapH = Math.round((snapW / vw) * vh);
    if (frameSnap.width !== snapW || frameSnap.height !== snapH) {
      frameSnap.width = snapW;
      frameSnap.height = snapH;
    }
    frameSnap.getContext("2d")!.drawImage(grab, 0, 0, snapW, snapH);
  }

  const img = ctx.getImageData(0, 0, vw, vh);
  busy[slot] = true;
  workers[slot]!.postMessage(
    { id: frameId++, buf: img.data.buffer, w: vw, h: vh, maxSymbols: gridCells },
    [img.data.buffer],
  );
}

/**
 * Synchronously inspect bytes for a key QR frame.
 * If the bytes match the "K:" + hex(32 bytes) format, kick off importKeyBytes
 * and return the resulting Promise<CryptoKey> WITHOUT awaiting it.
 *
 * Returning a Promise (not awaiting) is the key to the race fix: the caller
 * can assign sessionKeyPromise = tryStartKeyImport(...) in a single sync
 * statement before any yield point, so no concurrent onDecoded call can
 * observe sessionKeyPromise===null after it has been set.
 */
function tryStartKeyImport(bytes: Uint8Array): Promise<CryptoKey> | null {
  // Key QR data is UTF-8 text: "K:" + 64 hex chars (66 bytes total as UTF-8)
  if (bytes.length !== KEY_PREFIX.length + KEY_HEX_LEN) return null;
  if (bytes[0] !== 0x4b || bytes[1] !== 0x3a) return null; // "K:"
  const hex = new TextDecoder().decode(bytes.subarray(2));
  if (!/^[0-9a-f]{64}$/.test(hex)) return null;
  const keyBytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    keyBytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  // importKeyBytes returns a Promise — we return it without awaiting.
  // The caller stores this Promise synchronously, closing the race window.
  return importKeyBytes(keyBytes).then((key) => {
    // Phase 5: capture raw key bytes for IDB persistence.
    // Done here (in the resolved callback, not at construction time) so
    // currentKeyBytes is only set after the key is confirmed valid by SubtleCrypto.
    currentKeyBytes = keyBytes;
    keyBanner.style.cssText =
      "display:block;padding:10px;background:#1a1a2e;border:2px solid #4ecca3;" +
      "border-radius:6px;color:#4ecca3;font-family:monospace;font-size:13px;" +
      "text-align:center;margin-bottom:10px;";
    keyBanner.textContent = "✓ Key received — now scan the main QR stream.";
    stats.textContent = `camera ready — scanning main stream…`;
    return key;
  });
}

async function onDecoded(bytes: Uint8Array): Promise<void> {
  decodeTimes.push(performance.now());

  // Atomic check-and-set: no await between the null-check and the assignment.
  // JS is single-threaded; async functions execute synchronously up to their
  // first await. The assignment below is that first yield-free statement, so
  // no concurrent onDecoded call can observe sessionKeyPromise===null after
  // the first call has set it — regardless of how many workers are running.
  if (!sessionKeyPromise) {
    const kp = tryStartKeyImport(bytes); // sync: returns Promise or null immediately
    if (kp) sessionKeyPromise = kp;      // sync assignment — no yield before this
    return; // drop this frame: either just started key import or no key yet
  }

  // Await the key (may already be resolved if import finished, or still pending).
  let key: CryptoKey;
  try {
    key = await sessionKeyPromise;
  } catch (err: unknown) {
    stats.textContent = `✗ key import failed: ${err instanceof Error ? err.message : String(err)}`;
    return;
  }

  const parsed = parseFrame(bytes);
  if (!parsed || done) return;
  const { header, block } = parsed;
  if (!decoder || sessionId !== header.sessionId) {
    // Phase 5: sender restarted with a new sessionId — delete the stale IDB record
    // so an accidental reload doesn't offer to resume the old (now-irrelevant) session.
    if (sessionId !== 0 && sessionId !== header.sessionId) {
      void deleteSession(sessionId).catch(() => {/* non-fatal */});
    }
    lastSaveTs = 0; // reset throttle so first frame of new session saves promptly
    decoder = new LTDecoder(header.k, header.blockLen, header.sessionId, header.totalLen);
    sessionId = header.sessionId;
    startTs = performance.now();
    progressEl.style.display = "block";
  }
  decoder.addFrame(header.seq, block);
  const progress = Math.min(0.99, decoder.framesNew / (decoder.k * OVERHEAD_EST));
  bar.style.width = `${(progress * 100).toFixed(1)}%`;

  // Phase 5: throttled IDB save — at most once per SAVE_INTERVAL_MS.
  // Also save when ≥90% complete (so a near-the-end reload still resumes well).
  const now90 = performance.now();
  const near90 = progress >= 0.9;
  if (currentKeyBytes && (now90 - lastSaveTs >= SAVE_INTERVAL_MS || near90)) {
    lastSaveTs = now90;
    const snap = snapshotDecoder(decoder);
    const record: SavedSession = {
      sessionId: decoder.sessionId,
      k: decoder.k,
      blockLen: decoder.blockLen,
      totalLen: decoder.totalLen,
      keyBytes: currentKeyBytes,
      solvedBuffers: snap.solvedBuffers,
      solvedCount: snap.solvedCount,
      framesNew: snap.framesNew,
      seenSeqs: snap.seenSeqs,
      savedAt: Date.now(),
    };
    void saveSession(record).catch(() => {/* IDB save failure is non-fatal */});
  }

  if (decoder.isComplete) {
    // Guard against duplicate completion: multiple concurrent onDecoded calls
    // can all observe decoder.isComplete===true if they were already past the
    // outer `if (!parsed || done)` check when the decoder completed.
    //
    // Fix: `if (done) return; done = true;` is a sync check-and-set — no await
    // between them, so JS's single-threaded execution guarantees only the first
    // call proceeds. Any subsequent call sees done===true and returns.
    if (done) return;
    done = true; // set synchronously before the first await below

    // assemble() returns the encrypted blob (IV + ciphertext + auth tag).
    const encryptedBlob = decoder.assemble()!;
    const seconds = (performance.now() - startTs) / 1000;
    // FNV verified over encrypted blob — same as what the sender computed.
    const hashOk = fnv1a(encryptedBlob) === header.payloadFnv;

    // Decrypt. AES-GCM auth tag failure throws — surface it as a user error.
    let compressed: Uint8Array;
    try {
      compressed = await aesGcmDecrypt(key, encryptedBlob);
    } catch (err: unknown) {
      stats.textContent = `✗ decryption failed (auth tag mismatch or wrong key): ${err instanceof Error ? err.message : String(err)}`;
      return;
    }

    // Decompress to recover the original file.
    void gzipDecompress(compressed)
      .then((original) => {
        finish(original, hashOk, seconds, encryptedBlob.length);
      })
      .catch((err: unknown) => {
        stats.textContent = `✗ decompression failed: ${err instanceof Error ? err.message : String(err)}`;
      });
  }
}

function finish(payload: Uint8Array, hashOk: boolean, seconds: number, totalLen: number) {
  // Defense-in-depth guard: finish() must never render the UI more than once.
  // The primary fix is in onDecoded (done set synchronously before any await),
  // but this guard catches any future code path that calls finish() directly.
  if (result.hasChildNodes()) return;

  // Phase 5: clear the IDB record for this session — transfer complete.
  void deleteSession(sessionId).catch(() => {/* non-fatal */});
  currentKeyBytes = null;
  captureGen++;
  stream?.getTracks().forEach((t) => t.stop());
  preview.style.display = "none";
  bar.style.width = "100%";
  keyBanner.style.display = "none";
  const kb = Math.round(totalLen / 1024);
  const rate = (totalLen / 1024 / seconds).toFixed(1);
  stats.textContent = `${kb} KB in ${seconds.toFixed(1)} s · ${rate} KB/s · hash ${hashOk ? "verified ✓" : "MISMATCH ✗"}`;

  const heading = document.createElement("div");
  heading.className = "done";
  heading.textContent = "Transfer Complete!";
  result.append(heading);

  // Phase 4: parse DCMN bundle and offer correct-typed downloads.
  // If the payload starts with the DCMN magic bytes, unbundle it;
  // otherwise treat it as a raw legacy payload (image/png assumed).
  const files = isBundled(payload) ? unbundleFiles(payload) : null;

  if (files && files.length > 0) {
    // --- Bundled path (Phase 4) ---
    for (const file of files) {
      // Copy into a plain ArrayBuffer-backed Uint8Array so Blob accepts it
      // (TypeScript can't narrow Uint8Array<ArrayBufferLike> → Uint8Array<ArrayBuffer>)
      const plainData = new Uint8Array(file.data.length);
      plainData.set(file.data);
      const blob = new Blob([plainData], { type: file.mime || "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const filename = file.name || "received-file";

      // If the file is an image, show a preview.
      if (file.mime.startsWith("image/")) {
        const img = document.createElement("img");
        img.className = "received";
        img.src = url;
        img.alt = filename;
        result.append(img);
      }

      // Always offer a download link with the correct filename.
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      link.className = "download-link";
      link.textContent = `⤓ Download ${filename} (${(file.data.length / 1024).toFixed(0)} KB)`;
      link.style.cssText =
        "display:block;margin:8px 0;padding:8px 12px;background:#1a1a2e;" +
        "border:1px solid #4ecca3;border-radius:6px;color:#4ecca3;" +
        "font-family:monospace;font-size:14px;text-decoration:none;";
      result.append(link);
    }

    if (files.length > 1) {
      const note = document.createElement("div");
      note.style.cssText = "font-size:12px;color:#888;margin-top:8px;font-family:monospace;";
      note.textContent = `✓ ${files.length} files received. Click each link to download individually.`;
      result.append(note);
    }
  } else {
    // --- Legacy raw path (pre-Phase-4 payload without DCMN magic) ---
    const plain = new Uint8Array(payload.length);
    plain.set(payload);
    const img = document.createElement("img");
    img.className = "received";
    img.src = URL.createObjectURL(new Blob([plain], { type: "image/png" }));
    result.append(img);
  }
}

function updateStats() {
  if (done) return;
  const now = performance.now();
  const prune = (a: number[]) => {
    while (a.length > 0 && a[0]! < now - 2000) a.shift();
  };
  prune(captureTimes);
  prune(decodeTimes);
  prune(cellDecodeTimes);
  metric("m-cap").textContent = (captureTimes.length / 2).toFixed(0);
  metric("m-dec").textContent = (decodeTimes.length / 2).toFixed(1);
  const mCells = document.getElementById("m-cells");
  if (mCells) mCells.textContent = (cellDecodeTimes.length / 2).toFixed(1);

  // DIAGNOSTIC: show raw-found/frame and valid/frame in stats text
  // rawPF = avg symbols zxing located per camera frame processed
  // validPF = avg symbols that passed isValid filter (= cells actually fed to decoder)
  // If rawPF ≈ validPF ≈ gridCells → multi-symbol detection working
  // If rawPF < gridCells → zxing not finding all symbols (layout/margin issue)
  // If rawPF > validPF → zxing finding but flagging invalid (decode error issue)
  const mDiag = document.getElementById("m-diag");
  if (mDiag && diagRawFrames > 0) {
    const rawPF = (diagRawSymbols / diagRawFrames).toFixed(2);
    const validPF = (diagValidSymbols / diagRawFrames).toFixed(2);
    mDiag.textContent =
      `[DIAG] gridCells=${gridCells} maxSymbols sent=✓ ` +
      `raw/frame=${rawPF} valid/frame=${validPF} ` +
      `frames=${diagRawFrames}`;
  }

  if (!decoder) return;
  const elapsed = (now - startTs) / 1000;
  const kbs = (decoder.framesNew * decoder.blockLen) / OVERHEAD_EST / 1024 / Math.max(0.1, elapsed);
  metric("m-rate").textContent = `${kbs.toFixed(1)} KB/s`;
  metric("m-time").textContent = `${elapsed.toFixed(0)} s`;
  metric("m-frames").textContent = `${decoder.framesNew}/${decoder.framesDup}`;
  metric("m-k").textContent = String(decoder.k);
  metric("m-block").textContent = `${decoder.blockLen} B`;
  metric("m-payload").textContent = `${Math.round(decoder.totalLen / 1024)} KB`;
}
