// Sender: turn a file into an endless fountain-coded QR stream.
//
// Tuning notes from the experiments this PoC is distilled from:
// - Frame payload sets the QR version; denser wins on goodput as long as the
//   receiver can still decode it. 1465 bytes ≈ V27 is a safe middle ground
//   for arbitrary monitors; 2953 (V40) is the ceiling and works phone-to-
//   phone at close range.
// - The mask pattern is pinned (any declared mask is valid to a decoder);
//   this skips the spec's 8-way mask evaluation and speeds generation ~4×.
// - Displays need each frame shown for ≥2 refresh cycles or captures catch
//   the transition; 24 fps on a 60 Hz screen is comfortable.
// - Error correction stays at L by default: the fountain layer already
//   handles erasures, and a frame is either decoded whole or discarded.
//
// Phase 2 — encryption:
// - Key delivery: a separate "key QR" is shown before the main stream.
//   The receiver scans it once to obtain the AES-256-GCM session key.
//   The key is encoded as "K:" + hex(32 raw key bytes) — 66 chars total,
//   fits comfortably in a V3/ECC-M QR code. The "K:" prefix lets the
//   receiver distinguish it from fountain-coded data frames.
// - IV: 12 bytes prepended to the ciphertext blob; generated fresh per session.
// - FNV hash and totalLen are over the encrypted blob (IV + ciphertext + tag).
//
// Phase 3 — multi-QR grid:
// - A "grid density" setting controls how many QR codes are rendered per
//   displayed frame (1, 4, 9, or 16 — i.e. 1×1, 2×2, 3×3, 4×4).
// - Each grid cell carries a DIFFERENT fountain frame (different seq, different
//   encoded block). The receiver's zxing worker decodes all cells in one pass
//   using maxNumberOfSymbols = gridCells, feeding each into the same LTDecoder.
// - The key QR is still rendered as a single separate QR (not part of the grid).
// - Throughput scales by up to gridCells× per displayed frame — actual gain
//   depends on whether the receiver's worker pool can decode them fast enough.
//   This must be verified with a real device test, not assumed from grid math.

// Phase 4 — arbitrary file support:
// - A <input type="file" multiple> lets the user select any file(s).
// - Multiple files are bundled into a single DCMN container (shared/bundle.ts)
//   before the compress → encrypt → fountain pipeline.
// - The bundle manifest carries filename + MIME type inside the encrypted
//   payload (not in the frame header), so metadata is protected by AES-GCM.
// - Existing test-image presets are preserved as quick-start options.
// - Maximum file size is bounded by k (u16 ≤ 65,535 blocks):
//     at default blockLen=1445 B → max ≈ 90 MB raw input
//     at max blockLen=2933 B   → max ≈ 183 MB raw input
//   (totalLen is u32 = 4 GB, never the binding constraint.)
//   The UI validates and warns before attempting to send an oversized bundle.

import QRCode from "qrcode";
import { bundleFiles } from "../shared/bundle";
import { gzipCompress } from "../shared/compress";
import { aesGcmEncrypt, exportKeyBytes, generateAesKey } from "../shared/crypto";
import { LTEncoder } from "../shared/fountain";
import { HEADER_LEN, PROTO_VERSION, fnv1a, packFrame, type FrameHeader } from "../shared/protocol";

const MARGIN = 4;    // quiet-zone modules per cell (QR spec minimum)
// CELL_GAP: explicit white-pixel gap between adjacent cells in the grid,
// SEPARATE from each cell's MARGIN. Adjacent cells' quiet zones are not
// enough separation for zxing's finder-pattern detector — it needs physical
// blank space between symbol boundaries. 8px at scale=1 (scales up with the
// QR module scale, so at a typical scale=4 this becomes 32 display pixels).
const CELL_GAP = 8;
const LOOKAHEAD = 3;

const canvas = document.getElementById("qr") as HTMLCanvasElement;
const specs = document.getElementById("specs")!;
const cfgPayload = document.getElementById("cfg-payload") as HTMLSelectElement;
const cfgFps = document.getElementById("cfg-fps") as HTMLSelectElement;
const cfgBytes = document.getElementById("cfg-bytes") as HTMLSelectElement;
const cfgEcc = document.getElementById("cfg-ecc") as HTMLSelectElement;
const cfgSize = document.getElementById("cfg-size") as HTMLInputElement;
// Grid density control — added in Phase 3. Falls back to 1 if not found (for tests).
const cfgGrid = document.getElementById("cfg-grid") as HTMLSelectElement | null;
// Phase 4: file picker alongside the existing preset dropdown.
const cfgFileInput = document.getElementById("cfg-file") as HTMLInputElement | null;

// State: files selected via the picker. When non-null, overrides cfgPayload URL.
let selectedFiles: File[] | null = null;

// Key-QR overlay — created dynamically so the HTML doesn't need modification.
const keyStage = document.createElement("div");
keyStage.id = "key-stage";
keyStage.style.cssText =
  "display:none;text-align:center;margin:16px 0;padding:12px;background:#1a1a2e;" +
  "border:2px solid #4ecca3;border-radius:8px;";
const keyCanvas = document.createElement("canvas");
const keyLabel = document.createElement("div");
keyLabel.style.cssText = "color:#4ecca3;font-size:14px;margin-top:8px;font-family:monospace;";
keyLabel.textContent = "① Scan this key QR on the receiver first, then the transfer begins.";
keyStage.append(keyCanvas, keyLabel);
canvas.parentElement!.insertAdjacentElement("beforebegin", keyStage);

const payloadCache = new Map<string, Uint8Array>();
let generation = 0; // bumped on every restart; stale loops see it and die

// DIAGNOSTIC: large unmissable banner showing active grid mode.
// Inserted once after the specs line; updated on every startStream().
const gridBanner = document.createElement("div");
gridBanner.id = "grid-banner";
gridBanner.style.cssText =
  "font-family:monospace;font-size:18px;font-weight:bold;text-align:center;" +
  "padding:8px;margin:8px 0;border-radius:6px;border:3px solid;";
specs.insertAdjacentElement("afterend", gridBanner);

// Copy-to-clipboard button: lets receiver match settings without re-reading
// the screen. Inserted once alongside gridBanner; only appears after first stream.
const copySpecsBtn = document.createElement("button");
copySpecsBtn.id = "copy-specs-btn";
copySpecsBtn.textContent = "⎘ copy settings";
copySpecsBtn.style.cssText =
  "display:none;font-family:monospace;font-size:11px;padding:3px 10px;" +
  "background:#1b1712;color:#ffb257;border:1px solid #ffb257;border-radius:0;" +
  "cursor:pointer;margin-top:4px;";
copySpecsBtn.setAttribute("aria-label", "Copy current sender settings to clipboard");
copySpecsBtn.onclick = () => {
  const text = specs.textContent ?? "";
  void navigator.clipboard?.writeText(text).then(() => {
    copySpecsBtn.textContent = "✓ copied";
    setTimeout(() => { copySpecsBtn.textContent = "⎘ copy settings"; }, 1800);
  }).catch(() => {
    copySpecsBtn.textContent = "✗ copy failed";
    setTimeout(() => { copySpecsBtn.textContent = "⎘ copy settings"; }, 1800);
  });
};
gridBanner.insertAdjacentElement("afterend", copySpecsBtn);

async function loadPayload(url: string): Promise<Uint8Array | null> {
  const hit = payloadCache.get(url);
  if (hit) return hit;
  const res = await fetch(url);
  if (!res.ok) return null;
  const bytes = new Uint8Array(await res.arrayBuffer());
  payloadCache.set(url, bytes);
  return bytes;
}

/** Render a string value into a canvas element as a QR code. */
async function renderKeyQr(text: string): Promise<void> {
  await QRCode.toCanvas(keyCanvas, text, {
    errorCorrectionLevel: "M",
    margin: 2,
    width: 200,
  });
}

async function main() {
  // ── Feature detection ────────────────────────────────────────────────────
  // CompressionStream: Chrome 80+, Firefox 113+, Safari 16.4+.
  // SubtleCrypto: available on any HTTPS/localhost secure context.
  // Both are required — if either is missing, show a specific error instead of
  // crashing silently on the first compress/encrypt call.
  if (typeof CompressionStream === "undefined") {
    specs.textContent =
      "✗ Your browser doesn't support the Compression Streams API. " +
      "Try Chrome 80+, Firefox 113+, or update Safari to 16.4+.";
    return;
  }
  if (!window.crypto?.subtle) {
    specs.textContent =
      "✗ WebCrypto (crypto.subtle) is not available. " +
      "This page must be served over HTTPS — open it at the https:// address.";
    return;
  }

  const controls = [cfgPayload, cfgFps, cfgBytes, cfgEcc, cfgSize];
  if (cfgGrid) controls.push(cfgGrid);
  for (const el of controls) {
    el.addEventListener("change", () => void startStream());
  }
  // Phase 4: file picker — selecting files triggers a stream restart.
  if (cfgFileInput) {
    cfgFileInput.addEventListener("change", () => {
      const files = cfgFileInput.files ? Array.from(cfgFileInput.files) : null;
      selectedFiles = files && files.length > 0 ? files : null;
      // Update the filename display
      const namesEl = document.getElementById("cfg-file-names");
      if (namesEl) {
        if (selectedFiles && selectedFiles.length > 0) {
          namesEl.textContent = selectedFiles.map((f) => `${f.name} (${(f.size / 1024).toFixed(0)} KB)`).join(", ");
        } else {
          namesEl.textContent = "";
        }
      }
      void startStream();
    });
  }
  await startStream();
  try {
    await (navigator as Navigator & { wakeLock?: { request(t: "screen"): Promise<unknown> } })
      .wakeLock?.request("screen");
  } catch {
    /* fine without it */
  }
}

async function startStream() {
  const gen = ++generation;
  const frameBytes = Number(cfgBytes.value);
  const blockLen = frameBytes - HEADER_LEN;

  // --- Phase 4: resolve raw payload from file picker OR preset URL ---
  let rawPayload: Uint8Array;
  if (selectedFiles && selectedFiles.length > 0) {
    // Validate size before any async work: check k won't overflow u16 (65535).
    // We must compute on the COMPRESSED size (unknown until we compress), but
    // we can check the raw bundle size as a conservative upper bound — gzip
    // always produces output ≥ 1 byte, so if raw/blockLen > 65535 we warn.
    // The real check happens again after compression below.
    let totalRawBytes = 0;
    for (const f of selectedFiles) totalRawBytes += f.size;
    const kEstimate = Math.ceil(totalRawBytes / blockLen);
    if (kEstimate > 65535) {
      specs.textContent =
        `✗ Files too large: ~${Math.round(totalRawBytes / 1024 / 1024)} MB uncompressed, ` +
        `estimated ${kEstimate} blocks — maximum is 65,535 blocks ` +
        `(≈${Math.round(65535 * blockLen / 1024 / 1024)} MB at ${frameBytes} B/frame). ` +
        `Select fewer or smaller files.`;
      return;
    }
    // Read all files and bundle them.
    const entries = await Promise.all(
      selectedFiles.map(async (f) => ({
        name: f.name,
        mime: f.type || "application/octet-stream",
        data: new Uint8Array(await f.arrayBuffer()),
      })),
    );
    rawPayload = bundleFiles(entries);
  } else {
    // Preset URL path (original behavior).
    const loaded = await loadPayload(cfgPayload.value);
    if (!loaded) {
      specs.textContent = `✗ couldn't load ${cfgPayload.value}`;
      return;
    }
    // Wrap preset in a bundle too, so the receiver always speaks the same format.
    // Use the URL basename as the filename and guess image/png for the presets.
    const url = cfgPayload.value;
    const name = url.split("/").pop() ?? "file.bin";
    const mime = name.endsWith(".png") ? "image/png" :
                 name.endsWith(".jpg") || name.endsWith(".jpeg") ? "image/jpeg" :
                 "application/octet-stream";
    rawPayload = bundleFiles([{ name, mime, data: loaded }]);
  }

  if (gen !== generation) return; // superseded while reading files
  const txFps = Number(cfgFps.value);
  const ecc = cfgEcc.value as "L" | "M" | "Q" | "H";
  const displayPx = Number(cfgSize.value);
  const gridCells = cfgGrid ? Number(cfgGrid.value) : 1;
  const gridCols = Math.round(Math.sqrt(gridCells));

  // DIAGNOSTIC: update banner immediately so it's visible before crypto runs.
  if (gridCells > 1) {
    gridBanner.textContent = `GRID ACTIVE: ${gridCols}×${gridCols} = ${gridCells} CELLS/FRAME`;
    gridBanner.style.color = "#4ecca3";
    gridBanner.style.borderColor = "#4ecca3";
    gridBanner.style.background = "#0d2b22";
  } else {
    gridBanner.textContent = `SINGLE QR (1×1) — grid OFF`;
    gridBanner.style.color = "#888";
    gridBanner.style.borderColor = "#555";
    gridBanner.style.background = "#1a1a1a";
  }
  console.log(`[SENDER] startStream: gridCells=${gridCells} gridCols=${gridCols} cfgGrid.value=${cfgGrid?.value ?? "(no element)"}`);

  // Step 1: Compress.
  const compressed = await gzipCompress(rawPayload);

  // Post-compression k check — compressed size is the real input to fountain.
  const realK = Math.ceil(compressed.length / blockLen);
  if (realK > 65535) {
    specs.textContent =
      `✗ Compressed payload too large: ${Math.round(compressed.length / 1024 / 1024)} MB ` +
      `→ ${realK} blocks — maximum is 65,535. ` +
      `Try a smaller file or a larger bytes/frame setting.`;
    return;
  }


  // Step 2: Generate session key and render the key QR for the receiver to scan.
  // The key QR is always a single QR code — it is NOT part of the grid.
  const sessionKey = await generateAesKey();
  const keyBytes = await exportKeyBytes(sessionKey);
  const keyHex = Array.from(keyBytes).map((b) => b.toString(16).padStart(2, "0")).join("");
  keyStage.style.display = "block";
  await renderKeyQr(`K:${keyHex}`);

  // Step 3: Encrypt (bundle → compress → encrypt → fountain).
  const payload = await aesGcmEncrypt(sessionKey, compressed);

  if (gen !== generation) return;

  const sessionId = (Math.floor(Math.random() * 0xffff) + 1) & 0xffff;
  const encoder = new LTEncoder(payload, blockLen, sessionId);
  const baseHeader: FrameHeader = {
    version: PROTO_VERSION,
    sessionId,
    seq: 0,
    k: encoder.k,
    blockLen,
    totalLen: payload.length,
    payloadFnv: fnv1a(payload),
  };

  let qrVersion: number | undefined; // locked after the first QR is generated
  let cellModules = 0;               // module count per cell (including margin)
  const staging = document.createElement("canvas");
  const queue: ImageData[] = [];
  let nextSeq = 0;

  /** Size the output canvas to fit a gridCols×gridCols grid of cells with
   * CELL_GAP white pixels of separation between adjacent cells (in addition
   * to each cell's own MARGIN quiet zone). Returns the computed values so
   * makeGridFrame can use them without re-computing.
   */
  let _cellPx = 0; // set once by sizeCanvas, read by makeGridFrame
  let _gapPx = 0;
  const sizeCanvas = () => {
    const dpr = window.devicePixelRatio || 1;
    const cellTotal = cellModules;
    const budget = Math.min(0.9 * Math.min(window.innerWidth, window.innerHeight), displayPx);
    // scale: how many physical pixels per QR module
    // Budget must fit gridCols cells + (gridCols-1) gaps.
    // We solve for scale first (ignore gaps for now), then derive gap in same units.
    const scale = Math.max(1, Math.floor((budget * dpr) / (cellTotal * gridCols + CELL_GAP * (gridCols - 1))));
    _cellPx = cellTotal * scale;
    // CELL_GAP is in screen-pixel units at scale=1; multiply by scale so the
    // gap is proportionally the same physical size regardless of display scale.
    _gapPx = CELL_GAP * scale;
    const gridPx = _cellPx * gridCols + _gapPx * (gridCols - 1);
    staging.width = gridPx;
    staging.height = gridPx;
    canvas.width = gridPx;
    canvas.height = gridPx;
    canvas.style.width = `${gridPx / dpr}px`;
    canvas.style.height = `${gridPx / dpr}px`;
  };

  /**
   * Render one QR code cell for fountain frame at seq `s` into ImageData.
   * Returns the ImageData for the cell AND the module size (for first-time sizing).
   */
  const makeCell = (s: number): { img: ImageData; modules: number } => {
    const bytes = packFrame({ ...baseHeader, seq: s }, encoder.encode(s));
    const qr = QRCode.create([{ data: bytes, mode: "byte" } as unknown as QRCode.QRCodeSegment], {
      errorCorrectionLevel: ecc,
      version: qrVersion,
      maskPattern: 4,
    });
    qrVersion = qr.version;
    const size = qr.modules.size;
    const total = size + 2 * MARGIN;
    const img = new ImageData(total, total);
    const px = new Uint32Array(img.data.buffer);
    px.fill(0xffffffff);
    const data = qr.modules.data;
    for (let y = 0; y < size; y++) {
      const row = (y + MARGIN) * total + MARGIN;
      const src = y * size;
      for (let x = 0; x < size; x++) {
        if (data[src + x]) px[row + x] = 0xff000000;
      }
    }
    return { img, modules: total };
  };

  /**
   * Build one grid ImageData: gridCols×gridCols cells, each a different fountain frame.
   * Advances nextSeq by gridCells.
   */
  const makeGridFrame = (): ImageData => {
    const cells: ImageData[] = [];
    for (let i = 0; i < gridCells; i++) {
      const { img, modules } = makeCell(nextSeq++);
      if (cellModules === 0) {
        // First cell ever: lock cell size and resize the output canvas.
        cellModules = modules;
        sizeCanvas();
        specs.textContent =
          `${txFps} FPS · ${frameBytes} B/frame · V${qrVersion!} · ECC ${ecc} · ` +
          `grid ${gridCols}×${gridCols} (${gridCells} cells/frame, gap=${CELL_GAP}px) · ` +
          `${Math.round(rawPayload.length / 1024)} KB raw → ` +
          `${Math.round(compressed.length / 1024)} KB compressed → ` +
          `${Math.round(payload.length / 1024)} KB encrypted · K=${encoder.k}`;
        copySpecsBtn.style.display = "inline-block";
      }
      cells.push(img);

    }

    // Composite cells into the grid with CELL_GAP white separation between them.
    // Each cell is placed at: x = col * (cellPx + gapPx), y = row * (cellPx + gapPx).
    // The staging canvas is pre-filled white, so gaps are automatically white space.
    const ctx2d = staging.getContext("2d")!;
    ctx2d.fillStyle = "#fff";
    ctx2d.fillRect(0, 0, staging.width, staging.height);
    for (let i = 0; i < cells.length; i++) {
      const col = i % gridCols;
      const row = Math.floor(i / gridCols);
      const x = col * (_cellPx + _gapPx);
      const y = row * (_cellPx + _gapPx);
      // Draw via temporary canvas (putImageData doesn't support scaling).
      const tmp = document.createElement("canvas");
      tmp.width = cells[i]!.width;
      tmp.height = cells[i]!.height;
      tmp.getContext("2d")!.putImageData(cells[i]!, 0, 0);
      ctx2d.drawImage(tmp, x, y, _cellPx, _cellPx);
    }
    return ctx2d.getImageData(0, 0, staging.width, staging.height);
  };

  const pump = () => {
    if (gen !== generation) return;
    try {
      while (queue.length < LOOKAHEAD) queue.push(makeGridFrame());
    } catch (err) {
      specs.textContent = `✗ QR render error: ${err instanceof Error ? err.message : String(err)}`;
      return;
    }
    setTimeout(pump, 0);
  };
  pump();

  const interval = 1000 / txFps;
  let nextAt = performance.now();
  const tick = (now: number) => {
    if (gen !== generation) return;
    requestAnimationFrame(tick);
    if (now < nextAt) return;
    const img = queue.shift();
    if (!img) {
      nextAt = now + interval;
      return;
    }
    canvas.getContext("2d")!.putImageData(img, 0, 0);
    nextAt += interval;
    if (now - nextAt > 3 * interval) nextAt = now + interval;
  };
  requestAnimationFrame(tick);
}

void main();
