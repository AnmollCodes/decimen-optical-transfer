# Decimen Optical Transfer: fountain-coded QR file transfer

Send a file between two devices using nothing but a screen and a camera. One page displays the file as an endless stream of animated QR codes; another device points its camera at it and reconstructs the file. No network path between the devices, no app, no pairing, no permissions beyond the camera. The payload travels as light.

This began as a minimal proof of concept extracted from a larger experiment that reached 128 KB/s phone-to-phone with denser frames, multi-code grids, and an error-corrected color channel. It has since grown into a real, production-hardened tool: end-to-end encrypted, compressed, resumable across interruptions, capable of arbitrary multi-file transfers, and roughly 10x faster than where it started — every claim below verified on real hardware, not just in a test suite.

> **This is a fork.** The original proof of concept — the fountain-coded QR core, the cross-engine determinism fixes, the camera capture pipeline — was built by [bashalarmistalt](https://github.com/bashalarmistalt/decimen-optical-transfer). Everything from **Phase 1 onward** in this document is new work built on top of that foundation. See [Credit & License](#credit--license) at the bottom.

---

## Table of contents

- [Why this exists](#why-this-exists)
- [What it does](#what-it-does)
- [Quick start](#quick-start)
- [Architecture](#architecture)
- [How the fountain-code channel works](#how-the-fountain-code-channel-works)
- [The build: six phases, six real device tests](#the-build-six-phases-six-real-device-tests)
  - [Phase 0 — Tests, lint, CI](#phase-0--tests-lint-ci)
  - [Phase 1 — Compression](#phase-1--compression)
  - [Phase 2 — End-to-end encryption](#phase-2--end-to-end-encryption)
  - [Phase 3 — Multi-QR grid: the 10x throughput phase](#phase-3--multi-qr-grid-the-10x-throughput-phase)
  - [Phase 4 — Arbitrary file and multi-file support](#phase-4--arbitrary-file-and-multi-file-support)
  - [Phase 5 — Resumable sessions](#phase-5--resumable-sessions)
  - [Phase 6 — Security hardening and QA](#phase-6--security-hardening-and-qa)
- [Performance](#performance)
- [Security model](#security-model)
- [Known limitations](#known-limitations)
- [Testing](#testing)
- [Tuning reference](#tuning-reference)
- [Roadmap](#roadmap)
- [Credit & License](#credit--license)

---

## Why this exists

Most file-sharing methods assume some communication channel exists between two devices — Wi-Fi, Bluetooth, a cable, a shared cloud account. Sometimes none of those are available or trusted: an air-gapped machine, a device with radios disabled, two devices that simply cannot see each other on a network.

A screen and a camera are always there. This project turns that into a channel.

## What it does

| Capability | Status |
|---|---|
| Screen-to-camera file transfer, zero network | Core (inherited) |
| gzip compression before transfer | Phase 1 |
| AES-256-GCM end-to-end encryption | Phase 2 |
| ~10x throughput via multi-QR grid rendering | Phase 3 |
| Any file type, single or multiple files | Phase 4 |
| Resume an interrupted transfer, no restart | Phase 5 |
| Bounds-checked, audited against malformed input | Phase 6 |

Every row above the core was built, tested, and verified with a real laptop-to-phone transfer — not assumed to work because the code looked right.

## Quick start

```bash
npm install
npm run dev
```

- On the sending device (a laptop is ideal): open `https://localhost:5173/send/`. Pick a file, or use one of the built-in test payloads. It starts streaming immediately. Max screen brightness helps.
- On the receiving device (a phone): open the Network URL Vite prints (`https://<lan-ip>:5173/receive/`), accept the certificate warning once, tap **Start camera**, and point it at the screen.
- A key QR appears first — scan that one before the main stream. The receiver will tell you when it's ready.
- A few seconds later: **Transfer Complete!**, hash verified, and your file downloads with its original name and extension intact.

**Why HTTPS is required:** the receiver uses `getUserMedia`, and browsers strip that API entirely on insecure origins — a phone reaching your dev server over plain HTTP has no camera access, full stop. The dev server ships with a self-signed certificate (`@vitejs/plugin-basic-ssl`) for exactly this reason.

Hold the phone steady, or prop it against something. Camera autofocus hunting from hand tremor remains the single biggest throughput killer, same as the original PoC found.

## Architecture

```
shared/
  protocol.ts        20-byte frame header (pack/parse), FNV-1a hash, splitmix32 PRNG, bounds constants
  fountain.ts         LT fountain codec — LTEncoder (infinite stream), LTDecoder (reassembly)
  compress.ts         gzip via the browser-native Compression Streams API          [Phase 1]
  crypto.ts           AES-256-GCM: key gen, export/import, encrypt/decrypt         [Phase 2]
  bundle.ts           DCMN multi-file bundle format: bundleFiles, unbundleFiles     [Phase 4]
  decoder-state.ts    Pure decoder snapshot/restore for resumability               [Phase 5]

send/
  index.html          Sender UI — file picker, presets, FPS/ECC/grid controls
  main.ts             file → bundle → compress → encrypt → fountain-split → QR grid render

receive/
  index.html          Receiver UI — camera settings, grid density, session controls
  main.ts             camera → worker → fountain decode → decrypt → decompress → download
  worker.ts           zxing-wasm decode worker, one or more QR symbols per frame
  session-store.ts    IndexedDB wrapper for resumable sessions                     [Phase 5]

tests/
  protocol.test.ts, fountain.test.ts          core codec correctness
  compression.test.ts, crypto.test.ts         Phase 1 / Phase 2
  file-bundle.test.ts, resume.test.ts         Phase 4 / Phase 5
  hardening.test.ts, e2e-pipeline.test.ts     Phase 6 — bounds checks + full pipeline integration
```

### The full pipeline, one file end to end

```
                    SENDER                                         RECEIVER
              ┌──────────────┐                              ┌──────────────┐
  files  ───▶ │  bundleFiles │                              │ unbundleFiles│ ───▶ files
              │  (Phase 4)   │                              │  (Phase 4)   │
              └──────┬───────┘                              └──────▲───────┘
                     ▼                                             │
              ┌──────────────┐                              ┌──────────────┐
              │ gzipCompress │                              │gzipDecompress│
              │  (Phase 1)   │                              │  (Phase 1)   │
              └──────┬───────┘                              └──────▲───────┘
                     ▼                                             │
              ┌──────────────┐                              ┌──────────────┐
              │ aesGcmEncrypt│                              │aesGcmDecrypt │
              │  (Phase 2)   │                              │  (Phase 2)   │
              └──────┬───────┘                              └──────▲───────┘
                     ▼                                             │
              ┌──────────────┐                              ┌──────────────┐
              │  LTEncoder   │   ══════ light ══════▶        │  LTDecoder   │
              │ + QR grid    │   (screen → camera,           │ + zxing-wasm │
              │  (Phase 3)   │    no network)                │  (Phase 3)   │
              └──────────────┘                              └──────────────┘
                                                                     │
                                                       Phase 5: decoder state
                                                       snapshotted to IndexedDB
                                                       every 2s — survives a
                                                       page reload mid-transfer
```

## How the fountain-code channel works

A screen-to-camera link has no back-channel. The receiver cannot ask the sender to resend a missed frame, and it will inevitably miss some — blur, refresh timing, autofocus hunting. Looping a fixed sequence of frames and hoping the receiver catches everything is fragile: miss one frame and you wait a full cycle for it to come back around.

**Fountain codes** solve this completely. The sender never transmits the file's blocks directly. Each frame is the XOR of a pseudorandom subset of blocks, with subset sizes drawn from a robust-soliton distribution (Luby Transform coding). The receiver collects any sufficiently large set of distinct frames — no particular ones, in no particular order — and mathematically peels the original file back out. A dropped frame costs a little time. It never costs correctness.

Every frame is also fully self-describing: a 20-byte header carries the session ID, sequence number, block count and size, file length, and an integrity hash. There is no handshake. The receiver locks onto a stream mid-flight, and restarting the sender resets the receiver automatically.

## The build: six phases, six real device tests

Every phase below followed the same discipline: implement, run the full test suite, then physically run a transfer between a real laptop and a real Android phone before calling it done. Several phases surfaced real bugs during that device-testing step that no amount of code review alone would have caught — those are called out honestly below, because that's the actual value of testing on hardware instead of trusting a green checkmark.

### Phase 0 — Tests, lint, CI

The original PoC shipped with zero automated tests and no CI. Before touching any feature, this fork added:

- A Vitest suite with golden-vector tests for the FNV-1a hash and the `splitmix32` PRNG — the exact numbers the original author flagged as needing to stay bit-identical across V8 and JavaScriptCore
- An ESLint v9 flat config
- A GitHub Actions workflow running typecheck, lint, and test on every push and pull request

**Result:** 33 tests passing, clean baseline to build every later phase against.

### Phase 1 — Compression

Files are gzip-compressed with the browser-native `CompressionStream`/`DecompressionStream` API before entering the fountain encoder, and decompressed after reconstruction on the receive side. Zero dependencies added — it's a standard Web API, not a library.

One real design decision worth stating: the integrity hash (`payloadFnv`) is computed over the **compressed** bytes, not the original file — because that's what actually travels the optical channel, and that's the layer whose integrity needs verifying.

**Real device result** (laptop Chrome → Android Chrome): a 522 KB compressed payload transferred in 122.1 seconds at 4.3 KB/s, hash verified. This became the baseline every later phase was measured against.

### Phase 2 — End-to-end encryption

AES-256-GCM via the browser's native `SubtleCrypto`. The sender generates a random key per session and delivers it to the receiver as a separate, one-time QR code — scanned before the main data stream begins — so there's no manual passphrase exchange and no shared secret typed on both ends.

A 12-byte random IV is generated per encryption. Since exactly one encryption happens per transfer session, the (key, IV) pair is always unique by construction — there is no reuse scenario in this design.

**A real bug found during device testing, not code review:** the receiver's frame-decode path runs across multiple concurrent Web Workers. A race condition meant two workers could each observe the session key as "not yet imported" and both attempt the import simultaneously. Fixed with an atomic check-and-set: the key-import promise is assigned in a single synchronous statement with no `await` before it, closing the window where a second caller could slip through. This exact pattern — synchronous assignment before any yield point — was reused again in Phase 4 when an analogous race caused a duplicate "Transfer Complete" render.

**Real device result:** key QR scanned successfully, clear UX transition ("Key received — now scan the main QR stream"), 522 KB payload transferred with hash verified.

### Phase 3 — Multi-QR grid: the 10x throughput phase

This is the phase where the project's actual throughput problem got solved — and it took five rounds of real-device debugging to get there, which is worth documenting honestly because the debugging process is the more instructive part.

**The idea:** instead of one QR code per displayed frame, render a 2×2 grid of four independent QR codes per frame, each carrying its own fountain-coded block. `zxing-wasm`'s native multi-symbol detection (`maxNumberOfSymbols`) finds and decodes all four in a single scan pass — no custom image-splitting code needed, once the right library option was found.

**What actually happened, in order:**

1. First real device test: **no improvement at all** — 4.4 KB/s versus the 4.3 KB/s baseline. A diagnostic instrument (`raw/frame` and `valid/frame` counters, plus a "download last captured frame" button) was added rather than guessing at a fix.
2. The diagnostic revealed `raw/frame ≈ 0.20` — zxing was finding roughly one-fifth of a symbol per frame, nowhere near the four it should have found.
3. First hypothesis: insufficient quiet-zone spacing between adjacent QR cells, causing zxing's finder-pattern detector to get confused across cell boundaries. An 8px gap was added between cells. **This didn't move the number at all** (still ≈0.20) — because of the next finding.
4. The downloaded frame capture showed the actual root cause: the sender was still rendering a single dense QR code, not a 2×2 grid, in every prior test. The grid setting had never actually taken effect.
5. Fixed with an unmissable visual confirmation banner ("GRID ACTIVE: 2×2 = 4 CELLS/FRAME") so a silent configuration mismatch could never happen again.
6. Once grid mode was genuinely active, the earlier gap fix — previously untested because the bug it was meant to fix didn't exist yet — turned out to be exactly correct.

**Real device result:** 522 KB payload transferred in 12.3 seconds at 44.0 KB/s — a measured **~10x improvement** over the Phase 1 baseline, hash verified, on real hardware.

### Phase 4 — Arbitrary file and multi-file support

The fixed test-image presets were replaced with a real file picker supporting any file type and multiple files per transfer. A custom lightweight bundle format (magic bytes `DCMN`, a manifest of filename/MIME-type/size per entry, followed by concatenated file data) wraps one or more files into a single payload before it enters the existing compress → encrypt → fountain pipeline — no new dependency, no zip library.

Filenames and MIME types are deliberately stored inside the encrypted payload rather than the frame header, so they benefit from the same AES-256-GCM protection as the file content, and no protocol version bump was needed for this feature.

**A real bug found during device testing:** the completion screen rendered twice for a single transfer, caused by the same class of async race as Phase 2's key-import bug — multiple concurrent worker callbacks could both pass the "not yet finished" check before either one set a flag. Fixed with the identical atomic guard pattern.

**Real device results:** a real `.txt` file downloaded with its correct filename and extension intact; a real signed PDF offer letter (272 KB) transferred correctly; and a two-file transfer produced two separate, correctly-named download links, each verified by tapping and downloading on the phone.

### Phase 5 — Resumable sessions

If the receiver's page is reloaded mid-transfer — an accidental navigation, the browser reclaiming the tab, a phone lock screen killing it — the transfer no longer has to restart from zero. The fountain decoder's solved-block state, the session identifiers, and the AES key are snapshotted to IndexedDB every two seconds. On reload, a clear resume prompt appears with the transfer's age and progress, and the user explicitly chooses to resume or start fresh — never a silent auto-resume of a stale session.

**A documented tradeoff, stated plainly rather than glossed over:** persisting the raw AES key to IndexedDB extends its lifetime from "tab session" to "until the transfer completes or is cleared." The key was already resident in JavaScript's heap memory for the full transfer duration regardless, so this doesn't meaningfully change the threat model for a local, single-device optical-transfer tool — but it is a real design choice, not a free win, and it's written down as one.

**Real device result, all three scenarios verified on hardware:**

1. A transfer was manually interrupted via page reload at 56% progress (272 KB of a 484 KB file). The resume banner appeared correctly. Tapping Resume continued the transfer to completion — the file downloaded correctly, with its name and extension intact.
2. Reloading the page again *after* completion showed no stale banner, confirming the IndexedDB record was cleared.
3. Tapping "Start fresh" instead of Resume correctly discarded the old progress and began a clean new transfer.

### Phase 6 — Security hardening and QA

A dedicated pass over the finished codebase, with three findings worth calling out:

**Frame header bounds.** `parseFrame` previously rejected zero values but had no upper bound. A worst-case calculation showed a malicious or corrupted frame claiming an unbounded block length combined with the maximum block count could force an allocation approaching 4 GB. Fixed by capping `blockLen` at 2953 bytes — the actual physical maximum a real QR code (version 40, error correction L) can carry — and `totalLen` at 500 MB, a generous ceiling well above the protocol's practical limit.

**A real denial-of-service finding in the bundle parser.** `unbundleFiles` could be handed a manifest claiming a file count of over four billion, causing an unbounded busy-loop before the existing truncation check would ever trigger. Fixed with explicit caps on file count, filename length, and MIME-type length, each rejected immediately with a clear error rather than iterating first.

**A full non-null-assertion audit.** The codebase carries 47 TypeScript non-null assertions, each one reviewed individually with documented reasoning for why it is provably safe by construction — array indices bounded by loop conditions, DOM elements guaranteed to exist by the page's own structure, decoder state guaranteed non-null by the calling code's invariants. Zero were found to be genuine bugs.

An XSS/injection review confirmed every place a filename or MIME type reaches the DOM uses safe `textContent` or property assignment, never raw HTML insertion — independently re-verified by hand, not just taken on the audit's word.

**Result:** 125 tests passing, `npm audit` reports zero vulnerabilities, and a new end-to-end integration test exercises the complete pure-logic pipeline — bundle, compress, encrypt, fountain-encode, fountain-decode, decrypt, decompress, unbundle — in a single assertion, alongside explicit tests for wrong-key rejection and tamper detection.

## Performance

| Configuration | Payload | Time | Throughput | Notes |
|---|---|---|---|---|
| Single QR (Phase 1 baseline) | 522 KB | 122.1 s | 4.3 KB/s | Compression only |
| 2×2 grid (Phase 3) | 522 KB | 12.3 s | 44.0 KB/s | **~10x** over baseline, real device |

The parent experiment this fork was originally extracted from measured a ceiling of roughly 128 KB/s handheld and 186 KB/s propped, using denser frames, a 120 fps sender, and stacked color codes. This fork currently ships single-color grid rendering; there is real, measured headroom above the current 44 KB/s figure that hasn't been chased down (see [Known limitations](#known-limitations)).

## Security model

- **Encryption:** AES-256-GCM, one key per session, delivered out-of-band via a scanned key QR — never typed, never sent over any network.
- **Integrity, two independent layers:** an FNV-1a hash verifies what the fountain-coded optical channel actually transported; AES-GCM's built-in authentication tag independently verifies what was encrypted. A tampered ciphertext or a wrong key fails cleanly with a visible error — it never silently produces corrupted output.
- **Input validation:** frame headers and file bundle manifests are bounds-checked against a malicious or corrupted stream before any expensive allocation happens.
- **What this does not protect against:** a device physically compromised while a transfer is in progress can recover the session key from IndexedDB — but the key is already resident in memory during any transfer regardless, so this isn't a meaningfully new exposure. There is currently no verified protection against a third party's camera also capturing the optical stream in the same room; encryption ensures they'd capture ciphertext, not plaintext, but this hasn't been a stated design goal beyond that.

## Known limitations

Stated plainly, not hidden in fine print:

- **File size ceiling:** roughly 90 MB at default settings, up to ~183 MB at the maximum block size — bounded by the fountain protocol's 16-bit block-count field, not by the 32-bit total-length field.
- **No zip bundling for multiple files:** each file gets its own individual download link. No browser-native zip API exists, and adding a compression library was ruled out to keep the project at zero runtime dependencies.
- **Cross-engine verification is Blink-only.** Every phase above was verified with a Chromium-based sender and a Chromium-based (Android Chrome) receiver. Safari and JavaScriptCore have not yet been tested on real hardware — this is the single most important open item in the project right now.
- **Grid density is not auto-negotiated.** Sender and receiver must be manually set to the same grid density; a mismatch silently underperforms rather than failing loudly. This bit the project directly during Phase 3 debugging.
- **One saved session at a time** in the resumable-sessions store; a manual "clear saved session" control exists for cleanup.
- **Measured throughput has real headroom.** The 2×2 grid achieves roughly 1.67 of a theoretical maximum of 4 decoded symbols per camera frame — worker throughput tuning or a denser grid could plausibly go further, untested.

## Testing

```bash
npm run typecheck   # tsc --noEmit
npm run lint        # eslint, flat config
npm run test        # vitest — 125 tests across 9 files
```

Every phase's automated tests are additive — nothing from an earlier phase was ever quietly modified to make a later phase pass. The suite currently covers the fountain codec, compression, encryption (including race-condition regression tests), file bundling, session resumability, and a full end-to-end pipeline integration test — all runnable in Node, with no browser required. What genuinely cannot be tested outside a real browser and camera — QR rendering fidelity, multi-symbol camera detection, actual device throughput — was verified by hand on real hardware at every phase, and the results are documented above rather than assumed.

## Tuning reference

Both sender and receiver pages have a collapsible Settings panel.

| Setting | Where | Default | Notes |
|---|---|---|---|
| Grid density | Both, must match | 1×1 | 2×2 verified with a real 10x gain; 3×3/4×4 exist but are untested on hardware |
| Tx FPS | Sender | 24 | Each frame needs at least 2 display refresh cycles |
| Bytes / frame | Sender | 1465 (QR v27) | Denser (2953, v40) works at close range if the receiver can still decode it |
| Error correction | Sender | L | Deliberately minimum — the fountain layer, not in-frame ECC, handles erasure |
| Decode workers | Receiver | 2 | Increase toward 4 at higher grid densities |

## Roadmap

Deliberately not yet done, in rough priority order:

1. Verify the full pipeline on iOS Safari / JavaScriptCore
2. Auto-negotiate grid density between sender and receiver instead of requiring manual matching
3. Investigate the gap between measured (1.67) and theoretical (4.0) symbols-per-frame at 2×2 density
4. Package `shared/` as a standalone, independently importable library
5. PWA support for installable, offline-capable use
6. Color-channel encoding, as explored in the parent experiment this project was extracted from

## Credit & License

This project is forked from [bashalarmistalt/decimen-optical-transfer](https://github.com/bashalarmistalt/decimen-optical-transfer), which built the original proof of concept: the fountain-coded QR core, the cross-engine determinism fixes for the soliton distribution math, the iOS camera frame-rate handling, and the WASM-based decode pipeline. That work — and the write-up explaining the fountain-coding approach — is the foundation everything in this document is built on top of.

Similar independent projects worth a look:

- [mohankumarelec/airgapped-qr-code-transfer](https://github.com/mohankumarelec/airgapped-qr-code-transfer) — browser-based QR file transfer with compression and sequential chunking
- [divan/txqr](https://github.com/divan/txqr) (2018) — animated QR plus fountain codes in Go, with excellent write-ups on why fountain coding beats sequential looping
- [sz3/libcimbar](https://github.com/sz3/libcimbar) — a custom high-density color code purpose-built for this exact channel

Licensed under MIT — see [LICENSE](./LICENSE). The original copyright notice is preserved unchanged.