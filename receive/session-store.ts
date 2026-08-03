// IndexedDB persistence layer for fountain decoder sessions.
//
// WHY WE PERSIST THE AES KEY:
// The raw 32-byte AES key is stored in IDB alongside the decoder state.
// Security trade-off: IDB is local device storage only — the key is never
// re-transmitted. Persisting it extends the key lifetime from "tab lifetime"
// to "until transfer completes or user clears sessions". For a page-reload
// scenario (accidental navigation, phone lock killing the tab) this is the
// right trade-off: the alternative is requiring the user to re-scan the key
// QR on resume, but the sender's key QR only appears at stream start and the
// sender may have moved on. We clear the key from IDB on transfer completion
// and on manual "Clear saved session" actions. If the device is physically
// seized mid-transfer, the key is recoverable from IDB — acceptable for this
// local optical transfer use case.
//
// IDB SCHEMA:
//   DB name:    "dcmn-sessions"
//   Store name: "sessions"
//   Key:        sessionId (number / u32)
//
// PERSISTENCE FREQUENCY:
//   Caller throttles writes to every ~2 seconds during frame acceptance.
//   One final write is made when the session is very close to complete (≥90%)
//   so a last-second reload still resumes from near the end.

export interface SavedSession {
  sessionId: number;          // IDB key — matches frame header sessionId
  k: number;                  // LTDecoder: total source blocks
  blockLen: number;           // LTDecoder: bytes per block
  totalLen: number;           // LTDecoder: original payload byte length
  keyBytes: Uint8Array;       // 32 raw AES-256-GCM key bytes
  // Decoder solved state: k-length array, each entry is a blockLen-byte
  // buffer (as ArrayBuffer for structured-clone compatibility) or null.
  solvedBuffers: (ArrayBuffer | null)[];
  solvedCount: number;        // mirrors LTDecoder.solvedCount
  framesNew: number;          // mirrors LTDecoder.framesNew
  seenSeqs: number[];         // sorted array of all seq values already seen
  savedAt: number;            // Date.now() — for "saved X minutes ago" display
}

const DB_NAME = "dcmn-sessions";
const STORE = "sessions";
const DB_VERSION = 1;

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      req.result.createObjectStore(STORE, { keyPath: "sessionId" });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

/** Persist or update a session record. */
export async function saveSession(session: SavedSession): Promise<void> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put(session);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/** Load all saved sessions (there will usually be 0 or 1). */
export async function loadAllSessions(): Promise<SavedSession[]> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly");
    const req = tx.objectStore(STORE).getAll();
    req.onsuccess = () => resolve(req.result as SavedSession[]);
    req.onerror = () => reject(req.error);
  });
}

/** Load a specific session by sessionId. Returns undefined if not found. */
export async function loadSession(sessionId: number): Promise<SavedSession | undefined> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly");
    const req = tx.objectStore(STORE).get(sessionId);
    req.onsuccess = () => resolve(req.result as SavedSession | undefined);
    req.onerror = () => reject(req.error);
  });
}

/** Delete a session record (called on completion or manual clear). */
export async function deleteSession(sessionId: number): Promise<void> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).delete(sessionId);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/** Delete ALL session records (manual "clear saved sessions" action). */
export async function clearAllSessions(): Promise<void> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).clear();
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}
