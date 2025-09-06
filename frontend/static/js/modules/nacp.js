// frontend/static/js/modules/nacp.js
// NullTrace Access Capsule Protocol (NT-C1) – med versjon, signert transkript, TTL og padding

import sodium from "libsodium-wrappers";
import { b64, u8, signDetached, verifyDetached } from "./handshake.js";
await sodium.ready;

// ───────────────────────────────────────────────────────────────
// Konfig
export const CAPSULE_TTL_MS = 2 * 60 * 1000; // 2 min
const PAD_MIN = 512;
const PAD_MAX = 1024;
const MAX_CAPSULE_BYTES = 4096; // defensiv grense på base64-dekodet JSON

// Versjon/alg – gir oss mulighet til å migrere senere
const CAPSULE_VER = "NT-C1";
const CAPSULE_ALG = "Ed25519|X25519+ML-KEM-512";

// ───────────────────────────────────────────────────────────────
// Utils
function randomPad(len) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return Array.from(arr, v => String.fromCharCode(33 + (v % 94))).join("");
}

function encStr(s){ return new TextEncoder().encode(s); }

// Kanonisk transkript for signatur/verifisering
function buildCapsuleTranscript(p) {
  // Rekkefølgen er viktig og må være stabil på begge sider.
  // Felt som ikke fantes i eldre kapsler ekskluderes (bakoverkompatibilitet).
  const parts = ["v=", p.v ?? "", "|alg=", p.alg ?? "", "|room=", p.room, "|cid=", p.cid,
                 "|x=", p.x, "|k=", p.k];
  if (typeof p.iat === "number") parts.push("|iat=", String(p.iat));
  parts.push("|exp=", String(p.exp));
  return encStr(parts.join(""));
}

// ───────────────────────────────────────────────────────────────
// Kapselbygging

/**
 * Lag en signert tilgangskapsel for å invitere en gjest.
 * Kapselen inneholder *ikke* rom-token; det hentes fra server før WS.
 */
export function createCapsule(room, xPub, pqPub, cid, idPriv, idPub) {
  const now = Date.now();
  const exp = now + CAPSULE_TTL_MS;

  const payload = {
    v:   CAPSULE_VER,
    alg: CAPSULE_ALG,
    room,
    cid,
    x:   b64(xPub),
    k:   b64(pqPub),
    iat: now,
    exp
  };

  // Signér kanonisk transkript
  const transcript = buildCapsuleTranscript(payload);
  const sig = signDetached(transcript, idPriv);

  const capsule = {
    payload,
    id:  b64(idPub),
    sig: b64(sig)
  };

  // Padding for å obfuskere størrelse
  let json = JSON.stringify(capsule);
  const target = PAD_MIN + Math.floor(Math.random() * (PAD_MAX - PAD_MIN + 1));
  const padCount = target - json.length;
  if (padCount > 0) capsule.pad = randomPad(padCount);

  json = JSON.stringify(capsule);
  return b64(new TextEncoder().encode(json));
}

// ───────────────────────────────────────────────────────────────
// Kapsel-parsing

/**
 * Parse og verifiser en tilgangskapsel.
 * Støtter både NT-C1 og eldre format (uten v/alg/iat).
 */
export function parseCapsule(str) {
  try {
    if (typeof str !== "string") return null;
    const trimmed = str.trim();

    // Base64 → bytes (defensiv grense)
    const bytes = u8(trimmed);
    if (bytes.length > MAX_CAPSULE_BYTES) return null;

    const raw = new TextDecoder().decode(bytes);
    const obj = JSON.parse(raw);

    if (!obj || typeof obj !== "object") return null;
    const { payload, id, sig } = obj || {};
    if (!payload || typeof payload !== "object") return null;

    const { v, alg, room, cid, x, k, iat, exp } = payload;

    // TTL-sjekker
    const now = Date.now();
    if (typeof exp !== "number" || now > exp) return null;
    if (typeof iat === "number" && (iat > now || exp - iat > CAPSULE_TTL_MS * 2)) {
      // unormal iat (i fremtiden eller altfor langt vindu)
      return null;
    }

    // Signatur-sjekk – bygg transkript etter hva kapselen faktisk inneholder
    const transcript = buildCapsuleTranscript(payload);
    const idPubBytes = u8(id);
    const sigBytes   = u8(sig);
    if (!verifyDetached(sigBytes, transcript, idPubBytes)) return null;

    // Dekode nøkler
    const xPub  = u8(x);
    const pqPub = u8(k);

    return {
      room,
      cid,
      xPub,
      pqPub,
      idPub: idPubBytes,
      ver: v || "legacy",
      alg: alg || "legacy"
    };
  } catch {
    return null;
  }
}
