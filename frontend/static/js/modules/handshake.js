import sodium from "libsodium-wrappers";
import { MlKem768 } from "mlkem";
import { createInitiator, createResponder } from "./ratchet.js";
await sodium.ready;

export const PROTOCOL_VERSION = 3;
export const SUITE = "Ed25519|X25519+ML-KEM-768|HKDF-SHA256|vodozemac-Double-Ratchet|XChaCha20-Poly1305";
export const enc = sodium.base64_variants.ORIGINAL;
export const b64 = value => sodium.to_base64(value, enc);
export const u8 = value => {
  if (typeof value !== "string" || value.length > 24576) throw new Error("Invalid encoding");
  return sodium.from_base64(value, enc);
};
export const bytes = value => new TextEncoder().encode(value);
export const fp4 = value => b64(sodium.crypto_generichash(16, value)).replace(/=+$/, "");
export const signDetached = (message, key) => sodium.crypto_sign_detached(message, key);
export const verifyDetached = (sig, message, key) => sodium.crypto_sign_verify_detached(sig, message, key);
export const validCid = cid => typeof cid === "string" && cid.length === 36 &&
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(cid);

export async function createLocalKeys() {
  const x = sodium.crypto_kx_keypair();
  const kem = new MlKem768();
  const [pqPub, pqPriv] = await kem.generateKeyPair();
  const id = sodium.crypto_sign_keypair();
  return { xPub: x.publicKey, xPriv: x.privateKey, pqPub, pqPriv, kem,
    idPub: id.publicKey, idPriv: id.privateKey };
}

export function wipeKeys(keys) {
  if (!keys) return;
  for (const key of ["xPriv", "pqPriv", "idPriv"]) {
    if (keys[key] instanceof Uint8Array) sodium.memzero(keys[key]);
  }
}

export function wipeBootstrapKeys(keys) {
  if (!keys) return;
  for (const key of ["xPriv", "pqPriv"]) {
    if (keys[key] instanceof Uint8Array) sodium.memzero(keys[key]);
  }
}

export function validPublicKeys(peer) {
  return peer?.xPub instanceof Uint8Array && peer.xPub.length === 32 &&
    peer.pqPub instanceof Uint8Array && peer.pqPub.length === 1184 &&
    peer.idPub instanceof Uint8Array && peer.idPub.length === 32;
}

// Only these fields affect protocol state. Padding and relay timestamps are not trusted.
export function packetBytes(packet, room) {
  return bytes(JSON.stringify(["NullTrace", PROTOCOL_VERSION, room,
    packet.t, packet.cid, packet.to ?? null, packet.v ?? null,
    packet.x ?? null, packet.k ?? null, packet.id ?? null,
    packet.ct ?? null, packet.rp ?? null, packet.rk ?? null,
    packet.e ?? null, packet.rh ?? null,
    packet.n ?? null, packet.ek ?? null, packet.s ?? null,
    packet.ts ?? null, packet.c ?? null]));
}

export function signPacket(packet, room, idPriv) {
  return { ...packet, sig: b64(signDetached(packetBytes(packet, room), idPriv)) };
}

export function verifyPacket(packet, room, idPub) {
  try {
    return packet.v === PROTOCOL_VERSION && validCid(packet.cid) &&
      verifyDetached(u8(packet.sig), packetBytes(packet, room), idPub);
  } catch { return false; }
}

export function createHello(cid, local, room) {
  return signPacket({ t: "hello", v: PROTOCOL_VERSION, cid,
    x: b64(local.xPub), k: b64(local.pqPub), id: b64(local.idPub) }, room, local.idPriv);
}

export function readHello(message, room) {
  try {
    const peer = { xPub: u8(message.x), pqPub: u8(message.k), idPub: u8(message.id) };
    return validPublicKeys(peer) && verifyPacket(message, room, peer.idPub) ? peer : null;
  } catch { return null; }
}

export function makeTranscript(local, peer, role, room, { hostCid, guestCid }) {
  const init = role === "init" ? local : peer;
  const resp = role === "init" ? peer : local;
  return bytes(JSON.stringify(["NullTrace handshake", PROTOCOL_VERSION, SUITE, room, hostCid, guestCid,
    b64(init.idPub), b64(resp.idPub), b64(init.xPub), b64(resp.xPub),
    b64(init.pqPub), b64(resp.pqPub), b64(peer.ct)]));
}

function ratchetContext(local, peer, role, room, { hostCid, guestCid }) {
  const host = role === "init" ? local : peer;
  const guest = role === "init" ? peer : local;
  return bytes(JSON.stringify(["NullTrace pairwise ratchet", PROTOCOL_VERSION, room,
    hostCid, guestCid, b64(host.idPub), b64(guest.idPub)]));
}

function signedHandshake(transcript, initialPublicKey) {
  return bytes(JSON.stringify(["NullTrace authenticated ratchet bootstrap", PROTOCOL_VERSION,
    b64(transcript), b64(initialPublicKey)]));
}

async function deriveSharedKey(sharedX, sharedK, transcript) {
  const ikm = new Uint8Array(64);
  ikm.set(sharedX);
  ikm.set(sharedK, 32);
  try {
    const material = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
    const salt = await crypto.subtle.digest("SHA-256", transcript);
    return new Uint8Array(await crypto.subtle.deriveBits({
      name: "HKDF", hash: "SHA-256", salt,
      info: bytes("NullTrace v3 pairwise ratchet bootstrap")
    }, material, 256));
  } finally { sodium.memzero(ikm); }
}

export async function handshakeWith(peer, local, role, room, participants) {
  if (!validPublicKeys(peer) || !validPublicKeys(local) ||
      !["init", "resp"].includes(role) || !/^[A-Za-z0-9_-]{6,64}$/.test(room) ||
      !validCid(participants?.hostCid) || !validCid(participants?.guestCid) ||
      participants.hostCid === participants.guestCid) {
    throw new Error("Invalid handshake");
  }
  let sharedX, sharedK, sharedKey, ratchet;
  try {
    if (role === "init") {
      [peer.ct, sharedK] = await local.kem.encap(peer.pqPub);
    } else {
      if (!(peer.ct instanceof Uint8Array) || peer.ct.length !== 1088 ||
          !(peer.rp instanceof Uint8Array) || peer.rp.length !== 32 ||
          !(peer.sig instanceof Uint8Array) || peer.sig.length !== 64 ||
          !verifyDetached(peer.sig, signedHandshake(
            makeTranscript(local, peer, role, room, participants), peer.rp), peer.idPub)) {
        throw new Error("Unauthenticated handshake");
      }
      sharedK = await local.kem.decap(peer.ct, local.pqPriv);
    }
    sharedX = sodium.crypto_scalarmult(local.xPriv, peer.xPub);
    const transcript = makeTranscript(local, peer, role, room, participants);
    sharedKey = await deriveSharedKey(sharedX, sharedK, transcript);
    const context = ratchetContext(local, peer, role, room, participants);
    if (role === "init") {
      ratchet = createInitiator(sharedKey, context);
      peer.rp = new Uint8Array(ratchet.initialPublicKey);
      peer.sig = signDetached(signedHandshake(transcript, peer.rp), local.idPriv);
    } else {
      ratchet = createResponder(sharedKey, context, peer.rp);
      peer.sigOK = true;
      // Bootstrap secrets must not survive into the live ratcheted session.
      // Signed public hello fields and the independent identity remain usable.
      wipeBootstrapKeys(local);
    }
    peer.sas = fp4(signedHandshake(transcript, peer.rp));
    return ratchet;
  } catch (error) {
    ratchet?.destroy();
    throw error;
  } finally {
    if (sharedX) sodium.memzero(sharedX);
    if (sharedK) sodium.memzero(sharedK);
    if (sharedKey) sodium.memzero(sharedKey);
  }
}
