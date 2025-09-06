// frontend/static/js/modules/handshake.js (v81)
import sodium from "libsodium-wrappers";
import { MlKem512 } from "mlkem";
await sodium.ready;

// Base64‐variant og hjelpetjenester
export const enc = sodium.base64_variants.ORIGINAL;
export const b64 = u => sodium.to_base64(u, enc);
export const u8  = b => sodium.from_base64(b, enc);
export const fp4 = u => b64(sodium.crypto_generichash(4, u)).replace(/=+$/,"");

// ───────────────────────────────────────────────────────────────
// Nøkkelmateriale

function generateIdKeys(){
  const kp = sodium.crypto_sign_keypair();
  return { idPub: kp.publicKey, idPriv: kp.privateKey };
}

export async function createLocalKeys(){
  const { publicKey, privateKey } = sodium.crypto_kx_keypair(); // X25519
  const kem = new MlKem512();                                    // PQ KEM
  const [pqPub, pqPriv] = await kem.generateKeyPair();
  const { idPub, idPriv } = generateIdKeys();                    // Ed25519
  return { xPub: publicKey, xPriv: privateKey, pqPub, pqPriv, kem, idPub, idPriv };
}

// ───────────────────────────────────────────────────────────────
// Signatur-helpers

export function signDetached(msg, priv){
  return sodium.crypto_sign_detached(msg, priv);
}

export function verifyDetached(sig, msg, pub){
  return sodium.crypto_sign_verify_detached(sig, msg, pub);
}

// ───────────────────────────────────────────────────────────────
// HKDF-BLAKE2b helpers

function hkdfExtract(salt, ikm){
  return sodium.crypto_generichash(32, ikm, salt);
}

function hkdfExpand(prk, info, len = 32){
  const info1 = new Uint8Array(info.length + 1);
  info1.set(info, 0);
  info1[info1.length - 1] = 0x01;
  return sodium.crypto_generichash(len, info1, prk);
}

function toU8(s){ return new TextEncoder().encode(s); }
function concatU8(...arrs){
  let n = 0; for(const a of arrs) n += a.length;
  const out = new Uint8Array(n);
  let o = 0; for(const a of arrs){ out.set(a, o); o += a.length; }
  return out;
}

// ───────────────────────────────────────────────────────────────
// Transkript (kanonisk INIT→RESP uansett hvem som kaller)

function buildTranscript(local, peer, role, room = "nt"){
  const init = role === "init" ? local : peer;
  const resp = role === "init" ? peer  : local;
  const parts = [
    "NT-v1|handshake|",
    room, "|",
    "init.id=",  b64(init.idPub),  "|",
    "resp.id=",  b64(resp.idPub),  "|",
    "init.x=",   b64(init.xPub),   "|",
    "resp.x=",   b64(resp.xPub),   "|",
    "init.pq=",  b64(init.pqPub),  "|",
    "resp.pq=",  b64(resp.pqPub)
  ];
  return toU8(parts.join(""));
}

/**
 * Symmetrisk (rolle-uavhengig) avledning av delt nøkkel for å pakke ut/in 'gk'.
 * Vi blender inn ECDH+KEM i saltet, bruker transkriptet som IKM, og 'room' som info.
 */
function deriveSharedKey(sharedX, sharedK, transcript, room){
  const salt = sodium.crypto_generichash(32, concatU8(sharedX, sharedK));
  const prk  = hkdfExtract(salt, transcript);
  const info = toU8(`NullTrace v1 handshake|room=${room || "nt"}`);
  return hkdfExpand(prk, info, 32);
}

// ───────────────────────────────────────────────────────────────
// Hybrid handshake (X25519 + Kyber512) + signert transkript

export async function handshakeWith(peer, local, role, room = "nt"){
  // 1) Klassisk ECDH
  const sharedX = sodium.crypto_scalarmult(local.xPriv, peer.xPub);

  // 2) PQ-KEM
  let sharedK, ct = null;
  if (role === "init"){
    [ct, sharedK] = await local.kem.encap(peer.pqPub);
    peer.ct = ct;
  } else {
    if (!peer.ct) throw new Error("Missing peer.ct for resp handshake");
    sharedK = await local.kem.decap(peer.ct, local.pqPriv);
  }

  // 3) Transkript (kanonisk INIT→RESP)
  const transcript = buildTranscript(local, peer, role, room);

  // 4) Signatur (INIT signerer; RESP verifiserer om sig finnes)
  if (role === "init"){
    const sig = signDetached(transcript, local.idPriv);
    peer.sig = sig;
  } else if (peer.sig) {
    try{
      const ok = verifyDetached(peer.sig, transcript, peer.idPub);
      peer.sigOK = !!ok;
    }catch{ peer.sigOK = false; }
  }

  // 5) SAS (kort fingerprint)
  peer.sas = fp4(transcript);

  // 6) Symmetrisk delt nøkkel (rolle-uavhengig!)
  const sk = deriveSharedKey(sharedX, sharedK, transcript, room);
  return sk;
}

export const makeTranscript = buildTranscript;
