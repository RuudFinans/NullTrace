// frontend/static/js/modules/mls.js – v3 (AAD fix + robust rekey)
import sodium from "libsodium-wrappers";
import { b64, u8 } from "./handshake.js";
import { Group } from "./group.js";
await sodium.ready;

/**
 * MlsGroup – gruppestyring med automatisk (debouncet) rekey hos initiator.
 * Inkluderer roster-hash (rh) i GK-pakker og i AAD for konsistenssjekk.
 */
export class MlsGroup extends Group {
  /**
   * @param {string} cid
   * @param {(obj:any)=>void} sendFn
   * @param {()=>void} readyCb
   * @param {boolean} isInitiator
   */
  constructor(cid, sendFn, readyCb, isInitiator) {
    super(cid, sendFn, readyCb);
    this.isInitiator = !!isInitiator;
    this._rekeyTimer = null;
    this._rekeyDelayMs = 50; // koalescer flere joins/leaves
  }

  // ───────────── helpers ─────────────
  _u8(s){ return new TextEncoder().encode(s); }

  _aadGK(senderCid, epoch, rh){
    // AAD for gk: inkluder roster-hash når den finnes
    // (t, cid, s=0, e, rh?) – hold rekkefølgen stabil.
    const base = { t:"gk", cid: senderCid, s:0, e: epoch };
    if (rh) base.rh = rh;
    return this._u8(JSON.stringify(base));
  }

  _rosterCids(){
    // inkluder oss selv + alle peers (sortert for determinisme)
    const set = new Set([this.cid, ...this.peers.keys()]);
    return Array.from(set).sort();
  }

  _rosterHash(){
    // 16B hash holder som indikator, b64 for wire
    const data = this._u8(JSON.stringify(this._rosterCids()));
    const h = sodium.crypto_generichash(16, data);
    return b64(h);
  }

  _scheduleRekey(){
    if (!this.isInitiator) return;
    clearTimeout(this._rekeyTimer);
    this._rekeyTimer = setTimeout(() => this.rekey(), this._rekeyDelayMs);
  }

  // ───────────── medlemsendringer ─────────────
  addMember(peerCid, sharedKey) {
    this.peers.set(peerCid, sharedKey);
    this._scheduleRekey();
  }

  removeMember(peerCid){
    this.peers.delete(peerCid);
    this._scheduleRekey();
  }

  setInitiator(flag){
    this.isInitiator = !!flag;
  }

  // ───────────── nøkkelrotasjon ─────────────
  /**
   * Rekey med roster-hash i AAD. Overstyrer Group.rekey()
   */
  rekey(){
    if (!this.isInitiator) return;

    this.groupKey = sodium.randombytes_buf(32);
    this.epoch = (this.epoch | 0) + 1;
    this.sendSeq = 0;
    this.recvSeq.clear();

    const rh = this._rosterHash();
    this.onReady?.();

    for (const [peerCid, sk] of this.peers){
      const aad = this._aadGK(this.cid, this.epoch, rh);
      const nonce = sodium.randombytes_buf(
        sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
      );

      // ⭐ FIX: riktig parameterrekkefølge – AAD er 2. argument
      const ek = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        this.groupKey,   // plaintext
        aad,             // AAD   ✅
        null,            // nsec  ✅
        nonce,
        sk
      );

      this.send({
        t:   "gk",
        cid: this.cid,
        to:  peerCid,
        e:   this.epoch,
        rh,                 // roster hash for konsistens
        n:   b64(nonce),
        ek:  b64(ek)
      });
    }
  }

  /**
   * Last inn ny groupKey. Overstyrer Group.loadGK for å støtte rh i AAD
   * med bakoverkompatibel fallback.
   */
  loadGK(msg, mySk) {
    if (msg.to && msg.to !== this.cid) return;

    // avvis ikke-fremdrift
    const me = this.epoch | 0;
    const theirE = msg.e | 0;
    if (theirE <= me) return;

    const tryDecrypt = (useRh) => {
      const aad = useRh
        ? this._aadGK(msg.cid, theirE, msg.rh)
        : this._aadGK(msg.cid, theirE, undefined);
      return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,         // nsec
        u8(msg.ek),   // ciphertext
        aad,          // AAD
        u8(msg.n),    // nonce
        mySk
      );
    };

    let gk = null;
    try {
      if (typeof msg.rh === "string") {
        gk = tryDecrypt(true);
      } else {
        gk = tryDecrypt(false);
      }
    } catch {
      if (typeof msg.rh === "string") {
        try { gk = tryDecrypt(false); } catch { /* ignore */ }
      }
    }

    if (!gk) return; // kunne ikke dekryptere

    this.groupKey = gk;
    this.epoch    = theirE;
    this.sendSeq  = 0;
    this.recvSeq.clear();
    this.onReady?.();

    // Forsøk å vise buffrede meldinger for denne epoch
    this.flush(()=>{});
  }
}
