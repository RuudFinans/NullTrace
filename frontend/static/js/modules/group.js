// frontend/static/js/modules/group.js
import sodium from "libsodium-wrappers";
import { b64, u8 } from "./handshake.js";
await sodium.ready;

/**
 * Sikker gruppe-kryptering m/ per-avsender sekvens, epoch og AAD.
 * - Én felles groupKey som distribueres (kryptert per-peer) via 'gk'
 * - Per-avsender deterministisk nonce: H("NT|nonce|cid|seq|epoch")[:24]
 * - AAD binder {t,cid,s,epoch} for antireplay/integritet
 */
export class Group {
  constructor(cid, sendFn, readyCb){
    this.cid      = cid;       // egen ID
    this.send     = sendFn;    // funksjon å sende WS-objekter med
    this.onReady  = readyCb;   // callback når (ny) key er klar
    this.peers    = new Map(); // peerCid -> sharedSymKey (fra handshake, brukes for gk)
    this.groupKey = null;      // felles symmetrisk key for meldinger
    this.epoch    = 0;         // økes ved rekey
    this.pending  = [];        // buffer for meldinger før key

    // per-avsender status
    this.sendSeq  = 0;                 // vår sekvens
    this.recvSeq  = new Map();         // peerCid -> siste aksepterte seq
  }

  // ───────────── helpers ─────────────
  _u8(s){ return new TextEncoder().encode(s); }
  _concat(...arrs){
    let len = 0; for(const a of arrs) len += a.length;
    const out = new Uint8Array(len);
    let off = 0; for(const a of arrs){ out.set(a, off); off += a.length; }
    return out;
  }
  _nonce(cid, seq, epoch){
    // 24-byte XChaCha nonce derivert deterministisk
    const tag = this._u8("NT-v1|nonce|");
    const body = this._u8(`${cid}|${seq}|${epoch}`);
    const h = sodium.crypto_generichash(24, this._concat(tag, body));
    return h; // 24 bytes
  }
  _senderKey(){
    // Vi bruker groupKey direkte; vil du separere per-avsender nøkler:
    // return sodium.crypto_generichash(32, this._concat(this._u8("NT-v1|sender|"), this._u8(this.cid), this.groupKey));
    return this.groupKey;
  }
  _aad(obj){
    // AAD må bygges identisk i encrypt/decrypt
    // Behold felt-rekkefølge: t, cid, s, e
    const s = JSON.stringify({ t: obj.t, cid: obj.cid, s: obj.s, e: obj.e });
    return this._u8(s);
  }

  // ───────────── medlems-/nøkkelstyring ─────────────
  addPeer(cid, sk){
    this.peers.set(cid, sk);
  }

  /**
   * Initiator: etabler/rotér groupKey og distribuer til alle peers
   */
  rekey(){
    this.groupKey = sodium.randombytes_buf(32);
    this.epoch = (this.epoch | 0) + 1;
    this.sendSeq = 0;
    this.recvSeq.clear();

    // gjør UI klart umiddelbart – meldinger vil ha e=this.epoch
    this.onReady?.();

    // Krypter og send ny groupKey per peer via deres handshake-baserte 'sk'
    for(const [peerCid, sk] of this.peers){
      const aad = this._aad({ t:"gk", cid:this.cid, s:0, e:this.epoch });
      const nonce = sodium.randombytes_buf(
        sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
      );
      // VIKTIG: riktig parameterrekkefølge – AAD er *andre* argument
      const ek = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        this.groupKey,         // message (plaintext)
        aad,                   // additional data  ✅
        null,                  // secret data      ✅ alltid null
        nonce,
        sk
      );
      this.send({
        t:   "gk",
        cid: this.cid,
        to:  peerCid,
        e:   this.epoch,
        n:   b64(nonce),
        ek:  b64(ek)
      });
    }
  }

  /**
   * Responder: last inn groupKey ved mottatt 'gk' (med AAD-verifisering)
   */
  loadGK(msg, mySk){
    if(msg.to && msg.to !== this.cid) return;

    try{
      const aad = this._aad({ t:"gk", cid: msg.cid, s:0, e: msg.e|0 });
      const gk = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        u8(msg.ek),
        aad,                 // samme AAD som over
        u8(msg.n),
        mySk
      );
      this.groupKey = gk;
      this.epoch    = msg.e|0;
      this.sendSeq  = 0;
      this.recvSeq.clear();
      this.onReady?.();
      // prosesser evt. buffrede meldinger for denne epoch
      this.flush(()=>{});
    }catch{
      // Ignorer korrupt/feil 'gk'
    }
  }

  // ───────────── meldingskryptering ─────────────
  encrypt(txt){
    if(!this.groupKey) return null;

    const s = this.sendSeq;
    const e = this.epoch;
    const nonce = this._nonce(this.cid, s, e);
    const aad = this._aad({ t:"m", cid:this.cid, s, e });

    const cipher = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      sodium.from_string(txt),
      aad,                   // ✅ AAD på riktig plass
      null,                  // ✅ secret data = null
      nonce,
      this._senderKey()
    );

    this.sendSeq = s + 1;

    return {
      t:   "m",
      cid: this.cid,
      s,          // sequence
      e,          // epoch
      n:   b64(nonce),
      c:   b64(cipher)
    };
  }

  decrypt(msg){
    if(!this.groupKey){
      this.pending.push(msg);
      return null;
    }

    // feil epoch? dropp rolig
    if((msg.e|0) !== (this.epoch|0)){
      return null;
    }

    // antireplay per avsender
    const last = this.recvSeq.get(msg.cid) ?? -1;
    if((msg.s|0) <= last){
      return null;
    }

    try{
      const nonce = this._nonce(msg.cid, msg.s|0, msg.e|0);
      const aad   = this._aad({ t:"m", cid: msg.cid, s: msg.s|0, e: msg.e|0 });
      const pt = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        u8(msg.c),
        aad,               // samme AAD som i encrypt
        u8(msg.n),
        this.groupKey
      );
      this.recvSeq.set(msg.cid, msg.s|0);
      return sodium.to_string(pt);
    }catch{
      // korrupt eller ikke-dekrypterbar – dropp
      return null;
    }
  }

  /**
   * Prøv å vise buffrede meldinger når key/epoch er klar.
   * (Vi forsøker alle; de som ikke passer nåværende epoch ignoreres.)
   */
  flush(cb){
    if(!this.groupKey) return;
    const rest = [];
    while(this.pending.length){
      const m = this.pending.shift();
      const txt = this.decrypt(m);
      if(txt !== null){
        cb(txt);
      }else{
        // behold fremtidige/feil-epoch i rest (begrens minne)
        if((m.e|0) > (this.epoch|0)) rest.push(m);
      }
    }
    if(rest.length) this.pending.unshift(...rest);
  }
}
