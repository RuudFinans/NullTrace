// Historical import name. This is a host-managed ratcheted group, not RFC 9420 MLS.
import sodium from "libsodium-wrappers";
import { b64, u8, bytes, PROTOCOL_VERSION, signPacket, verifyPacket, validCid } from "./handshake.js";
import { Group } from "./group.js";
await sodium.ready;

export class MlsGroup extends Group {
  constructor(cid, sendFn, readyCb, isInitiator, options) {
    super(cid, sendFn, readyCb, options);
    this.isInitiator = !!isInitiator;
    if (options.hostId) this.identities.set(options.hostCid, options.hostId);
    this.rosterHash = "";
    this._latestEnvelopes = new Map();
    this._lastRequests = new Map();
    this._lastRekeyAt = 0;
  }

  _aadGK(message) {
    return bytes(JSON.stringify(["NullTrace v3 ratchet control", this.room,
      message.t, message.v, message.cid, message.to, message.e, message.rh]));
  }

  _roster() {
    return [...this.identities].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
      .map(([cid, id]) => ({ cid, id: b64(id) }));
  }

  _rosterHash(roster) {
    return b64(sodium.crypto_generichash(32, bytes(JSON.stringify(roster))));
  }

  _sendPacket(packet) {
    if (this.destroyed || this.send(packet) === false) throw new Error("Ratchet transport closed");
  }

  addMember(cid, ratchet, idPub) {
    this.addPeer(cid, ratchet, idPub);
    if (this.isInitiator) this.rekey();
  }

  removeMember(cid) {
    this.peers.get(cid)?.destroy();
    this.peers.delete(cid);
    this.identities.delete(cid);
    this._latestEnvelopes.delete(cid);
    this._lastRequests.delete(cid);
    if (this.isInitiator) this.rekey();
  }

  rekey() {
    if (!this.isInitiator || this.destroyed) return false;
    if (!Number.isSafeInteger(this.epoch + 1)) throw new Error("Epoch exhausted");
    const seed = sodium.randombytes_buf(32);
    const epoch = this.epoch + 1;
    const roster = this._roster();
    const rh = this._rosterHash(roster);
    const rosterBytes = bytes(JSON.stringify(roster));
    // The secret is never base64/JSON encoded: immutable JS strings cannot be wiped.
    const payload = new Uint8Array(32 + rosterBytes.length);
    payload.set(seed);
    payload.set(rosterBytes, 32);
    const packets = [];
    try {
      for (const [to, ratchet] of this.peers) {
        const message = { t: "gk", v: PROTOCOL_VERSION, cid: this.cid, to, e: epoch, rh };
        message.rk = ratchet.encrypt(payload, this._aadGK(message));
        packets.push(signPacket(message, this.room, this.idPriv));
      }
      // Install without firing callbacks: they must not send before the envelopes.
      this._installKey(seed, epoch, new Map(this.identities), false);
      this.rosterHash = rh;
      this._lastRekeyAt = Date.now();
      for (const packet of packets) {
        this._latestEnvelopes.set(packet.to, packet); // Ciphertext only; never retain the epoch seed.
        this._sendPacket(packet);
      }
      this.onReady?.();
      return true;
    } catch (error) {
      // A partially sent epoch cannot safely continue; never roll ratchets back.
      this.destroy();
      throw error;
    } finally {
      sodium.memzero(seed);
      sodium.memzero(payload);
    }
  }

  _control(type) {
    return { t: type, v: PROTOCOL_VERSION, cid: this.cid, to: this.hostCid,
      e: this.epoch, rh: this.rosterHash };
  }

  _sendControl(type) {
    const ratchet = this.peers.get(this.hostCid);
    if (this.isInitiator || !ratchet || this.destroyed) return false;
    const message = this._control(type);
    const payload = bytes(JSON.stringify([type, message.e, message.rh]));
    try {
      message.rk = ratchet.encrypt(payload, this._aadGK(message));
      this._sendPacket(signPacket(message, this.room, this.idPriv));
      return true;
    } catch (error) {
      this.destroy();
      throw error;
    } finally { sodium.memzero(payload); }
  }

  requestKey() {
    if (this.isInitiator || this.destroyed || !this.peers.has(this.hostCid)) return false;
    if (this.ready) return this._sendControl("gk_req");
    // Before its first authenticated epoch, a responder has no sending chain.
    // A signed bootstrap request can only cause ciphertext retransmission.
    this._sendPacket(signPacket(this._control("gk_req"), this.room, this.idPriv));
    return true;
  }

  handleControl(message) {
    if (!this.isInitiator || this.destroyed || !["gk_ack", "gk_req"].includes(message?.t) ||
        message.to !== this.cid || !this.peers.has(message.cid) ||
        !Number.isSafeInteger(message.e) || message.e < 0 || message.e > this.epoch ||
        typeof message.rh !== "string" || message.rh.length > 44 ||
        !verifyPacket(message, this.room, this.identities.get(message.cid))) return false;
    if (message.t === "gk_req" && message.e === 0 && message.rh === "" && message.rk === undefined) {
      return this._resend(message.cid);
    }
    if (message.e === 0 || typeof message.rk !== "string" || message.rk.length > 14000) return false;
    const plain = this.peers.get(message.cid).decrypt(message.rk, this._aadGK(message));
    if (!plain) return false;
    try {
      if (sodium.to_string(plain) !== JSON.stringify([message.t, message.e, message.rh])) return false;
      if (message.t === "gk_req") {
        if (Date.now() - this._lastRekeyAt >= 800) this.rekey();
        else this._resend(message.cid);
      }
      // ACKs advance the pairwise DH ratchet; they do not recursively rekey.
      return true;
    } finally { sodium.memzero(plain); }
  }

  _resend(cid) {
    const packet = this._latestEnvelopes.get(cid);
    const now = Date.now();
    if (!packet || now - (this._lastRequests.get(cid) ?? -Infinity) < 800) return false;
    this._lastRequests.set(cid, now);
    this._sendPacket(packet);
    return true;
  }

  loadGK(message) {
    if (this.isInitiator || this.destroyed || message?.to !== this.cid || message.cid !== this.hostCid ||
        !Number.isSafeInteger(message.e) || message.e <= this.epoch || message.e <= 0 ||
        typeof message.rh !== "string" || message.rh.length !== 44 ||
        typeof message.rk !== "string" || message.rk.length > 14000 ||
        !verifyPacket(message, this.room, this.identities.get(this.hostCid))) return false;
    const ratchet = this.peers.get(this.hostCid);
    if (!ratchet) return false;
    const plain = ratchet.decrypt(message.rk, this._aadGK(message));
    if (!plain) return false;
    let seed;
    try {
      if (plain.length <= 32 || plain.length > 8192) return false;
      const roster = JSON.parse(sodium.to_string(plain.subarray(32)));
      if (!Array.isArray(roster) || roster.length < 2 || roster.length > 16 ||
          message.rh !== this._rosterHash(roster)) return false;
      const identities = new Map();
      for (const entry of roster) {
        if (!validCid(entry?.cid) || identities.has(entry.cid)) return false;
        const identity = u8(entry.id);
        if (identity.length !== 32) return false;
        const known = this.identities.get(entry.cid);
        if (known && !sodium.memcmp(known, identity)) return false;
        identities.set(entry.cid, identity);
      }
      if (!identities.has(this.cid) || !identities.has(this.hostCid)) return false;
      seed = plain.slice(0, 32);
      this._installKey(seed, message.e, identities, false);
      this.rosterHash = message.rh;
    } catch { return false; }
    finally {
      sodium.memzero(plain);
      if (seed) sodium.memzero(seed);
    }
    this._sendControl("gk_ack");
    this.onReady?.();
    return true;
  }

  destroy() {
    super.destroy();
    this._latestEnvelopes.clear();
    this._lastRequests.clear();
    this.rosterHash = "";
  }
}
