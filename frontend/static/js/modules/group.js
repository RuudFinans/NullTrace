import sodium from "libsodium-wrappers";
import { b64, u8, bytes, PROTOCOL_VERSION, signPacket, verifyPacket, validCid } from "./handshake.js";
await sodium.ready;

export const MAX_SKIPPED_MESSAGES = 64;
export const MESSAGE_KEY_TTL_MS = 35000;
const MESSAGE_LABEL = bytes("NullTrace v3 sender message key");
const CHAIN_LABEL = bytes("NullTrace v3 next sender chain");

// libsodium crypto_auth is HMAC-SHA512 with a 256-bit output. Independent
// domain labels derive the message key and the next one-way chain key.
function step(key) {
  return { message: sodium.crypto_auth(MESSAGE_LABEL, key), next: sodium.crypto_auth(CHAIN_LABEL, key) };
}

function wipeChain(chain) {
  if (!chain) return;
  sodium.memzero(chain.key);
  for (const entry of chain.skipped.values()) sodium.memzero(entry.key);
  chain.skipped.clear();
}

// Host-managed groups, not RFC 9420 MLS. Epoch seeds are expanded once and
// erased; only advancing sender chains remain. A lagging member's state can
// still derive messages it has not processed, until it installs a new epoch.
export class Group {
  constructor(cid, sendFn, readyCb, { room, idPriv, idPub, hostCid } = {}) {
    if (!validCid(cid) || !room || !idPriv || !idPub) throw new Error("Missing group identity");
    Object.assign(this, { cid, room, idPriv, idPub, hostCid, send: sendFn, onReady: readyCb });
    this.peers = new Map();
    this.identities = new Map([[cid, idPub]]);
    this._sendChain = null;
    this.recvChains = new Map();
    this.epoch = 0;
    this.sendSeq = 0;
    this.pending = [];
    this.destroyed = false;
    this._pruneTimer = setInterval(() => this._pruneSkipped(), 1000);
    this._pruneTimer.unref?.();
  }

  get ready() { return !this.destroyed && this._sendChain !== null; }

  _aad(message) {
    return bytes(JSON.stringify(["NullTrace message", PROTOCOL_VERSION, this.room,
      message.cid, message.e, message.s, message.ts]));
  }

  addPeer(cid, ratchet, idPub) {
    if (this.destroyed || !validCid(cid) || cid === this.cid || idPub?.length !== 32 ||
        typeof ratchet?.encrypt !== "function" || typeof ratchet?.decrypt !== "function" ||
        typeof ratchet?.destroy !== "function") throw new Error("Invalid member");
    const pinned = this.identities.get(cid);
    if (pinned && !sodium.memcmp(pinned, idPub)) throw new Error("Member identity changed");
    if (this.peers.size >= 15 && !this.peers.has(cid)) throw new Error("Room is full");
    const previous = this.peers.get(cid);
    if (previous && previous !== ratchet) previous.destroy();
    this.peers.set(cid, ratchet);
    this.identities.set(cid, idPub);
  }

  _installKey(seed, epoch, identities, notify = true) {
    let sending = null;
    const receiving = new Map();
    try {
      if (this.destroyed || seed?.length !== 32 || !Number.isSafeInteger(epoch) || epoch <= this.epoch ||
          !identities.has(this.cid)) throw new Error("Invalid epoch");
      for (const [cid, identity] of identities) {
        const key = sodium.crypto_generichash(32, bytes(JSON.stringify([
          "NullTrace v3 sender chain seed", this.room, epoch, cid, b64(identity)
        ])), seed);
        // Never keep an own receive chain: its old key would undo send-side erasure.
        if (cid === this.cid) sending = key;
        else receiving.set(cid, { key, next: 0, skipped: new Map() });
      }
      if (this._sendChain) sodium.memzero(this._sendChain);
      for (const chain of this.recvChains.values()) wipeChain(chain);
      this._sendChain = sending;
      this.recvChains = receiving;
      this.identities = identities;
      this.epoch = epoch;
      this.sendSeq = 0;
    } catch (error) {
      if (sending) sodium.memzero(sending);
      for (const chain of receiving.values()) wipeChain(chain);
      throw error;
    } finally {
      if (seed instanceof Uint8Array) sodium.memzero(seed);
    }
    if (notify) this.onReady?.();
  }

  _pruneSkipped() {
    const now = Date.now();
    for (const chain of this.recvChains.values()) {
      for (const [index, entry] of chain.skipped) {
        if (entry.expires <= now) {
          sodium.memzero(entry.key);
          chain.skipped.delete(index);
        }
      }
    }
  }

  encrypt(text) {
    if (!this.ready) return null;
    const plain = bytes(text);
    let messageKey;
    try {
      if (plain.length > 8192) throw new Error("Message exceeds 8192 UTF-8 bytes");
      if (!Number.isSafeInteger(this.sendSeq) || this.sendSeq >= Number.MAX_SAFE_INTEGER) {
        throw new Error("Sequence exhausted");
      }
      const packet = { t: "m", v: PROTOCOL_VERSION, cid: this.cid,
        s: this.sendSeq, e: this.epoch, ts: Date.now() };
      const derived = step(this._sendChain);
      messageKey = derived.message;
      sodium.memzero(this._sendChain);
      this._sendChain = derived.next;
      this.sendSeq++; // Burn the key even if encryption, signing or transport later fails.
      const nonce = sodium.randombytes_buf(24);
      packet.n = b64(nonce);
      packet.c = b64(sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plain, this._aad(packet), null, nonce, messageKey));
      return signPacket(packet, this.room, this.idPriv);
    } finally {
      if (messageKey) sodium.memzero(messageKey);
      sodium.memzero(plain);
    }
  }

  decrypt(message) {
    if (this.destroyed || !message || message.t !== "m" || message.v !== PROTOCOL_VERSION ||
        !validCid(message.cid) || message.cid === this.cid ||
        !Number.isSafeInteger(message.s) || message.s < 0 ||
        !Number.isSafeInteger(message.e) || message.e <= 0 ||
        !Number.isSafeInteger(message.ts) || message.ts > Date.now() + 10000 ||
        Date.now() - message.ts > MESSAGE_KEY_TTL_MS ||
        typeof message.c !== "string" || message.c.length > 11000) return null;
    if (!this.ready || message.e > this.epoch) {
      if (this.pending.length < 32) this.pending.push(message);
      return null;
    }
    const identity = this.identities.get(message.cid);
    const current = this.recvChains.get(message.cid);
    if (message.e !== this.epoch || !identity || !current ||
        !verifyPacket(message, this.room, identity)) return null;
    this._pruneSkipped();
    let candidate, messageKey, plain;
    try {
      const nonce = u8(message.n);
      if (nonce.length !== 24) return null;
      const cached = current.skipped.get(message.s);
      if (message.s < current.next) {
        if (!cached) return null;
        plain = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
          null, u8(message.c), this._aad(message), nonce, cached.key);
        const text = sodium.to_string(plain);
        sodium.memzero(cached.key);
        current.skipped.delete(message.s);
        return text;
      }
      const gap = message.s - current.next;
      if (gap > MAX_SKIPPED_MESSAGES || current.skipped.size + gap > MAX_SKIPPED_MESSAGES) return null;
      candidate = { key: new Uint8Array(current.key), next: current.next,
        skipped: new Map([...current.skipped].map(([index, entry]) => [index,
          { key: new Uint8Array(entry.key), expires: entry.expires }])) };
      while (candidate.next <= message.s) {
        const derived = step(candidate.key);
        sodium.memzero(candidate.key);
        candidate.key = derived.next;
        const index = candidate.next++;
        if (index === message.s) messageKey = derived.message;
        else candidate.skipped.set(index, { key: derived.message, expires: Date.now() + MESSAGE_KEY_TTL_MS });
      }
      plain = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null, u8(message.c), this._aad(message), nonce, messageKey);
      const text = sodium.to_string(plain);
      // Authenticated plaintext only: malformed packets cannot consume chain state.
      wipeChain(current);
      this.recvChains.set(message.cid, candidate);
      candidate = null;
      return text;
    } catch { return null; }
    finally {
      if (candidate) wipeChain(candidate);
      if (messageKey) sodium.memzero(messageKey);
      if (plain) sodium.memzero(plain);
    }
  }

  flush(callback) {
    if (!this.ready) return;
    const pending = this.pending;
    this.pending = [];
    for (const message of pending) {
      const text = this.decrypt(message);
      if (text !== null) callback(text);
    }
  }

  destroy() {
    clearInterval(this._pruneTimer);
    clearTimeout(this._rekeyTimer);
    if (this._sendChain) sodium.memzero(this._sendChain);
    for (const chain of this.recvChains.values()) wipeChain(chain);
    for (const ratchet of this.peers.values()) ratchet.destroy();
    this._sendChain = null;
    this.recvChains.clear();
    this.peers.clear();
    this.identities.clear();
    this.pending = [];
    this.destroyed = true;
  }
}
