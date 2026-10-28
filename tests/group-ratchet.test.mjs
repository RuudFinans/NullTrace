import test, { afterEach } from "node:test";
import assert from "node:assert/strict";
import { createHmac, randomUUID } from "node:crypto";
import sodium from "libsodium-wrappers";
import {
  b64, u8, bytes, createLocalKeys, handshakeWith, signPacket, wipeKeys
} from "../frontend/static/js/modules/handshake.js";
import { MAX_SKIPPED_MESSAGES, MESSAGE_KEY_TTL_MS } from "../frontend/static/js/modules/group.js";
import { MlsGroup } from "../frontend/static/js/modules/mls.js";
await sodium.ready;

const liveGroups = new Set();
const liveKeys = new Set();
afterEach(() => {
  for (const group of liveGroups) group.destroy();
  for (const keys of liveKeys) wipeKeys(keys);
  liveGroups.clear();
  liveKeys.clear();
});

const publicKeys = keys => ({ xPub: keys.xPub, pqPub: keys.pqPub, idPub: keys.idPub });
const isZero = value => value.every(byte => byte === 0);
const flip = encoded => {
  const changed = u8(encoded);
  changed[changed.length - 1] ^= 1;
  return b64(changed);
};
const hmac = (key, label) => new Uint8Array(
  createHmac("sha512", key).update(label, "utf8").digest().subarray(0, 32)
);

async function network(size = 2, { deliver = true } = {}) {
  const room = randomUUID(), keys = [], cids = [], groups = [], wire = [];
  for (let i = 0; i < size; i++) {
    const identity = await createLocalKeys();
    liveKeys.add(identity);
    keys.push(identity);
    cids.push(randomUUID());
  }
  for (let i = 0; i < size; i++) {
    const group = new MlsGroup(cids[i], packet => { wire.push(packet); return true; },
      () => {}, i === 0, { room, idPriv: keys[i].idPriv, idPub: keys[i].idPub,
        hostCid: cids[0], hostId: keys[0].idPub });
    liveGroups.add(group);
    groups.push(group);
  }
  function take(type, recipient) {
    const index = wire.findIndex(packet => packet.t === type &&
      (recipient === undefined || packet.to === recipient));
    assert.notEqual(index, -1, `Missing ${type} packet`);
    return wire.splice(index, 1)[0];
  }
  function drain() {
    let count = 0;
    while (wire.length) {
      assert.ok(++count < 100, "Control messages must not recursively rekey");
      const packet = wire.shift(), recipient = groups[cids.indexOf(packet.to)];
      assert.ok(recipient, "Packet has a known recipient");
      assert.equal(packet.t === "gk" ? recipient.loadGK(packet) : recipient.handleControl(packet), true);
    }
  }
  for (let i = 1; i < size; i++) {
    const peer = publicKeys(keys[i]), participants = { hostCid: cids[0], guestCid: cids[i] };
    const hostRatchet = await handshakeWith(peer, keys[0], "init", room, participants);
    const guestRatchet = await handshakeWith({ ...publicKeys(keys[0]), ct: peer.ct,
      rp: peer.rp, sig: peer.sig }, keys[i], "resp", room, participants);
    groups[i].addMember(cids[0], guestRatchet, keys[0].idPub);
    groups[0].addMember(cids[i], hostRatchet, keys[i].idPub);
    if (deliver) drain();
  }
  return { room, keys, cids, groups, wire, take, drain };
}

function openMessage(group, packet, key) {
  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null, u8(packet.c), group._aad(packet), u8(packet.n), key
  );
}

function snapshot(chain) {
  return { key: [...chain.key], next: chain.next,
    skipped: [...chain.skipped].map(([index, entry]) =>
      [index, [...entry.key], entry.expires]) };
}

test("sender-chain derivation matches independent truncated HMAC-SHA512", async () => {
  const { groups: [host, guest] } = await network();
  const before = host._sendChain.slice();
  const messageKey = hmac(before, "NullTrace v3 sender message key");
  const nextKey = hmac(before, "NullTrace v3 next sender chain");
  let plaintext;
  try {
    assert.deepEqual(messageKey, sodium.crypto_auth(bytes("NullTrace v3 sender message key"), before));
    assert.deepEqual(nextKey, sodium.crypto_auth(bytes("NullTrace v3 next sender chain"), before));
    const packet = host.encrypt("independent KDF check");
    assert.deepEqual(host._sendChain, nextKey);
    plaintext = openMessage(host, packet, messageKey);
    assert.equal(sodium.to_string(plaintext), "independent KDF check");
    assert.equal(guest.decrypt(packet), "independent KDF check");
  } finally {
    for (const secret of [before, messageKey, nextKey, plaintext]) if (secret) sodium.memzero(secret);
  }
});

test("epoch installation wipes seeds and old chains without retaining an own receive chain", async () => {
  const { groups, cids, drain } = await network(3);
  const seeds = [], payloads = [], oldKeys = [];
  const skippedPacket = groups[0].encrypt("skipped before rekey");
  const receivedPacket = groups[0].encrypt("received before rekey");
  for (const guest of groups.slice(1)) assert.equal(guest.decrypt(receivedPacket), "received before rekey");
  for (const ratchet of groups[0].peers.values()) {
    const encrypt = ratchet.encrypt;
    ratchet.encrypt = function(payload, aad) {
      payloads.push(payload);
      return encrypt.call(this, payload, aad);
    };
  }
  for (const group of groups) {
    oldKeys.push(group._sendChain);
    for (const chain of group.recvChains.values()) {
      oldKeys.push(chain.key, ...[...chain.skipped.values()].map(entry => entry.key));
    }
    const install = group._installKey;
    group._installKey = function(seed, ...args) {
      seeds.push(seed);
      return install.call(this, seed, ...args);
    };
  }
  groups[0].rekey();
  drain();
  assert.equal(seeds.length, 3);
  assert.ok(seeds.every(seed => seed.length === 32 && isZero(seed)));
  assert.equal(payloads.length, 2);
  assert.ok(payloads.every(payload => payload.length > 32 && isZero(payload)));
  assert.ok(oldKeys.every(isZero));
  for (const guest of groups.slice(1)) assert.equal(guest.decrypt(skippedPacket), null);
  for (let i = 0; i < groups.length; i++) {
    assert.equal("groupKey" in groups[i], false);
    assert.equal(groups[i].recvChains.has(cids[i]), false);
    assert.equal(groups[i].recvChains.size, groups.length - 1);
    assert.equal(groups[i].epoch, groups[0].epoch);
  }
});

test("consumed message keys are erased and next keys cannot open consumed ciphertext", async t => {
  const { groups: [host, guest], cids } = await network();
  const messageLabel = bytes("NullTrace v3 sender message key"), derivedMessages = [];
  const authenticate = sodium.crypto_auth;
  t.mock.method(sodium, "crypto_auth", (message, key) => {
    const result = authenticate(message, key);
    if (message.length === messageLabel.length && sodium.memcmp(message, messageLabel)) {
      derivedMessages.push(result);
    }
    return result;
  });
  const oldSend = host._sendChain, oldReceive = guest.recvChains.get(cids[0]).key;
  const packet = host.encrypt("consume exactly once");
  assert.ok(isZero(oldSend));
  assert.equal(guest.decrypt(packet), "consume exactly once");
  assert.ok(isZero(oldReceive));
  assert.equal(derivedMessages.length, 2);
  assert.ok(derivedMessages.every(isZero));
  assert.equal(guest.recvChains.get(cids[0]).skipped.size, 0);
  assert.equal(guest.decrypt(packet), null);
  for (const current of [host._sendChain, guest.recvChains.get(cids[0]).key]) {
    const nextMessageKey = hmac(current, "NullTrace v3 sender message key");
    try { assert.throws(() => openMessage(host, packet, nextMessageKey)); }
    finally { sodium.memzero(nextMessageKey); }
  }
});

test("skipped message keys are bounded at 64 and expiry wipes retained buffers", async t => {
  const { groups: [host, guest], cids } = await network();
  assert.equal(MAX_SKIPPED_MESSAGES, 64);
  assert.equal(MESSAGE_KEY_TTL_MS, 35000);
  const packets = Array.from({ length: 133 }, (_, i) => host.encrypt(`message ${i}`));
  assert.equal(guest.decrypt(packets[64]), "message 64");
  let chain = guest.recvChains.get(cids[0]);
  assert.equal(chain.skipped.size, 64);
  const beforeOverflow = snapshot(chain);
  assert.equal(guest.decrypt(packets[66]), null); // Existing 64 plus one new skipped key.
  assert.deepEqual(snapshot(chain), beforeOverflow);
  const consumedSkipped = chain.skipped.get(0).key;
  assert.equal(guest.decrypt(packets[0]), "message 0");
  assert.ok(isZero(consumedSkipped));
  assert.equal(guest.decrypt(packets[66]), "message 66");
  chain = guest.recvChains.get(cids[0]);
  assert.equal(chain.skipped.size, 64);
  assert.equal(guest.decrypt(packets[132]), null); // A 65-message forward gap.
  const retained = [...chain.skipped.values()].map(entry => entry.key);
  const afterExpiry = Date.now() + MESSAGE_KEY_TTL_MS + 1;
  t.mock.method(Date, "now", () => afterExpiry);
  guest._pruneSkipped();
  assert.equal(chain.skipped.size, 0);
  assert.ok(retained.every(isZero));
});

test("valid signatures on invalid message AEAD cannot advance or consume receive state", async () => {
  const { groups: [host, guest], keys, cids, room } = await network();
  const packets = [host.encrypt("cached"), host.encrypt("first arrival"), host.encrypt("next")];
  assert.equal(guest.decrypt(packets[1]), "first arrival");
  const chain = guest.recvChains.get(cids[0]), before = snapshot(chain);
  for (const original of [packets[2], packets[0]]) {
    const corrupt = signPacket({ ...original, c: flip(original.c) }, room, keys[0].idPriv);
    assert.equal(guest.decrypt(corrupt), null);
    assert.equal(guest.recvChains.get(cids[0]), chain);
    assert.deepEqual(snapshot(chain), before);
  }
  assert.equal(guest.decrypt(packets[2]), "next");
  assert.equal(guest.decrypt(packets[0]), "cached");
});

test("native ratcheted envelopes roll back bad AAD, signed metadata changes and ciphertext corruption", async () => {
  const { groups: [host, guest], keys, cids, room, take } = await network();
  host.rekey();
  const envelope = take("gk"), previousEpoch = guest.epoch;
  const ratchet = guest.peers.get(cids[0]);
  assert.equal(ratchet.decrypt(envelope.rk, bytes("wrong associated data")), null);
  for (const changed of [
    { ...envelope, e: envelope.e + 1 },
    { ...envelope, rh: flip(envelope.rh) },
    { ...envelope, rk: flip(envelope.rk) }
  ]) {
    assert.equal(guest.loadGK(signPacket(changed, room, keys[0].idPriv)), false);
    assert.equal(guest.epoch, previousEpoch);
  }
  assert.equal(guest.loadGK(envelope), true);
  assert.equal(guest.epoch, envelope.e);
  assert.equal(guest.loadGK(envelope), false);
});

test("a transport failure after a partial epoch send destroys the host group and its ratchets", async () => {
  const { groups: [host], wire } = await network(3);
  const previousEpoch = host.epoch;
  const oldKeys = [host._sendChain, ...[...host.recvChains.values()].map(chain => chain.key)];
  const ratchets = [...host.peers.values()];
  const install = host._installKey;
  let failedEpochKey;
  host._installKey = function(...args) {
    const result = install.apply(this, args);
    failedEpochKey = this._sendChain;
    return result;
  };
  let sends = 0;
  host.send = packet => {
    if (++sends === 2) return false;
    wire.push(packet);
    return true;
  };
  assert.throws(() => host.rekey(), /transport closed/);
  assert.equal(wire.length, 1);
  assert.equal(wire[0].e, previousEpoch + 1);
  assert.equal(host.destroyed, true);
  assert.equal(host.ready, false);
  assert.equal(host.peers.size, 0);
  assert.equal(host.recvChains.size, 0);
  assert.equal(host._latestEnvelopes.size, 0);
  assert.equal(host.encrypt("must not send"), null);
  assert.ok(oldKeys.every(isZero));
  assert.ok(failedEpochKey && isZero(failedEpochKey));
  for (const ratchet of ratchets) assert.throws(() => ratchet.encrypt(bytes("closed"), bytes("aad")), /destroyed/);
});

test("signed initial requests retransmit only ciphertext and ACK tampering or replay cannot rekey", async () => {
  const { groups: [host, guest], keys, room, wire, take } = await network(2, { deliver: false });
  const initialEnvelope = take("gk"), epoch = host.epoch, sendChain = host._sendChain;
  assert.equal(guest.ready, false);
  assert.equal(guest.requestKey(), true);
  const request = take("gk_req");
  assert.equal(request.e, 0);
  assert.equal(request.rh, "");
  assert.equal(request.rk, undefined);
  assert.equal(host.handleControl({ ...request, sig: "" }), false);
  assert.equal(host.handleControl(request), true);
  assert.equal(take("gk"), initialEnvelope, "Retry reuses the exact ciphertext packet");
  assert.equal(host.epoch, epoch);
  assert.equal(host._sendChain, sendChain);
  assert.equal(host.handleControl(request), false, "Initial retries are rate limited");
  assert.equal(guest.loadGK(initialEnvelope), true);
  const ack = take("gk_ack");
  assert.equal(typeof ack.rk, "string");
  for (const changed of [{ ...ack, rh: flip(ack.rh) }, { ...ack, rk: flip(ack.rk) }]) {
    assert.equal(host.handleControl(signPacket(changed, room, keys[1].idPriv)), false);
  }
  assert.equal(host.handleControl(ack), true);
  assert.equal(host.handleControl(ack), false);
  assert.equal(host.epoch, epoch);
  assert.equal(wire.length, 0, "ACKs do not emit another epoch");
});

test("repeated epochs tolerate lost ACKs, reject older envelopes and reorder messages for three members", async () => {
  const { groups, wire } = await network(3);
  let droppedAcks = 0;
  for (let cycle = 0; cycle < 20; cycle++) {
    for (const ack of wire.splice(0)) {
      assert.equal(ack.t, "gk_ack");
      if (cycle % 3 === 0) droppedAcks++;
      else assert.equal(groups[0].handleControl(ack), true);
    }
    groups[0].rekey();
    groups[0].rekey();
    const envelopes = wire.splice(0);
    assert.equal(envelopes.length, 4);
    for (const guest of groups.slice(1)) {
      const addressed = envelopes.filter(packet => packet.to === guest.cid);
      assert.equal(addressed.length, 2);
      assert.equal(guest.loadGK(addressed[1]), true);
      assert.equal(guest.loadGK(addressed[0]), false);
      assert.equal(guest.epoch, groups[0].epoch);
    }
    for (const sender of groups) {
      const first = sender.encrypt(`first ${cycle}`), second = sender.encrypt(`second ${cycle}`);
      for (const receiver of groups) {
        if (receiver === sender) continue;
        assert.equal(receiver.decrypt(second), `second ${cycle}`);
        assert.equal(receiver.decrypt(first), `first ${cycle}`);
        assert.equal(receiver.decrypt(second), null);
      }
    }
  }
  assert.ok(droppedAcks >= 10);
});
