import test from "node:test";
import assert from "node:assert/strict";
import sodium from "libsodium-wrappers";
import { createInitiator, createResponder } from "../frontend/static/js/modules/ratchet.js";

const b = value => new TextEncoder().encode(value);
const context = b("NullTrace v3|room|host cid|guest cid|pinned identities");
const aad = b("room|host|guest|group epoch 1");
function pair() {
  const secret = sodium.randombytes_buf(32);
  const alice = createInitiator(secret, context);
  const bob = createResponder(secret, context, alice.initialPublicKey);
  sodium.memzero(secret);
  return [alice, bob];
}

test("real WASM ratchet exchanges messages in both directions and rejects replay", () => {
  const [alice, bob] = pair();
  try {
    const packet = alice.encrypt(b("group seed"), aad);
    assert.deepEqual(bob.decrypt(packet, aad), b("group seed"));
    assert.equal(bob.decrypt(packet, aad), null);
    const reply = bob.encrypt(b("authenticated ack"), aad);
    assert.deepEqual(alice.decrypt(reply, aad), b("authenticated ack"));
    const rotated = alice.encrypt(b("fresh epoch seed"), aad);
    assert.deepEqual(bob.decrypt(rotated, aad), b("fresh epoch seed"));
  } finally { alice.destroy(); bob.destroy(); }
});

test("corruption and wrong associated data cannot consume ratchet state", () => {
  const [alice, bob] = pair();
  try {
    const packet = alice.encrypt(b("sensitive seed"), aad);
    const corrupt = sodium.from_base64(packet, sodium.base64_variants.ORIGINAL);
    corrupt[corrupt.length - 1] ^= 1;
    assert.equal(bob.decrypt(sodium.to_base64(corrupt, sodium.base64_variants.ORIGINAL), aad), null);
    assert.equal(bob.decrypt(packet, b("different group epoch")), null);
    assert.deepEqual(bob.decrypt(packet, aad), b("sensitive seed"));
    const reply = bob.encrypt(b("fresh DH"), aad);
    assert.equal(alice.decrypt(reply, b("wrong direction")), null);
    assert.deepEqual(alice.decrypt(reply, aad), b("fresh DH"));
  } finally { alice.destroy(); bob.destroy(); }
});

test("committing a newer control envelope deletes skipped envelope keys", () => {
  const [alice, bob] = pair();
  try {
    const old = alice.encrypt(b("old group seed"), aad);
    const current = alice.encrypt(b("current group seed"), aad);
    assert.deepEqual(bob.decrypt(current, aad), b("current group seed"));
    assert.equal(bob.decrypt(old, aad), null);
    const delayed = alice.encrypt(b("old receive chain"), aad);
    assert.deepEqual(alice.decrypt(bob.encrypt(b("ack"), aad), aad), b("ack"));
    assert.deepEqual(bob.decrypt(alice.encrypt(b("next DH chain"), aad), aad), b("next DH chain"));
    assert.equal(bob.decrypt(delayed, aad), null);
  } finally { alice.destroy(); bob.destroy(); }
});

test("bootstrap binds context and generates a dedicated fresh initial DH key", () => {
  const secret = sodium.randombytes_buf(32);
  const alice = createInitiator(secret, context);
  const another = createInitiator(secret, context);
  const wrong = createResponder(secret, b("different room or participants"), alice.initialPublicKey);
  try {
    assert.notDeepEqual(alice.initialPublicKey, another.initialPublicKey);
    const exposed = alice.initialPublicKey;
    exposed.fill(0);
    assert.notDeepEqual(alice.initialPublicKey, exposed);
    assert.equal(wrong.decrypt(alice.encrypt(b("bound seed"), aad), aad), null);
    assert.throws(() => createResponder(secret, context, new Uint8Array(32)));
    assert.throws(() => createInitiator(secret, new Uint8Array()));
    assert.throws(() => createInitiator(new Uint8Array(31), context));
  } finally { sodium.memzero(secret); alice.destroy(); another.destroy(); wrong.destroy(); }
});

test("strict bounds and destroyed sessions fail closed without leaking snapshots", () => {
  const [alice, bob] = pair();
  const packet = alice.encrypt(b("seed"), aad);
  assert.throws(() => alice.encrypt(new Uint8Array(8193), aad));
  assert.throws(() => alice.encrypt(b("seed"), new Uint8Array(2049)));
  assert.equal(bob.decrypt("A".repeat(16385), aad), null);
  assert.equal(bob.decrypt(packet + "\n", aad), null);
  assert.equal(bob.decrypt(packet, new Uint8Array(2049)), null);
  assert.deepEqual(bob.decrypt(packet, aad), b("seed"));
  assert.deepEqual(Object.keys(alice), []);
  assert.equal("pickle" in alice, false);
  alice.destroy(); alice.destroy(); bob.destroy();
  assert.throws(() => alice.encrypt(b("seed"), aad), /destroyed/);
  assert.equal(alice.decrypt(packet, aad), null);
});
