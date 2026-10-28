// Synchronous, in-memory Double Ratchet control envelopes after WASM startup.
// The caller authenticates the bootstrap context and initialPublicKey, and
// wipes its bootstrap secret after construction. No session export is exposed.
import sodium from "libsodium-wrappers";
import initWasm, { NativeRatchet } from "../../libs/ratchet-wasm/nulltrace_ratchet.js";

const wasmUrl = new URL("../../libs/ratchet-wasm/nulltrace_ratchet_bg.wasm", import.meta.url);
// Node loads the exact same committed WASM in the protocol tests. Browsers
// fetch this same-origin static asset without a worker or a Rust backend.
if (typeof process !== "undefined" && process.versions?.node) {
  const { readFile } = await import("node:fs/promises");
  await initWasm({ module_or_path: await readFile(wasmUrl) });
} else {
  const response = await fetch(wasmUrl, { cache: "no-store", credentials: "same-origin" });
  if (!response.ok) throw new Error("Ratchet engine could not be loaded");
  await initWasm({ module_or_path: response });
}
await sodium.ready;

const MAX_PLAIN = 8192;
const MAX_CONTEXT = 2048;
const MAX_WIRE = 12288;
const MAX_WIRE_BASE64 = 16384;
const B64 = sodium.base64_variants.ORIGINAL;

function bytes(value, limit, name, exact = null) {
  if (!(value instanceof Uint8Array) || value.length > limit ||
      (exact !== null && value.length !== exact)) {
    throw new TypeError(`Invalid ratchet ${name}`);
  }
  return value;
}

function bootstrap(secret, context) {
  bytes(secret, 32, "secret", 32);
  bytes(context, MAX_CONTEXT, "context");
  if (!context.length) throw new TypeError("Invalid ratchet context");
}

class Ratchet {
  #native;
  #publicKey;

  constructor(native) {
    this.#native = native;
    this.#publicKey = native.initialPublicKey;
  }

  get initialPublicKey() { return this.#publicKey.slice(); }

  encrypt(plaintext, aad) {
    if (!this.#native) throw new Error("Ratchet destroyed");
    bytes(plaintext, MAX_PLAIN, "plaintext");
    bytes(aad, MAX_CONTEXT, "associated data");
    return sodium.to_base64(this.#native.encrypt(plaintext, aad), B64);
  }

  // Invalid MAC/AAD/wire/replay leaves all state unchanged. Once a newer
  // control envelope commits, older skipped envelopes are deliberately lost.
  decrypt(wire, aad) {
    if (!this.#native || typeof wire !== "string" || !wire.length ||
        wire.length > MAX_WIRE_BASE64) return null;
    try {
      bytes(aad, MAX_CONTEXT, "associated data");
      const decoded = sodium.from_base64(wire, B64);
      if (decoded.length > MAX_WIRE || sodium.to_base64(decoded, B64) !== wire) return null;
      return this.#native.decrypt(decoded, aad) ?? null;
    } catch {
      return null;
    }
  }

  destroy() {
    if (!this.#native) return;
    this.#native.destroy();
    this.#native.free();
    this.#native = null;
  }
}

export function createInitiator(secret, context) {
  bootstrap(secret, context);
  return new Ratchet(NativeRatchet.initiator(secret, context));
}

export function createResponder(secret, context, initialPublicKey) {
  bootstrap(secret, context);
  bytes(initialPublicKey, 32, "initial public key", 32);
  return new Ratchet(NativeRatchet.responder(secret, context, initialPublicKey));
}
