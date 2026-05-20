// node_modules/mlkem/esm/src/errors.js
var MlKemError = class extends Error {
  constructor(e) {
    let message;
    if (e instanceof Error) {
      message = e.message;
    } else if (typeof e === "string") {
      message = e;
    } else {
      message = "";
    }
    super(message);
    this.name = this.constructor.name;
  }
};

// node_modules/mlkem/esm/src/consts.js
var N = 256;
var Q = 3329;
var Q_INV = 62209;
var NTT_ZETAS = [
  2285,
  2571,
  2970,
  1812,
  1493,
  1422,
  287,
  202,
  3158,
  622,
  1577,
  182,
  962,
  2127,
  1855,
  1468,
  573,
  2004,
  264,
  383,
  2500,
  1458,
  1727,
  3199,
  2648,
  1017,
  732,
  608,
  1787,
  411,
  3124,
  1758,
  1223,
  652,
  2777,
  1015,
  2036,
  1491,
  3047,
  1785,
  516,
  3321,
  3009,
  2663,
  1711,
  2167,
  126,
  1469,
  2476,
  3239,
  3058,
  830,
  107,
  1908,
  3082,
  2378,
  2931,
  961,
  1821,
  2604,
  448,
  2264,
  677,
  2054,
  2226,
  430,
  555,
  843,
  2078,
  871,
  1550,
  105,
  422,
  587,
  177,
  3094,
  3038,
  2869,
  1574,
  1653,
  3083,
  778,
  1159,
  3182,
  2552,
  1483,
  2727,
  1119,
  1739,
  644,
  2457,
  349,
  418,
  329,
  3173,
  3254,
  817,
  1097,
  603,
  610,
  1322,
  2044,
  1864,
  384,
  2114,
  3193,
  1218,
  1994,
  2455,
  220,
  2142,
  1670,
  2144,
  1799,
  2051,
  794,
  1819,
  2475,
  2459,
  478,
  3221,
  3021,
  996,
  991,
  958,
  1869,
  1522,
  1628
];
var NTT_ZETAS_INV = [
  1701,
  1807,
  1460,
  2371,
  2338,
  2333,
  308,
  108,
  2851,
  870,
  854,
  1510,
  2535,
  1278,
  1530,
  1185,
  1659,
  1187,
  3109,
  874,
  1335,
  2111,
  136,
  1215,
  2945,
  1465,
  1285,
  2007,
  2719,
  2726,
  2232,
  2512,
  75,
  156,
  3e3,
  2911,
  2980,
  872,
  2685,
  1590,
  2210,
  602,
  1846,
  777,
  147,
  2170,
  2551,
  246,
  1676,
  1755,
  460,
  291,
  235,
  3152,
  2742,
  2907,
  3224,
  1779,
  2458,
  1251,
  2486,
  2774,
  2899,
  1103,
  1275,
  2652,
  1065,
  2881,
  725,
  1508,
  2368,
  398,
  951,
  247,
  1421,
  3222,
  2499,
  271,
  90,
  853,
  1860,
  3203,
  1162,
  1618,
  666,
  320,
  8,
  2813,
  1544,
  282,
  1838,
  1293,
  2314,
  552,
  2677,
  2106,
  1571,
  205,
  2918,
  1542,
  2721,
  2597,
  2312,
  681,
  130,
  1602,
  1871,
  829,
  2946,
  3065,
  1325,
  2756,
  1861,
  1474,
  1202,
  2367,
  3147,
  1752,
  2707,
  171,
  3127,
  3042,
  1907,
  1836,
  1517,
  359,
  758,
  1441
];

// node_modules/@noble/hashes/esm/_u64.js
var U32_MASK64 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
var _32n = /* @__PURE__ */ BigInt(32);
function fromBig(n, le = false) {
  if (le)
    return { h: Number(n & U32_MASK64), l: Number(n >> _32n & U32_MASK64) };
  return { h: Number(n >> _32n & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
}
function split(lst, le = false) {
  const len = lst.length;
  let Ah = new Uint32Array(len);
  let Al = new Uint32Array(len);
  for (let i = 0; i < len; i++) {
    const { h: h2, l } = fromBig(lst[i], le);
    [Ah[i], Al[i]] = [h2, l];
  }
  return [Ah, Al];
}
var rotlSH = (h2, l, s) => h2 << s | l >>> 32 - s;
var rotlSL = (h2, l, s) => l << s | h2 >>> 32 - s;
var rotlBH = (h2, l, s) => l << s - 32 | h2 >>> 64 - s;
var rotlBL = (h2, l, s) => h2 << s - 32 | l >>> 64 - s;

// node_modules/@noble/hashes/esm/utils.js
function isBytes(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
}
function anumber(n) {
  if (!Number.isSafeInteger(n) || n < 0)
    throw new Error("positive integer expected, got " + n);
}
function abytes(b, ...lengths) {
  if (!isBytes(b))
    throw new Error("Uint8Array expected");
  if (lengths.length > 0 && !lengths.includes(b.length))
    throw new Error("Uint8Array expected of length " + lengths + ", got length=" + b.length);
}
function aexists(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("Hash instance has been destroyed");
  if (checkFinished && instance.finished)
    throw new Error("Hash#digest() has already been called");
}
function aoutput(out, instance) {
  abytes(out);
  const min = instance.outputLen;
  if (out.length < min) {
    throw new Error("digestInto() expects output buffer of length at least " + min);
  }
}
function u32(arr) {
  return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}
function clean(...arrays) {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}
var isLE = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
function byteSwap(word) {
  return word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
}
function byteSwap32(arr) {
  for (let i = 0; i < arr.length; i++) {
    arr[i] = byteSwap(arr[i]);
  }
  return arr;
}
var swap32IfBE = isLE ? (u) => u : byteSwap32;
function utf8ToBytes(str) {
  if (typeof str !== "string")
    throw new Error("string expected");
  return new Uint8Array(new TextEncoder().encode(str));
}
function toBytes(data) {
  if (typeof data === "string")
    data = utf8ToBytes(data);
  abytes(data);
  return data;
}
var Hash = class {
};
function createHasher(hashCons) {
  const hashC = (msg) => hashCons().update(toBytes(msg)).digest();
  const tmp = hashCons();
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = () => hashCons();
  return hashC;
}
function createXOFer(hashCons) {
  const hashC = (msg, opts) => hashCons(opts).update(toBytes(msg)).digest();
  const tmp = hashCons({});
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = (opts) => hashCons(opts);
  return hashC;
}

// node_modules/@noble/hashes/esm/sha3.js
var _0n = BigInt(0);
var _1n = BigInt(1);
var _2n = BigInt(2);
var _7n = BigInt(7);
var _256n = BigInt(256);
var _0x71n = BigInt(113);
var SHA3_PI = [];
var SHA3_ROTL = [];
var _SHA3_IOTA = [];
for (let round = 0, R = _1n, x = 1, y = 0; round < 24; round++) {
  [x, y] = [y, (2 * x + 3 * y) % 5];
  SHA3_PI.push(2 * (5 * y + x));
  SHA3_ROTL.push((round + 1) * (round + 2) / 2 % 64);
  let t = _0n;
  for (let j = 0; j < 7; j++) {
    R = (R << _1n ^ (R >> _7n) * _0x71n) % _256n;
    if (R & _2n)
      t ^= _1n << (_1n << /* @__PURE__ */ BigInt(j)) - _1n;
  }
  _SHA3_IOTA.push(t);
}
var IOTAS = split(_SHA3_IOTA, true);
var SHA3_IOTA_H = IOTAS[0];
var SHA3_IOTA_L = IOTAS[1];
var rotlH = (h2, l, s) => s > 32 ? rotlBH(h2, l, s) : rotlSH(h2, l, s);
var rotlL = (h2, l, s) => s > 32 ? rotlBL(h2, l, s) : rotlSL(h2, l, s);
function keccakP(s, rounds = 24) {
  const B = new Uint32Array(5 * 2);
  for (let round = 24 - rounds; round < 24; round++) {
    for (let x = 0; x < 10; x++)
      B[x] = s[x] ^ s[x + 10] ^ s[x + 20] ^ s[x + 30] ^ s[x + 40];
    for (let x = 0; x < 10; x += 2) {
      const idx1 = (x + 8) % 10;
      const idx0 = (x + 2) % 10;
      const B0 = B[idx0];
      const B1 = B[idx0 + 1];
      const Th = rotlH(B0, B1, 1) ^ B[idx1];
      const Tl = rotlL(B0, B1, 1) ^ B[idx1 + 1];
      for (let y = 0; y < 50; y += 10) {
        s[x + y] ^= Th;
        s[x + y + 1] ^= Tl;
      }
    }
    let curH = s[2];
    let curL = s[3];
    for (let t = 0; t < 24; t++) {
      const shift = SHA3_ROTL[t];
      const Th = rotlH(curH, curL, shift);
      const Tl = rotlL(curH, curL, shift);
      const PI = SHA3_PI[t];
      curH = s[PI];
      curL = s[PI + 1];
      s[PI] = Th;
      s[PI + 1] = Tl;
    }
    for (let y = 0; y < 50; y += 10) {
      for (let x = 0; x < 10; x++)
        B[x] = s[y + x];
      for (let x = 0; x < 10; x++)
        s[y + x] ^= ~B[(x + 2) % 10] & B[(x + 4) % 10];
    }
    s[0] ^= SHA3_IOTA_H[round];
    s[1] ^= SHA3_IOTA_L[round];
  }
  clean(B);
}
var Keccak = class _Keccak extends Hash {
  // NOTE: we accept arguments in bytes instead of bits here.
  constructor(blockLen, suffix, outputLen, enableXOF = false, rounds = 24) {
    super();
    this.pos = 0;
    this.posOut = 0;
    this.finished = false;
    this.destroyed = false;
    this.enableXOF = false;
    this.blockLen = blockLen;
    this.suffix = suffix;
    this.outputLen = outputLen;
    this.enableXOF = enableXOF;
    this.rounds = rounds;
    anumber(outputLen);
    if (!(0 < blockLen && blockLen < 200))
      throw new Error("only keccak-f1600 function is supported");
    this.state = new Uint8Array(200);
    this.state32 = u32(this.state);
  }
  clone() {
    return this._cloneInto();
  }
  keccak() {
    swap32IfBE(this.state32);
    keccakP(this.state32, this.rounds);
    swap32IfBE(this.state32);
    this.posOut = 0;
    this.pos = 0;
  }
  update(data) {
    aexists(this);
    data = toBytes(data);
    abytes(data);
    const { blockLen, state } = this;
    const len = data.length;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      for (let i = 0; i < take; i++)
        state[this.pos++] ^= data[pos++];
      if (this.pos === blockLen)
        this.keccak();
    }
    return this;
  }
  finish() {
    if (this.finished)
      return;
    this.finished = true;
    const { state, suffix, pos, blockLen } = this;
    state[pos] ^= suffix;
    if ((suffix & 128) !== 0 && pos === blockLen - 1)
      this.keccak();
    state[blockLen - 1] ^= 128;
    this.keccak();
  }
  writeInto(out) {
    aexists(this, false);
    abytes(out);
    this.finish();
    const bufferOut = this.state;
    const { blockLen } = this;
    for (let pos = 0, len = out.length; pos < len; ) {
      if (this.posOut >= blockLen)
        this.keccak();
      const take = Math.min(blockLen - this.posOut, len - pos);
      out.set(bufferOut.subarray(this.posOut, this.posOut + take), pos);
      this.posOut += take;
      pos += take;
    }
    return out;
  }
  xofInto(out) {
    if (!this.enableXOF)
      throw new Error("XOF is not possible for this instance");
    return this.writeInto(out);
  }
  xof(bytes) {
    anumber(bytes);
    return this.xofInto(new Uint8Array(bytes));
  }
  digestInto(out) {
    aoutput(out, this);
    if (this.finished)
      throw new Error("digest() was already called");
    this.writeInto(out);
    this.destroy();
    return out;
  }
  digest() {
    return this.digestInto(new Uint8Array(this.outputLen));
  }
  destroy() {
    this.destroyed = true;
    clean(this.state);
  }
  _cloneInto(to) {
    const { blockLen, suffix, outputLen, rounds, enableXOF } = this;
    to || (to = new _Keccak(blockLen, suffix, outputLen, enableXOF, rounds));
    to.state32.set(this.state32);
    to.pos = this.pos;
    to.posOut = this.posOut;
    to.finished = this.finished;
    to.rounds = rounds;
    to.suffix = suffix;
    to.outputLen = outputLen;
    to.enableXOF = enableXOF;
    to.destroyed = this.destroyed;
    return to;
  }
};
var gen = (suffix, blockLen, outputLen) => createHasher(() => new Keccak(blockLen, suffix, outputLen));
var sha3_256 = /* @__PURE__ */ (() => gen(6, 136, 256 / 8))();
var sha3_512 = /* @__PURE__ */ (() => gen(6, 72, 512 / 8))();
var genShake = (suffix, blockLen, outputLen) => createXOFer((opts = {}) => new Keccak(blockLen, suffix, opts.dkLen === void 0 ? outputLen : opts.dkLen, true));
var shake128 = /* @__PURE__ */ (() => genShake(31, 168, 128 / 8))();
var shake256 = /* @__PURE__ */ (() => genShake(31, 136, 256 / 8))();

// node_modules/mlkem/esm/_dnt.shims.js
var dntGlobals = {};
var dntGlobalThis = createMergeProxy(globalThis, dntGlobals);
function createMergeProxy(baseObj, extObj) {
  return new Proxy(baseObj, {
    get(_target, prop, _receiver) {
      if (prop in extObj) {
        return extObj[prop];
      } else {
        return baseObj[prop];
      }
    },
    set(_target, prop, value) {
      if (prop in extObj) {
        delete extObj[prop];
      }
      baseObj[prop] = value;
      return true;
    },
    deleteProperty(_target, prop) {
      let success = false;
      if (prop in extObj) {
        delete extObj[prop];
        success = true;
      }
      if (prop in baseObj) {
        delete baseObj[prop];
        success = true;
      }
      return success;
    },
    ownKeys(_target) {
      const baseKeys = Reflect.ownKeys(baseObj);
      const extKeys = Reflect.ownKeys(extObj);
      const extKeysSet = new Set(extKeys);
      return [...baseKeys.filter((k) => !extKeysSet.has(k)), ...extKeys];
    },
    defineProperty(_target, prop, desc) {
      if (prop in extObj) {
        delete extObj[prop];
      }
      Reflect.defineProperty(baseObj, prop, desc);
      return true;
    },
    getOwnPropertyDescriptor(_target, prop) {
      if (prop in extObj) {
        return Reflect.getOwnPropertyDescriptor(extObj, prop);
      } else {
        return Reflect.getOwnPropertyDescriptor(baseObj, prop);
      }
    },
    has(_target, prop) {
      return prop in extObj || prop in baseObj;
    }
  });
}

// node_modules/mlkem/esm/src/utils.js
function byte(n) {
  return n % 256;
}
function int16(n) {
  const end = -32768;
  const start = 32767;
  if (n >= end && n <= start) {
    return n;
  }
  if (n < end) {
    n = n + 32769;
    n = n % 65536;
    return start + n;
  }
  n = n - 32768;
  n = n % 65536;
  return end + n;
}
function uint16(n) {
  return n % 65536;
}
function int32(n) {
  const end = -2147483648;
  const start = 2147483647;
  if (n >= end && n <= start) {
    return n;
  }
  if (n < end) {
    n = n + 2147483649;
    n = n % 4294967296;
    return start + n;
  }
  n = n - 2147483648;
  n = n % 4294967296;
  return end + n;
}
function uint32(n) {
  return n % 4294967296;
}
function constantTimeCompare(x, y) {
  if (x.length != y.length) {
    return 0;
  }
  const v = new Uint8Array([0]);
  for (let i = 0; i < x.length; i++) {
    v[0] |= x[i] ^ y[i];
  }
  const z = new Uint8Array([0]);
  z[0] = ~(v[0] ^ z[0]);
  z[0] &= z[0] >> 4;
  z[0] &= z[0] >> 2;
  z[0] &= z[0] >> 1;
  return z[0];
}
function equalUint8Array(x, y) {
  if (x.length != y.length) {
    return false;
  }
  for (let i = 0; i < x.length; i++) {
    if (x[i] !== y[i]) {
      return false;
    }
  }
  return true;
}
async function loadCrypto() {
  if (typeof dntGlobalThis !== "undefined" && globalThis.crypto !== void 0) {
    return globalThis.crypto;
  }
  try {
    const { webcrypto } = await import("crypto");
    return webcrypto;
  } catch (_e) {
    throw new Error("failed to load Crypto");
  }
}
function prf(len, seed, nonce) {
  return shake256.create({ dkLen: len }).update(seed).update(new Uint8Array([nonce])).digest();
}
function byteopsLoad24(x) {
  let r = uint32(x[0]);
  r |= uint32(x[1]) << 8;
  r |= uint32(x[2]) << 16;
  return r;
}
function byteopsLoad32(x) {
  let r = uint32(x[0]);
  r |= uint32(x[1]) << 8;
  r |= uint32(x[2]) << 16;
  r |= uint32(x[3]) << 24;
  return uint32(r);
}

// node_modules/mlkem/esm/src/mlKemBase.js
var MlKemBase = class {
  /**
   * Creates a new instance of the MlKemBase class.
   */
  constructor() {
    Object.defineProperty(this, "_api", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    Object.defineProperty(this, "_k", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 0
    });
    Object.defineProperty(this, "_du", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 0
    });
    Object.defineProperty(this, "_dv", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 0
    });
    Object.defineProperty(this, "_eta1", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 0
    });
    Object.defineProperty(this, "_eta2", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 0
    });
    Object.defineProperty(this, "_skSize", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 0
    });
    Object.defineProperty(this, "_pkSize", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 0
    });
    Object.defineProperty(this, "_compressedUSize", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 0
    });
    Object.defineProperty(this, "_compressedVSize", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 0
    });
  }
  /**
   * Generates a keypair [publicKey, privateKey].
   *
   * If an error occurred, throws {@link MlKemError}.
   *
   * @returns A kaypair [publicKey, privateKey].
   * @throws {@link MlKemError}
   *
   * @example Generates a {@link MlKem768} keypair.
   *
   * ```ts
   * // Using jsr:
   * import { MlKem768 } from "@dajiaji/mlkem";
   * // Using npm:
   * // import { MlKem768 } from "mlkem"; // or "crystals-kyber-js"
   *
   * const kyber = new MlKem768();
   * const [pk, sk] = await kyber.generateKeyPair();
   * ```
   */
  async generateKeyPair() {
    await this._setup();
    try {
      const rnd = new Uint8Array(64);
      this._api.getRandomValues(rnd);
      return this._deriveKeyPair(rnd);
    } catch (e) {
      throw new MlKemError(e);
    }
  }
  /**
   * Derives a keypair [publicKey, privateKey] deterministically from a 64-octet seed.
   *
   * If an error occurred, throws {@link MlKemError}.
   *
   * @param seed A 64-octet seed for the deterministic key generation.
   * @returns A kaypair [publicKey, privateKey].
   * @throws {@link MlKemError}
   *
   * @example Derives a {@link MlKem768} keypair deterministically.
   *
   * ```ts
   * // Using jsr:
   * import { MlKem768 } from "@dajiaji/mlkem";
   * // Using npm:
   * // import { MlKem768 } from "mlkem"; // or "crystals-kyber-js"
   *
   * const kyber = new MlKem768();
   * const seed = new Uint8Array(64);
   * globalThis.crypto.getRandomValues(seed);
   * const [pk, sk] = await kyber.deriveKeyPair(seed);
   * ```
   */
  async deriveKeyPair(seed) {
    await this._setup();
    try {
      if (seed.byteLength !== 64) {
        throw new Error("seed must be 64 bytes in length");
      }
      return this._deriveKeyPair(seed);
    } catch (e) {
      throw new MlKemError(e);
    }
  }
  /**
   * Generates a shared secret from the encapsulated ciphertext and the private key.
   *
   * If an error occurred, throws {@link MlKemError}.
   *
   * @param pk A public key.
   * @param seed An optional 32-octet seed for the deterministic shared secret generation.
   * @returns A ciphertext (encapsulated public key) and a shared secret.
   * @throws {@link MlKemError}
   *
   * @example The {@link MlKem768} encapsulation.
   *
   * ```ts
   * // Using jsr:
   * import { MlKem768 } from "@dajiaji/mlkem";
   * // Using npm:
   * // import { MlKem768 } from "mlkem"; // or "crystals-kyber-js"
   *
   * const kyber = new MlKem768();
   * const [pk, sk] = await kyber.generateKeyPair();
   * const [ct, ss] = await kyber.encap(pk);
   * ```
   */
  async encap(pk, seed) {
    await this._setup();
    try {
      if (pk.length !== 384 * this._k + 32) {
        throw new Error("invalid encapsulation key");
      }
      const m = this._getSeed(seed);
      const [k, r] = g(m, h(pk));
      const ct = this._encap(pk, m, r);
      return [ct, k];
    } catch (e) {
      throw new MlKemError(e);
    }
  }
  /**
   * Generates a ciphertext for the public key and a shared secret.
   *
   * If an error occurred, throws {@link MlKemError}.
   *
   * @param ct A ciphertext generated by {@link encap}.
   * @param sk A private key.
   * @returns A shared secret.
   * @throws {@link MlKemError}
   *
   * @example The {@link MlKem768} decapsulation.
   *
   * ```ts
   * // Using jsr:
   * import { MlKem768 } from "@dajiaji/mlkem";
   * // Using npm:
   * // import { MlKem768 } from "mlkem"; // or "crystals-kyber-js"
   *
   * const kyber = new MlKem768();
   * const [pk, sk] = await kyber.generateKeyPair();
   * const [ct, ssS] = await kyber.encap(pk);
   * const ssR = await kyber.decap(ct, sk);
   * // ssS === ssR
   * ```
   */
  async decap(ct, sk) {
    await this._setup();
    try {
      if (ct.byteLength !== this._compressedUSize + this._compressedVSize) {
        throw new Error("Invalid ct size");
      }
      if (sk.length !== 768 * this._k + 96) {
        throw new Error("Invalid decapsulation key");
      }
      const sk2 = sk.subarray(0, this._skSize);
      const pk = sk.subarray(this._skSize, this._skSize + this._pkSize);
      const hpk = sk.subarray(this._skSize + this._pkSize, this._skSize + this._pkSize + 32);
      const z = sk.subarray(this._skSize + this._pkSize + 32, this._skSize + this._pkSize + 64);
      const m2 = this._decap(ct, sk2);
      const [k2, r2] = g(m2, hpk);
      const kBar = kdf(z, ct);
      const ct2 = this._encap(pk, m2, r2);
      return constantTimeCompare(ct, ct2) === 1 ? k2 : kBar;
    } catch (e) {
      throw new MlKemError(e);
    }
  }
  /**
   * Sets up the MlKemBase instance by loading the necessary crypto library.
   * If the crypto library is already loaded, this method does nothing.
   * @returns {Promise<void>} A promise that resolves when the setup is complete.
   */
  async _setup() {
    if (this._api !== void 0) {
      return;
    }
    this._api = await loadCrypto();
  }
  /**
   * Returns a Uint8Array seed for cryptographic operations.
   * If no seed is provided, a random seed of length 32 bytes is generated.
   * If a seed is provided, it must be exactly 32 bytes in length.
   *
   * @param seed - Optional seed for cryptographic operations.
   * @returns A Uint8Array seed.
   * @throws Error if the provided seed is not 32 bytes in length.
   */
  _getSeed(seed) {
    if (seed == void 0) {
      const s = new Uint8Array(32);
      this._api.getRandomValues(s);
      return s;
    }
    if (seed.byteLength !== 32) {
      throw new Error("seed must be 32 bytes in length");
    }
    return seed;
  }
  /**
   * Derives a key pair from a given seed.
   *
   * @param seed - The seed used for key derivation.
   * @returns An array containing the public key and secret key.
   */
  _deriveKeyPair(seed) {
    const cpaSeed = seed.subarray(0, 32);
    const z = seed.subarray(32, 64);
    const [pk, skBody] = this._deriveCpaKeyPair(cpaSeed);
    const pkh = h(pk);
    const sk = new Uint8Array(this._skSize + this._pkSize + 64);
    sk.set(skBody, 0);
    sk.set(pk, this._skSize);
    sk.set(pkh, this._skSize + this._pkSize);
    sk.set(z, this._skSize + this._pkSize + 32);
    return [pk, sk];
  }
  // indcpaKeyGen generates public and private keys for the CPA-secure
  // public-key encryption scheme underlying ML-KEM.
  /**
   * Derives a CPA key pair using the provided CPA seed.
   *
   * @param cpaSeed - The CPA seed used for key derivation.
   * @returns An array containing the public key and private key.
   */
  _deriveCpaKeyPair(cpaSeed) {
    const [publicSeed, noiseSeed] = g(cpaSeed, new Uint8Array([this._k]));
    const a = this._sampleMatrix(publicSeed, false);
    const s = this._sampleNoise1(noiseSeed, 0, this._k);
    const e = this._sampleNoise1(noiseSeed, this._k, this._k);
    for (let i = 0; i < this._k; i++) {
      s[i] = ntt(s[i]);
      s[i] = reduce(s[i]);
      e[i] = ntt(e[i]);
    }
    const pk = new Array(this._k);
    for (let i = 0; i < this._k; i++) {
      pk[i] = polyToMont(multiply(a[i], s));
      pk[i] = add(pk[i], e[i]);
      pk[i] = reduce(pk[i]);
    }
    const pubKey = new Uint8Array(this._pkSize);
    for (let i = 0; i < this._k; i++) {
      pubKey.set(polyToBytes(pk[i]), i * 384);
    }
    pubKey.set(publicSeed, this._skSize);
    const privKey = new Uint8Array(this._skSize);
    for (let i = 0; i < this._k; i++) {
      privKey.set(polyToBytes(s[i]), i * 384);
    }
    return [pubKey, privKey];
  }
  // _encap is the encapsulation function of the CPA-secure
  // public-key encryption scheme underlying ML-KEM.
  /**
   * Encapsulates a message using the ML-KEM encryption scheme.
   *
   * @param pk - The public key.
   * @param msg - The message to be encapsulated.
   * @param seed - The seed used for generating random values.
   * @returns The encapsulated message as a Uint8Array.
   */
  _encap(pk, msg, seed) {
    const tHat = new Array(this._k);
    const pkCheck = new Uint8Array(384 * this._k);
    for (let i = 0; i < this._k; i++) {
      tHat[i] = polyFromBytes(pk.subarray(i * 384, (i + 1) * 384));
      pkCheck.set(polyToBytes(tHat[i]), i * 384);
    }
    if (!equalUint8Array(pk.subarray(0, pkCheck.length), pkCheck)) {
      throw new Error("invalid encapsulation key");
    }
    const rho = pk.subarray(this._skSize);
    const a = this._sampleMatrix(rho, true);
    const r = this._sampleNoise1(seed, 0, this._k);
    const e1 = this._sampleNoise2(seed, this._k, this._k);
    const e2 = this._sampleNoise2(seed, this._k * 2, 1)[0];
    for (let i = 0; i < this._k; i++) {
      r[i] = ntt(r[i]);
      r[i] = reduce(r[i]);
    }
    const u = new Array(this._k);
    for (let i = 0; i < this._k; i++) {
      u[i] = multiply(a[i], r);
      u[i] = nttInverse(u[i]);
      u[i] = add(u[i], e1[i]);
      u[i] = reduce(u[i]);
    }
    const m = polyFromMsg(msg);
    let v = multiply(tHat, r);
    v = nttInverse(v);
    v = add(v, e2);
    v = add(v, m);
    v = reduce(v);
    const ret = new Uint8Array(this._compressedUSize + this._compressedVSize);
    this._compressU(ret.subarray(0, this._compressedUSize), u);
    this._compressV(ret.subarray(this._compressedUSize), v);
    return ret;
  }
  // indcpaDecrypt is the decryption function of the CPA-secure
  // public-key encryption scheme underlying ML-KEM.
  /**
   * Decapsulates the ciphertext using the provided secret key.
   *
   * @param ct - The ciphertext to be decapsulated.
   * @param sk - The secret key used for decapsulation.
   * @returns The decapsulated message as a Uint8Array.
   */
  _decap(ct, sk) {
    const u = this._decompressU(ct.subarray(0, this._compressedUSize));
    const v = this._decompressV(ct.subarray(this._compressedUSize));
    const privateKeyPolyvec = this._polyvecFromBytes(sk);
    for (let i = 0; i < this._k; i++) {
      u[i] = ntt(u[i]);
    }
    let mp = multiply(privateKeyPolyvec, u);
    mp = nttInverse(mp);
    mp = subtract(v, mp);
    mp = reduce(mp);
    return polyToMsg(mp);
  }
  // generateMatrixA deterministically generates a matrix `A` (or the transpose of `A`)
  // from a seed. Entries of the matrix are polynomials that look uniformly random.
  // Performs rejection sampling on the output of an extendable-output function (XOF).
  /**
   * Generates a sample matrix based on the provided seed and transposition flag.
   *
   * @param seed - The seed used for generating the matrix.
   * @param transposed - A flag indicating whether the matrix should be transposed or not.
   * @returns The generated sample matrix.
   */
  _sampleMatrix(seed, transposed) {
    const a = new Array(this._k);
    const transpose = new Uint8Array(2);
    for (let ctr = 0, i = 0; i < this._k; i++) {
      a[i] = new Array(this._k);
      for (let j = 0; j < this._k; j++) {
        if (transposed) {
          transpose[0] = i;
          transpose[1] = j;
        } else {
          transpose[0] = j;
          transpose[1] = i;
        }
        const output = xof(seed, transpose);
        const result = indcpaRejUniform(output.subarray(0, 504), 504, N);
        a[i][j] = result[0];
        ctr = result[1];
        while (ctr < N) {
          const outputn = output.subarray(504, 672);
          const result1 = indcpaRejUniform(outputn, 168, N - ctr);
          const missing = result1[0];
          const ctrn = result1[1];
          for (let k = ctr; k < N; k++) {
            a[i][j][k] = missing[k - ctr];
          }
          ctr = ctr + ctrn;
        }
      }
    }
    return a;
  }
  /**
   * Generates a 2D array of noise samples.
   *
   * @param sigma - The noise parameter.
   * @param offset - The offset value.
   * @param size - The size of the array.
   * @returns The generated 2D array of noise samples.
   */
  _sampleNoise1(sigma, offset, size) {
    const r = new Array(size);
    for (let i = 0; i < size; i++) {
      r[i] = byteopsCbd(prf(this._eta1 * N / 4, sigma, offset), this._eta1);
      offset++;
    }
    return r;
  }
  /**
   * Generates a 2-dimensional array of noise samples.
   *
   * @param sigma - The noise parameter.
   * @param offset - The offset value.
   * @param size - The size of the array.
   * @returns The generated 2-dimensional array of noise samples.
   */
  _sampleNoise2(sigma, offset, size) {
    const r = new Array(size);
    for (let i = 0; i < size; i++) {
      r[i] = byteopsCbd(prf(this._eta2 * N / 4, sigma, offset), this._eta2);
      offset++;
    }
    return r;
  }
  // polyvecFromBytes deserializes a vector of polynomials.
  /**
   * Converts a Uint8Array to a 2D array of numbers representing a polynomial vector.
   * Each element in the resulting array represents a polynomial.
   * @param a The Uint8Array to convert.
   * @returns The 2D array of numbers representing the polynomial vector.
   */
  _polyvecFromBytes(a) {
    const r = new Array(this._k);
    for (let i = 0; i < this._k; i++) {
      r[i] = polyFromBytes(a.subarray(i * 384, (i + 1) * 384));
    }
    return r;
  }
  // compressU lossily compresses and serializes a vector of polynomials.
  /**
   * Compresses the given array of coefficients into a Uint8Array.
   *
   * @param r - The output Uint8Array.
   * @param u - The array of coefficients.
   * @returns The compressed Uint8Array.
   */
  _compressU(r, u) {
    const t = new Array(4);
    for (let rr = 0, i = 0; i < this._k; i++) {
      for (let j = 0; j < N / 4; j++) {
        for (let k = 0; k < 4; k++) {
          t[k] = ((u[i][4 * j + k] << 10) + Q / 2) / Q & 1023;
        }
        r[rr++] = byte(t[0] >> 0);
        r[rr++] = byte(t[0] >> 8 | t[1] << 2);
        r[rr++] = byte(t[1] >> 6 | t[2] << 4);
        r[rr++] = byte(t[2] >> 4 | t[3] << 6);
        r[rr++] = byte(t[3] >> 2);
      }
    }
    return r;
  }
  // compressV lossily compresses and subsequently serializes a polynomial.
  /**
   * Compresses the given array of numbers into a Uint8Array.
   *
   * @param r - The Uint8Array to store the compressed values.
   * @param v - The array of numbers to compress.
   * @returns The compressed Uint8Array.
   */
  _compressV(r, v) {
    const t = new Uint8Array(8);
    for (let rr = 0, i = 0; i < N / 8; i++) {
      for (let j = 0; j < 8; j++) {
        t[j] = byte(((v[8 * i + j] << 4) + Q / 2) / Q) & 15;
      }
      r[rr++] = t[0] | t[1] << 4;
      r[rr++] = t[2] | t[3] << 4;
      r[rr++] = t[4] | t[5] << 4;
      r[rr++] = t[6] | t[7] << 4;
    }
    return r;
  }
  // decompressU de-serializes and decompresses a vector of polynomials and
  // represents the approximate inverse of compress1. Since compression is lossy,
  // the results of decompression will may not match the original vector of polynomials.
  /**
   * Decompresses a Uint8Array into a two-dimensional array of numbers.
   *
   * @param a The Uint8Array to decompress.
   * @returns The decompressed two-dimensional array.
   */
  _decompressU(a) {
    const r = new Array(this._k);
    for (let i = 0; i < this._k; i++) {
      r[i] = new Array(384);
    }
    const t = new Array(4);
    for (let aa = 0, i = 0; i < this._k; i++) {
      for (let j = 0; j < N / 4; j++) {
        t[0] = uint16(a[aa + 0]) >> 0 | uint16(a[aa + 1]) << 8;
        t[1] = uint16(a[aa + 1]) >> 2 | uint16(a[aa + 2]) << 6;
        t[2] = uint16(a[aa + 2]) >> 4 | uint16(a[aa + 3]) << 4;
        t[3] = uint16(a[aa + 3]) >> 6 | uint16(a[aa + 4]) << 2;
        aa = aa + 5;
        for (let k = 0; k < 4; k++) {
          r[i][4 * j + k] = int16(uint32(t[k] & 1023) * uint32(Q) + 512 >> 10);
        }
      }
    }
    return r;
  }
  // decompressV de-serializes and subsequently decompresses a polynomial,
  // representing the approximate inverse of compress2.
  // Note that compression is lossy, and thus decompression will not match the
  // original input.
  /**
   * Decompresses a Uint8Array into an array of numbers.
   *
   * @param a - The Uint8Array to decompress.
   * @returns An array of numbers.
   */
  _decompressV(a) {
    const r = new Array(384);
    for (let aa = 0, i = 0; i < N / 2; i++, aa++) {
      r[2 * i + 0] = int16(uint16(a[aa] & 15) * uint16(Q) + 8 >> 4);
      r[2 * i + 1] = int16(uint16(a[aa] >> 4) * uint16(Q) + 8 >> 4);
    }
    return r;
  }
};
function g(a, b) {
  const hash = sha3_512.create().update(a);
  if (b !== void 0) {
    hash.update(b);
  }
  const res = hash.digest();
  return [res.subarray(0, 32), res.subarray(32, 64)];
}
function h(msg) {
  return sha3_256.create().update(msg).digest();
}
function kdf(a, b) {
  const hash = shake256.create({ dkLen: 32 }).update(a);
  if (b !== void 0) {
    hash.update(b);
  }
  return hash.digest();
}
function xof(seed, transpose) {
  return shake128.create({ dkLen: 672 }).update(seed).update(transpose).digest();
}
function polyToBytes(a) {
  let t0 = 0;
  let t1 = 0;
  const r = new Uint8Array(384);
  const a2 = subtractQ(a);
  for (let i = 0; i < N / 2; i++) {
    t0 = uint16(a2[2 * i]);
    t1 = uint16(a2[2 * i + 1]);
    r[3 * i + 0] = byte(t0 >> 0);
    r[3 * i + 1] = byte(t0 >> 8) | byte(t1 << 4);
    r[3 * i + 2] = byte(t1 >> 4);
  }
  return r;
}
function polyFromBytes(a) {
  const r = new Array(384).fill(0);
  for (let i = 0; i < N / 2; i++) {
    r[2 * i] = int16((uint16(a[3 * i + 0]) >> 0 | uint16(a[3 * i + 1]) << 8) & 4095);
    r[2 * i + 1] = int16((uint16(a[3 * i + 1]) >> 4 | uint16(a[3 * i + 2]) << 4) & 4095);
  }
  return r;
}
function polyToMsg(a) {
  const msg = new Uint8Array(32);
  let t;
  const a2 = subtractQ(a);
  for (let i = 0; i < N / 8; i++) {
    msg[i] = 0;
    for (let j = 0; j < 8; j++) {
      t = ((uint16(a2[8 * i + j]) << 1) + uint16(Q / 2)) / uint16(Q) & 1;
      msg[i] |= byte(t << j);
    }
  }
  return msg;
}
function polyFromMsg(msg) {
  const r = new Array(384).fill(0);
  let mask;
  for (let i = 0; i < N / 8; i++) {
    for (let j = 0; j < 8; j++) {
      mask = -1 * int16(msg[i] >> j & 1);
      r[8 * i + j] = mask & int16((Q + 1) / 2);
    }
  }
  return r;
}
function indcpaRejUniform(buf, bufl, len) {
  const r = new Array(384).fill(0);
  let ctr = 0;
  let val0, val1;
  for (let pos = 0; ctr < len && pos + 3 <= bufl; ) {
    val0 = (uint16(buf[pos] >> 0) | uint16(buf[pos + 1]) << 8) & 4095;
    val1 = (uint16(buf[pos + 1] >> 4) | uint16(buf[pos + 2]) << 4) & 4095;
    pos = pos + 3;
    if (val0 < Q) {
      r[ctr] = val0;
      ctr = ctr + 1;
    }
    if (ctr < len && val1 < Q) {
      r[ctr] = val1;
      ctr = ctr + 1;
    }
  }
  return [r, ctr];
}
function byteopsCbd(buf, eta) {
  let t, d;
  let a, b;
  const r = new Array(384).fill(0);
  for (let i = 0; i < N / 8; i++) {
    t = byteopsLoad32(buf.subarray(4 * i, buf.length));
    d = t & 1431655765;
    d = d + (t >> 1 & 1431655765);
    for (let j = 0; j < 8; j++) {
      a = int16(d >> 4 * j + 0 & 3);
      b = int16(d >> 4 * j + eta & 3);
      r[8 * i + j] = a - b;
    }
  }
  return r;
}
function ntt(r) {
  for (let j = 0, k = 1, l = 128; l >= 2; l >>= 1) {
    for (let start = 0; start < 256; start = j + l) {
      const zeta = NTT_ZETAS[k];
      k = k + 1;
      for (j = start; j < start + l; j++) {
        const t = nttFqMul(zeta, r[j + l]);
        r[j + l] = r[j] - t;
        r[j] = r[j] + t;
      }
    }
  }
  return r;
}
function nttFqMul(a, b) {
  return byteopsMontgomeryReduce(a * b);
}
function reduce(r) {
  for (let i = 0; i < N; i++) {
    r[i] = barrett(r[i]);
  }
  return r;
}
function barrett(a) {
  const v = ((1 << 24) + Q / 2) / Q;
  let t = v * a >> 24;
  t = t * Q;
  return a - t;
}
function byteopsMontgomeryReduce(a) {
  const u = int16(int32(a) * Q_INV);
  let t = u * Q;
  t = a - t;
  t >>= 16;
  return int16(t);
}
function polyToMont(r) {
  const f = 1353;
  for (let i = 0; i < N; i++) {
    r[i] = byteopsMontgomeryReduce(int32(r[i]) * int32(f));
  }
  return r;
}
function multiply(a, b) {
  let r = polyBaseMulMontgomery(a[0], b[0]);
  let t;
  for (let i = 1; i < a.length; i++) {
    t = polyBaseMulMontgomery(a[i], b[i]);
    r = add(r, t);
  }
  return reduce(r);
}
function polyBaseMulMontgomery(a, b) {
  let rx, ry;
  for (let i = 0; i < N / 4; i++) {
    rx = nttBaseMul(a[4 * i + 0], a[4 * i + 1], b[4 * i + 0], b[4 * i + 1], NTT_ZETAS[64 + i]);
    ry = nttBaseMul(a[4 * i + 2], a[4 * i + 3], b[4 * i + 2], b[4 * i + 3], -NTT_ZETAS[64 + i]);
    a[4 * i + 0] = rx[0];
    a[4 * i + 1] = rx[1];
    a[4 * i + 2] = ry[0];
    a[4 * i + 3] = ry[1];
  }
  return a;
}
function nttBaseMul(a0, a1, b0, b1, zeta) {
  const r = new Array(2);
  r[0] = nttFqMul(a1, b1);
  r[0] = nttFqMul(r[0], zeta);
  r[0] += nttFqMul(a0, b0);
  r[1] = nttFqMul(a0, b1);
  r[1] += nttFqMul(a1, b0);
  return r;
}
function add(a, b) {
  const c = new Array(384);
  for (let i = 0; i < N; i++) {
    c[i] = a[i] + b[i];
  }
  return c;
}
function subtract(a, b) {
  for (let i = 0; i < N; i++) {
    a[i] -= b[i];
  }
  return a;
}
function nttInverse(r) {
  let j = 0;
  for (let k = 0, l = 2; l <= 128; l <<= 1) {
    for (let start = 0; start < 256; start = j + l) {
      const zeta = NTT_ZETAS_INV[k];
      k = k + 1;
      for (j = start; j < start + l; j++) {
        const t = r[j];
        r[j] = barrett(t + r[j + l]);
        r[j + l] = t - r[j + l];
        r[j + l] = nttFqMul(zeta, r[j + l]);
      }
    }
  }
  for (j = 0; j < 256; j++) {
    r[j] = nttFqMul(r[j], NTT_ZETAS_INV[127]);
  }
  return r;
}
function subtractQ(r) {
  for (let i = 0; i < N; i++) {
    r[i] -= Q;
    r[i] += r[i] >> 31 & Q;
  }
  return r;
}

// node_modules/mlkem/esm/src/mlKem512.js
var MlKem512 = class extends MlKemBase {
  /**
   * Constructs a new instance of the MlKem512 class.
   */
  constructor() {
    super();
    Object.defineProperty(this, "_k", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 2
    });
    Object.defineProperty(this, "_du", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 10
    });
    Object.defineProperty(this, "_dv", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 4
    });
    Object.defineProperty(this, "_eta1", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 3
    });
    Object.defineProperty(this, "_eta2", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 2
    });
    this._skSize = 12 * this._k * N / 8;
    this._pkSize = this._skSize + 32;
    this._compressedUSize = this._k * this._du * N / 8;
    this._compressedVSize = this._dv * N / 8;
  }
  /**
   * Samples a vector of polynomials from a seed.
   * @internal
   * @param sigma - The seed.
   * @param offset - The offset.
   * @param size - The size.
   * @returns The sampled vector of polynomials.
   */
  _sampleNoise1(sigma, offset, size) {
    const r = new Array(size);
    for (let i = 0; i < size; i++) {
      r[i] = byteopsCbd2(prf(this._eta1 * N / 4, sigma, offset), this._eta1);
      offset++;
    }
    return r;
  }
};
function byteopsCbd2(buf, eta) {
  let t, d;
  let a, b;
  const r = new Array(384).fill(0);
  for (let i = 0; i < N / 4; i++) {
    t = byteopsLoad24(buf.subarray(3 * i, buf.length));
    d = t & 2396745;
    d = d + (t >> 1 & 2396745);
    d = d + (t >> 2 & 2396745);
    for (let j = 0; j < 4; j++) {
      a = int16(d >> 6 * j + 0 & 7);
      b = int16(d >> 6 * j + eta & 7);
      r[4 * i + j] = a - b;
    }
  }
  return r;
}

// node_modules/mlkem/esm/src/mlKem768.js
var MlKem768 = class extends MlKemBase {
  constructor() {
    super();
    Object.defineProperty(this, "_k", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 3
    });
    Object.defineProperty(this, "_du", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 10
    });
    Object.defineProperty(this, "_dv", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 4
    });
    Object.defineProperty(this, "_eta1", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 2
    });
    Object.defineProperty(this, "_eta2", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 2
    });
    this._skSize = 12 * this._k * N / 8;
    this._pkSize = this._skSize + 32;
    this._compressedUSize = this._k * this._du * N / 8;
    this._compressedVSize = this._dv * N / 8;
  }
};

// node_modules/mlkem/esm/src/mlKem1024.js
var MlKem1024 = class extends MlKemBase {
  /**
   * Constructs a new instance of the MlKem1024 class.
   */
  constructor() {
    super();
    Object.defineProperty(this, "_k", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 4
    });
    Object.defineProperty(this, "_du", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 11
    });
    Object.defineProperty(this, "_dv", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 5
    });
    Object.defineProperty(this, "_eta1", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 2
    });
    Object.defineProperty(this, "_eta2", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 2
    });
    this._skSize = 12 * this._k * N / 8;
    this._pkSize = this._skSize + 32;
    this._compressedUSize = this._k * this._du * N / 8;
    this._compressedVSize = this._dv * N / 8;
  }
  // compressU lossily compresses and serializes a vector of polynomials.
  /**
   * Lossily compresses and serializes a vector of polynomials.
   *
   * @param u - The vector of polynomials to compress.
   * @returns The compressed and serialized data as a Uint8Array.
   */
  _compressU(r, u) {
    const t = new Array(8);
    for (let rr = 0, i = 0; i < this._k; i++) {
      for (let j = 0; j < N / 8; j++) {
        for (let k = 0; k < 8; k++) {
          t[k] = uint16(((uint32(u[i][8 * j + k]) << 11) + uint32(Q / 2)) / uint32(Q) & 2047);
        }
        r[rr++] = byte(t[0] >> 0);
        r[rr++] = byte(t[0] >> 8 | t[1] << 3);
        r[rr++] = byte(t[1] >> 5 | t[2] << 6);
        r[rr++] = byte(t[2] >> 2);
        r[rr++] = byte(t[2] >> 10 | t[3] << 1);
        r[rr++] = byte(t[3] >> 7 | t[4] << 4);
        r[rr++] = byte(t[4] >> 4 | t[5] << 7);
        r[rr++] = byte(t[5] >> 1);
        r[rr++] = byte(t[5] >> 9 | t[6] << 2);
        r[rr++] = byte(t[6] >> 6 | t[7] << 5);
        r[rr++] = byte(t[7] >> 3);
      }
    }
    return r;
  }
  // compressV lossily compresses and subsequently serializes a polynomial.
  /**
   * Lossily compresses and serializes a polynomial.
   *
   * @param r - The output buffer to store the compressed data.
   * @param v - The polynomial to compress.
   * @returns The compressed and serialized data as a Uint8Array.
   */
  _compressV(r, v) {
    const t = new Uint8Array(8);
    for (let rr = 0, i = 0; i < N / 8; i++) {
      for (let j = 0; j < 8; j++) {
        t[j] = byte(((uint32(v[8 * i + j]) << 5) + uint32(Q / 2)) / uint32(Q)) & 31;
      }
      r[rr++] = byte(t[0] >> 0 | t[1] << 5);
      r[rr++] = byte(t[1] >> 3 | t[2] << 2 | t[3] << 7);
      r[rr++] = byte(t[3] >> 1 | t[4] << 4);
      r[rr++] = byte(t[4] >> 4 | t[5] << 1 | t[6] << 6);
      r[rr++] = byte(t[6] >> 2 | t[7] << 3);
    }
    return r;
  }
  // decompressU de-serializes and decompresses a vector of polynomials and
  // represents the approximate inverse of compress1. Since compression is lossy,
  // the results of decompression will may not match the original vector of polynomials.
  /**
   * Deserializes and decompresses a vector of polynomials.
   * This is the approximate inverse of the `_compressU` method.
   * Since compression is lossy, the decompressed data may not match the original vector of polynomials.
   *
   * @param a - The compressed and serialized data as a Uint8Array.
   * @returns The decompressed vector of polynomials.
   */
  _decompressU(a) {
    const r = new Array(this._k);
    for (let i = 0; i < this._k; i++) {
      r[i] = new Array(384);
    }
    const t = new Array(8);
    for (let aa = 0, i = 0; i < this._k; i++) {
      for (let j = 0; j < N / 8; j++) {
        t[0] = uint16(a[aa + 0]) >> 0 | uint16(a[aa + 1]) << 8;
        t[1] = uint16(a[aa + 1]) >> 3 | uint16(a[aa + 2]) << 5;
        t[2] = uint16(a[aa + 2]) >> 6 | uint16(a[aa + 3]) << 2 | uint16(a[aa + 4]) << 10;
        t[3] = uint16(a[aa + 4]) >> 1 | uint16(a[aa + 5]) << 7;
        t[4] = uint16(a[aa + 5]) >> 4 | uint16(a[aa + 6]) << 4;
        t[5] = uint16(a[aa + 6]) >> 7 | uint16(a[aa + 7]) << 1 | uint16(a[aa + 8]) << 9;
        t[6] = uint16(a[aa + 8]) >> 2 | uint16(a[aa + 9]) << 6;
        t[7] = uint16(a[aa + 9]) >> 5 | uint16(a[aa + 10]) << 3;
        aa = aa + 11;
        for (let k = 0; k < 8; k++) {
          r[i][8 * j + k] = uint32(t[k] & 2047) * Q + 1024 >> 11;
        }
      }
    }
    return r;
  }
  // decompressV de-serializes and subsequently decompresses a polynomial,
  // representing the approximate inverse of compress2.
  // Note that compression is lossy, and thus decompression will not match the
  // original input.
  /**
   * Decompresses a given polynomial, representing the approximate inverse of
   * compress2, in Uint8Array into an array of numbers.
   *
   * Note that compression is lossy, and thus decompression will not match the
   * original input.
   *
   * @param a - The Uint8Array to decompress.
   * @returns An array of numbers obtained from the decompression process.
   */
  _decompressV(a) {
    const r = new Array(384);
    const t = new Array(8);
    for (let aa = 0, i = 0; i < N / 8; i++) {
      t[0] = a[aa + 0] >> 0;
      t[1] = a[aa + 0] >> 5 | a[aa + 1] << 3;
      t[2] = a[aa + 1] >> 2;
      t[3] = a[aa + 1] >> 7 | a[aa + 2] << 1;
      t[4] = a[aa + 2] >> 4 | a[aa + 3] << 4;
      t[5] = a[aa + 3] >> 1;
      t[6] = a[aa + 3] >> 6 | a[aa + 4] << 2;
      t[7] = a[aa + 4] >> 3;
      aa = aa + 5;
      for (let j = 0; j < 8; j++) {
        r[8 * i + j] = int16(uint32(t[j] & 31) * uint32(Q) + 16 >> 5);
      }
    }
    return r;
  }
};
export {
  MlKem1024,
  MlKem512,
  MlKem768,
  MlKemError
};
/*! Bundled license information:

@noble/hashes/esm/utils.js:
  (*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) *)
*/
