(function (factory) {
    if (typeof module === "object" && typeof module.exports === "object") {
        var v = factory(require, exports);
        if (v !== undefined) module.exports = v;
    }
    else if (typeof define === "function" && define.amd) {
        define(["require", "exports", "./consts.js", "./mlKemBase.js", "./utils.js"], factory);
    }
})(function (require, exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.MlKem512 = void 0;
    /**
     * This implementation is based on https://github.com/antontutoveanu/crystals-kyber-javascript,
     * which was deveploped under the MIT licence below:
     * https://github.com/antontutoveanu/crystals-kyber-javascript/blob/main/LICENSE
     */
    const consts_js_1 = require("./consts.js");
    const mlKemBase_js_1 = require("./mlKemBase.js");
    const utils_js_1 = require("./utils.js");
    /**
     * Represents the MlKem512 class.
     *
     * This class extends the MlKemBase class and provides specific implementation for MlKem512.
     *
     * @remarks
     *
     * MlKem512 is a specific implementation of the ML-KEM key encapsulation mechanism.
     *
     * @example
     *
     * ```ts
     * // Using jsr:
     * import { MlKem512 } from "@dajiaji/mlkem";
     * // Using npm:
     * // import { MlKem512 } from "mlkem"; // or "crystals-kyber-js"
     *
     * const recipient = new MlKem512();
     * const [pkR, skR] = await recipient.generateKeyPair();
     *
     * const sender = new MlKem512();
     * const [ct, ssS] = await sender.encap(pkR);
     *
     * const ssR = await recipient.decap(ct, skR);
     * // ssS === ssR
     * ```
     */
    class MlKem512 extends mlKemBase_js_1.MlKemBase {
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
            this._skSize = 12 * this._k * consts_js_1.N / 8;
            this._pkSize = this._skSize + 32;
            this._compressedUSize = this._k * this._du * consts_js_1.N / 8;
            this._compressedVSize = this._dv * consts_js_1.N / 8;
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
                r[i] = byteopsCbd((0, utils_js_1.prf)(this._eta1 * consts_js_1.N / 4, sigma, offset), this._eta1);
                offset++;
            }
            return r;
        }
    }
    exports.MlKem512 = MlKem512;
    /**
     * Performs the byte operations for the Cbd function.
     *
     * @param buf - The input buffer.
     * @param eta - The value of eta.
     * @returns An array of numbers representing the result of the byte operations.
     */
    function byteopsCbd(buf, eta) {
        let t, d;
        let a, b;
        const r = new Array(384).fill(0);
        for (let i = 0; i < consts_js_1.N / 4; i++) {
            t = (0, utils_js_1.byteopsLoad24)(buf.subarray(3 * i, buf.length));
            d = t & 0x00249249;
            d = d + ((t >> 1) & 0x00249249);
            d = d + ((t >> 2) & 0x00249249);
            for (let j = 0; j < 4; j++) {
                a = (0, utils_js_1.int16)((d >> (6 * j + 0)) & 0x7);
                b = (0, utils_js_1.int16)((d >> (6 * j + eta)) & 0x7);
                r[4 * i + j] = a - b;
            }
        }
        return r;
    }
});
