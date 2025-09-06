(function (factory) {
    if (typeof module === "object" && typeof module.exports === "object") {
        var v = factory(require, exports);
        if (v !== undefined) module.exports = v;
    }
    else if (typeof define === "function" && define.amd) {
        define(["require", "exports", "./consts.js", "./mlKemBase.js"], factory);
    }
})(function (require, exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.MlKem768 = void 0;
    /**
     * This implementation is based on https://github.com/antontutoveanu/crystals-kyber-javascript,
     * which was deveploped under the MIT licence below:
     * https://github.com/antontutoveanu/crystals-kyber-javascript/blob/main/LICENSE
     */
    const consts_js_1 = require("./consts.js");
    const mlKemBase_js_1 = require("./mlKemBase.js");
    /**
     * Represents the MlKem768 class, which extends the MlKemBase class.
     *
     * This class extends the MlKemBase class and provides specific implementation for MlKem768.
     *
     * @remarks
     *
     * MlKem768 is a specific implementation of the ML-KEM key encapsulation mechanism.
     *
     * @example
     *
     * ```ts
     * // Using jsr:
     * import { MlKem768 } from "@dajiaji/mlkem";
     * // Using npm:
     * // import { MlKem768 } from "mlkem"; // or "crystals-kyber-js"
     *
     * const recipient = new MlKem768();
     * const [pkR, skR] = await recipient.generateKeyPair();
     *
     * const sender = new MlKem768();
     * const [ct, ssS] = await sender.encap(pkR);
     *
     * const ssR = await recipient.decap(ct, skR);
     * // ssS === ssR
     * ```
     */
    class MlKem768 extends mlKemBase_js_1.MlKemBase {
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
            this._skSize = 12 * this._k * consts_js_1.N / 8;
            this._pkSize = this._skSize + 32;
            this._compressedUSize = this._k * this._du * consts_js_1.N / 8;
            this._compressedVSize = this._dv * consts_js_1.N / 8;
        }
    }
    exports.MlKem768 = MlKem768;
});
